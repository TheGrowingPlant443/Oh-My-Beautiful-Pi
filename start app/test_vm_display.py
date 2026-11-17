"""Guest display helper: supervision against a scripted compositor (any Linux) and real Sway + wayvnc (VM guest)."""
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
import unittest

from runtime import OwnedChildren
import vm_display
from vm_display import HeadlessDisplays, count_views

LINUX = sys.platform.startswith("linux")

# Speaks just enough Sway IPC (subscribe, get_tree, window/shutdown events) for the supervisor; the test drives its
# view count through a private control socket.
FAKE_SWAY = r'''
import json, os, socket, struct, sys, threading
runtime = os.environ["XDG_RUNTIME_DIR"]
wayland = socket.socket(socket.AF_UNIX); wayland.bind(os.path.join(runtime, "wayland-1")); wayland.listen()
ipc = socket.socket(socket.AF_UNIX); ipc.bind(os.environ["SWAYSOCK"]); ipc.listen()
control = socket.socket(socket.AF_UNIX); control.bind(os.environ["FAKE_SWAY_CONTROL"]); control.listen()
views, subscribers, lock = 0, [], threading.Lock()
def send(connection, kind, value):
    data = json.dumps(value).encode()
    connection.sendall(b"i3-ipc" + struct.pack("=II", len(data), kind) + data)
def tree():
    return {"type": "root", "nodes": [{"type": "workspace", "nodes": [{"type": "con", "shell": "xdg_shell"}] * views}]}
def serve(connection):
    try:
        while header := connection.recv(14, socket.MSG_WAITALL):
            size, kind = struct.unpack("=II", header[6:])
            connection.recv(size, socket.MSG_WAITALL) if size else b""
            if kind == 2:
                send(connection, 2, {"success": True})
                with lock: subscribers.append(connection)
            elif kind == 4:
                send(connection, 4, tree())
    except OSError:
        pass
def accept():
    while True:
        connection, _ = ipc.accept()
        threading.Thread(target=serve, args=(connection,), daemon=True).start()
threading.Thread(target=accept, daemon=True).start()
while True:
    connection, _ = control.accept()
    command = connection.recv(64).decode().split()
    connection.close()
    if command[0] == "exit":
        os._exit(int(command[1]))
    views = int(command[1])
    with lock:
        for subscriber in subscribers:
            send(subscriber, 0x80000003, {"change": "new" if views else "close"})
'''


class TreeTests(unittest.TestCase):
    def test_counts_tiled_and_floating_views_only(self):
        tree = {"type": "root", "nodes": [
            {"type": "output", "nodes": [{"type": "workspace", "nodes": [
                {"type": "con", "shell": "xdg_shell", "nodes": []},
                {"type": "con", "nodes": [{"type": "con", "shell": "xdg_shell"}]}],
                "floating_nodes": [{"type": "floating_con", "shell": "xdg_shell"}]}]}]}
        self.assertEqual(count_views(tree), 3)
        self.assertEqual(count_views({"type": "root", "nodes": [{"type": "workspace", "nodes": []}]}), 0)

    def test_refuses_unknown_display_kind(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                HeadlessDisplays(Path(root) / "display", print).start("host", Path(root) / "p", "w", False,
                                                                       OwnedChildren(), None)


class _DisplayCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="vd-", dir="/tmp" if LINUX else None)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.events = []
        self.ended = []
        self.children = OwnedChildren()
        self.addCleanup(self.children.retire)
        self.log = open(self.root / "display.log", "ab")
        self.addCleanup(self.log.close)
        self.displays = HeadlessDisplays(self.root / "private", self.events.append)

    def start(self, kind="ombp", show=True):
        display = self.displays.start(kind, self.root / f"public-{kind}", f"wayland-{kind}", show, self.children,
                                      self.log, self.ended.append)
        self.addCleanup(display.terminate)
        return display

    def sleeper(self):
        """A stand-in application process that the test retires (kill and reap) afterwards."""
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(process.wait)
        self.addCleanup(process.kill)
        return process

    def until(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail("condition not reached; log:\n" + (self.root / "display.log").read_text(errors="replace"))
            time.sleep(0.05)


class _ScriptedCase(_DisplayCase):
    """Runs the supervisor against FAKE_SWAY instead of the real compositor."""

    def setUp(self):
        super().setUp()
        script = self.root / "fake-sway.py"
        script.write_text(FAKE_SWAY)
        self.control = self.root / "control.sock"
        wrapper = self.root / "sway"
        # The supervisor gives the compositor a minimal environment, so the fake's control path is baked in here.
        wrapper.write_text(f"#!/bin/sh\nFAKE_SWAY_CONTROL='{self.control}' exec {sys.executable} {script}\n")
        wrapper.chmod(0o700)
        previous = {key: os.environ.get(key) for key in ("START_APP_SWAY", "START_APP_WAYVNC")}
        os.environ["START_APP_SWAY"] = str(wrapper)
        os.environ.pop("START_APP_WAYVNC", None)
        self.addCleanup(self._restore, previous)

    @staticmethod
    def _restore(previous):
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def command(self, text):
        self.until(self.control.is_socket)
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(str(self.control))
            connection.sendall(text.encode())


@unittest.skipUnless(LINUX, "the display helper runs inside the Linux VM guest")
class ScriptedCompositorTests(_ScriptedCase):
    def test_public_directory_holds_only_the_wayland_socket(self):
        display = self.start(show=False)
        self.assertEqual([path.name for path in display.public.iterdir()], ["wayland-ombp"])
        self.assertEqual(os.stat(display.socket).st_ino, os.stat(display.wayland).st_ino)
        self.assertTrue((display.private / "sway-ipc.sock").is_socket())
        self.assertEqual(os.stat(display.private).st_mode & 0o777, 0o700)
        # Hidden desktop: no VNC listener, no display events.
        self.assertIsNone(display.wayvnc)
        self.assertIsNone(display.vnc_port)
        display.terminate()
        self.assertFalse(display.socket.exists())
        self.assertFalse(display.private.exists())
        self.assertEqual(self.events, [])

    def test_first_surface_then_closing_the_last_is_an_owned_stop(self):
        display = self.start(show=False)
        app = self.sleeper()
        self.command("views 1")
        display.wait_mapped(app, 10)
        self.assertIsNone(display.poll())
        self.command("views 0")
        self.until(lambda: display.poll() is not None)
        self.assertEqual(display.wait(timeout=1), 0)
        self.assertEqual(display.failure, "")
        self.assertEqual(self.ended, [display])
        self.assertIsNotNone(display.sway.poll())

    def test_browser_display_keeps_running_without_windows(self):
        display = self.start("browser", show=False)
        self.command("views 1")
        self.until(display._mapped.is_set)
        self.command("views 0")
        time.sleep(0.5)
        self.assertIsNone(display.poll())
        self.assertEqual(self.ended, [])

    def test_app_exit_or_no_surface_is_a_startup_failure(self):
        display = self.start(show=False)
        exited = subprocess.Popen([sys.executable, "-c", "raise SystemExit(3)"])
        exited.wait()
        with self.assertRaisesRegex(RuntimeError, "exited"):
            display.wait_mapped(exited, 5)
        alive = self.sleeper()
        with self.assertRaisesRegex(RuntimeError, "no window within 0.5 seconds"):
            display.wait_mapped(alive, 0.5)

    def test_compositor_death_is_a_display_failure(self):
        display = self.start(show=False)
        self.command("exit 9")
        self.until(lambda: display.poll() is not None)
        self.assertEqual(display.poll(), 1)
        self.assertIn("compositor stopped unexpectedly", display.failure)
        self.assertEqual(self.ended, [display])
        app = self.sleeper()
        with self.assertRaisesRegex(RuntimeError, "compositor stopped unexpectedly"):
            display.wait_mapped(app, 5)

    def test_supervisor_death_retires_the_compositor(self):
        code = f'''
import os, sys
sys.path.insert(0, {str(Path(__file__).parent)!r})
from pathlib import Path
from runtime import OwnedChildren
from vm_display import HeadlessDisplays
root = Path({str(self.root)!r})
display = HeadlessDisplays(root / "orphan", print).start("ombp", root / "orphan-public", "wayland-ombp", False,
                                                         OwnedChildren(), None)
os._exit(0)
'''
        parent = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30,
                                env=os.environ)
        self.assertEqual(parent.returncode, 0, parent.stderr)
        ipc = self.root / "orphan/ombp-1/sway-ipc.sock"
        self.assertTrue(ipc.is_socket())

        def retired():
            try:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.connect(str(ipc))
                return False
            except OSError:
                return True
        # desktop.py noticed its launcher died and stopped the compositor: nothing answers its IPC any more.
        self.until(retired)


@unittest.skipUnless(LINUX, "the Linux container backend runs inside the Linux VM guest")
class ContainerDisplayTests(_ScriptedCase):
    def setUp(self):
        super().setUp()
        from linux_runtime import ContainerBackend
        from policy import Policy
        self.backend = ContainerBackend(Policy(self.root / "state"), displays=self.displays)
        self.addCleanup(self.backend.stop)
        self.backend.children, self.backend.log = self.children, self.log

    def test_vm_refuses_gpu_passthrough_before_any_side_effect(self):
        for gpu in ("amd", "nvidia"):
            with self.subTest(gpu), patch("subprocess.Popen") as popen:
                with self.assertRaisesRegex(ValueError, "GPU passthrough is not available"):
                    self.backend.start("/nix/store/x-ombp/bin/omp-manager", True, gpu, self.root, "omp", self.log,
                                       self.children, installation={"installed_mode": False, "selected_packages": []},
                                       git_discovery_home="/host/home/u")
                popen.assert_not_called()

    def test_both_displays_are_headless_and_follow_the_desktop_setting(self):
        self.backend.show_desktop = False
        ombp = self.backend._display(self.root / "display", "wayland-ombp")
        self.assertEqual(ombp.kind, "ombp")
        self.assertFalse(ombp.show)
        ombp.terminate()
        # One scripted compositor at a time: the fake's control socket path is shared.
        self.control.unlink()
        browser = self.backend._display(self.root / "browser-display", "wayland-browser")
        self.assertEqual(browser.kind, "browser")
        self.assertFalse(browser.show)
        browser.terminate()
        # A shown desktop asks for the VNC server (absent in this scripted setup), proving the setting reached it.
        self.control.unlink()
        self.backend.show_desktop = True
        with self.assertRaisesRegex(ValueError, "wayvnc"):
            self.backend._display(self.root / "browser-display", "wayland-browser")

    def test_closing_ombp_display_stops_the_workload_and_is_not_an_error(self):
        self.backend.show_desktop = False
        self.backend.desktop_process = self.backend._display(self.root / "display", "wayland-ombp")
        self.backend.process = self.sleeper()
        self.command("views 1")
        self.backend.desktop_process.wait_mapped(self.backend.process, 10)
        self.command("views 0")
        code = self.backend.process.wait(timeout=10)
        self.assertNotEqual(code, 0)
        self.assertEqual(self.backend.exit_error(code), "")

    def test_display_failure_stops_the_workload_with_its_reason(self):
        self.backend.show_desktop = False
        self.backend.desktop_process = self.backend._display(self.root / "display", "wayland-ombp")
        self.backend.process = self.sleeper()
        self.command("exit 4")
        code = self.backend.process.wait(timeout=10)
        self.assertTrue(self.backend.exit_error(code).startswith("Isolated ombp compositor stopped unexpectedly"))

    def test_browser_display_failure_also_retires_the_workload(self):
        self.backend.show_desktop = False
        display = self.backend._display(self.root / "browser-display", "wayland-browser")
        self.addCleanup(display.terminate)
        self.backend.process = self.sleeper()
        self.command("exit 4")
        code = self.backend.process.wait(timeout=10)
        self.assertTrue(self.backend.exit_error(code).startswith("Isolated browser compositor stopped unexpectedly"))
        # Even an application that handles SIGTERM with exit 0 cannot hide the display failure.
        self.assertTrue(self.backend.exit_error(0).startswith("Isolated browser compositor stopped unexpectedly"))


SWAY = os.environ.get("START_APP_SWAY", "")
WAYVNC = os.environ.get("START_APP_WAYVNC", "")
REAL = LINUX and Path(SWAY).name == "sway" and Path(WAYVNC).name == "wayvnc"


def _exact(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(min(size - len(data), 1 << 20))
        if not chunk:
            raise EOFError
        data += chunk
    return bytes(data)


class _Rfb:
    """Minimal RFB 3.8 client: no-auth handshake, raw encoding, ExtendedDesktopSize."""

    def __init__(self, port):
        self.connection = socket.create_connection(("127.0.0.1", port), timeout=15)
        self.version = _exact(self.connection, 12)
        self.connection.sendall(b"RFB 003.008\n")
        count = _exact(self.connection, 1)[0]
        types = _exact(self.connection, count)
        if 1 not in types:
            raise AssertionError(f"no None security type offered: {list(types)}")
        self.connection.sendall(b"\x01")
        if struct.unpack(">I", _exact(self.connection, 4))[0]:
            raise AssertionError("security handshake failed")
        self.connection.sendall(b"\x01")  # shared
        self.width, self.height = struct.unpack(">HH", _exact(self.connection, 4))
        self.bpp = _exact(self.connection, 16)[0]
        _exact(self.connection, struct.unpack(">I", _exact(self.connection, 4))[0])
        # SetEncodings: raw, ExtendedDesktopSize (-308).
        self.connection.sendall(struct.pack(">BxHii", 2, 2, 0, -308))

    def request(self, incremental=0):
        self.connection.sendall(struct.pack(">BBHHHH", 3, incremental, 0, 0, self.width, self.height))

    def desktop_size(self, timeout=15):
        """Read updates until an ExtendedDesktopSize rectangle: (reason x, status y, width, height)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            kind = _exact(self.connection, 1)[0]
            if kind != 0:
                raise AssertionError(f"unexpected server message {kind}")
            _exact(self.connection, 1)
            rectangles = struct.unpack(">H", _exact(self.connection, 2))[0]
            found = None
            for _ in range(rectangles):
                x, y, width, height, encoding = struct.unpack(">HHHHi", _exact(self.connection, 12))
                if encoding == 0:
                    _exact(self.connection, width * height * self.bpp // 8)
                elif encoding == -308:
                    screens = _exact(self.connection, 4)[0]
                    self.screen = _exact(self.connection, 16 * screens)[:4]
                    self.width, self.height = width, height
                    found = (x, y, width, height)
                else:
                    raise AssertionError(f"unexpected encoding {encoding}")
            if found:
                return found
            self.request(1)
        raise AssertionError("no ExtendedDesktopSize rectangle")

    def set_desktop_size(self, width, height):
        self.connection.sendall(struct.pack(">BxHHBx", 251, width, height, 1) + self.screen +
                                struct.pack(">HHHHI", 0, 0, width, height, 0))

    def close(self):
        self.connection.close()


@unittest.skipUnless(REAL, "needs the guest runtime's START_APP_SWAY and START_APP_WAYVNC")
class RealSwayTests(_DisplayCase):
    def test_vnc_on_guest_loopback_with_remote_resize_and_private_ipc(self):
        display = self.start(show=True)
        self.assertEqual(self.events, [{"event": "display", "kind": "ombp", "generation": display.generation,
                                        "state": "ready", "vnc_port": display.vnc_port}])
        self.assertEqual(display._listener.getsockname()[0], "127.0.0.1")
        self.assertEqual(sorted(path.name for path in display.public.iterdir()), ["wayland-ombp"])
        self.assertTrue((display.private / "wayvnc.sock").is_socket())
        self.assertTrue((display.private / "sway-ipc.sock").is_socket())
        client = _Rfb(display.vnc_port)
        self.addCleanup(client.close)
        self.assertEqual(client.version, b"RFB 003.008\n")
        client.request()
        client.desktop_size()
        client.set_desktop_size(1000, 700)
        client.request(1)
        reason, status, width, height = client.desktop_size()
        while reason != 1:
            client.request(1)
            reason, status, width, height = client.desktop_size()
        # 0 = applied; 4 = forwarded to the compositor, which then announces the new size itself (noVNC follows it).
        self.assertIn(status, (0, 4))
        while status == 4 or (width, height) != (1000, 700):
            client.request(1)
            reason, status, width, height = client.desktop_size()
        self.assertEqual((status, width, height), (0, 1000, 700))
        query = vm_display._Ipc(display.ipc_path)
        self.addCleanup(query.close)
        outputs = query.request(3)  # GET_OUTPUTS
        self.assertEqual([(item["current_mode"]["width"], item["current_mode"]["height"]) for item in outputs],
                         [(1000, 700)])
        display.terminate()
        self.assertEqual(self.events[-1]["state"], "closed")
        self.assertIsNotNone(display.wayvnc.poll())
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", display.vnc_port), timeout=2).close()

    def test_viewer_keyboard_is_the_chosen_layout(self):
        for keyboard, expected in (("default", "English (US)"), ("dk", "Danish")):
            with self.subTest(keyboard=keyboard):
                self.displays = HeadlessDisplays(self.root / f"private-{keyboard}", self.events.append, keyboard)
                display = self.start(show=True)
                client = _Rfb(display.vnc_port)
                query = vm_display._Ipc(display.ipc_path)
                try:
                    layouts = []

                    def connected():
                        layouts[:] = [item.get("xkb_active_layout_name") for item in query.request(100)  # GET_INPUTS
                                      if item["type"] == "keyboard"]
                        return bool(layouts)
                    # The viewer's virtual keyboard appears once its VNC client is connected.
                    self.until(connected)
                    self.assertEqual(layouts, [expected])
                finally:
                    query.close()
                    client.close()
                    display.terminate()

    def test_zenity_picker_floats_over_the_whole_output_and_follows_viewer_resizes(self):
        zenity = os.environ.get("START_APP_ZENITY")
        if not zenity:
            self.skipTest("needs the guest runtime's START_APP_ZENITY")
        display = self.start(show=True)
        runtime = self.root / "picker-runtime"
        runtime.mkdir(mode=0o700)
        picker = subprocess.Popen([zenity, "--file-selection"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env={"PATH": os.environ["PATH"], "HOME": str(self.root), "GDK_BACKEND": "wayland",
                                       "XDG_RUNTIME_DIR": str(runtime), "WAYLAND_DISPLAY": str(display.socket)})
        self.addCleanup(picker.wait)
        self.addCleanup(picker.kill)
        query = vm_display._Ipc(display.ipc_path)
        self.addCleanup(query.close)

        def geometry():
            def find(node):
                if node.get("app_id") == "zenity":
                    return node
                for child in (*node.get("nodes", ()), *node.get("floating_nodes", ())):
                    if (found := find(child)) is not None:
                        return found
                return None
            node = find(query.request(4))  # GET_TREE
            if node is None:
                return None
            output = query.request(3)[0]["current_mode"]  # GET_OUTPUTS
            return (node["type"], node["fullscreen_mode"], node["rect"]["width"], node["rect"]["height"],
                    output["width"], output["height"])

        self.until(lambda: geometry() is not None, 30)
        kind, fullscreen, width, height, output_width, output_height = geometry()
        self.assertEqual((kind, fullscreen), ("floating_con", 0))
        self.assertEqual((width, height), (output_width, output_height))
        client = _Rfb(display.vnc_port)
        self.addCleanup(client.close)
        client.request()
        client.desktop_size()
        client.set_desktop_size(1000, 700)
        self.until(lambda: geometry()[2:] == (1000, 700, 1000, 700), 15)
        # Sway itself only clamps a picker into a smaller output; a larger one needs the size reapplied.
        client.set_desktop_size(1400, 900)
        self.until(lambda: geometry()[2:] == (1400, 900, 1400, 900), 15)
        self.assertIsNone(picker.poll(), "The picker stays open across viewer resizes")

    def test_vnc_death_fails_the_display_and_retires_the_compositor(self):
        display = self.start(show=True)
        os.killpg(display.wayvnc.pid, 9)
        self.until(lambda: display.poll() is not None)
        self.assertEqual(display.poll(), 1)
        self.assertIn("VNC server stopped unexpectedly", display.failure)
        self.assertEqual(self.events[-1]["state"], "failed")
        self.assertIsNotNone(display.sway.poll())
        self.assertEqual(self.ended, [display])

    def test_hidden_desktop_has_no_vnc_listener(self):
        display = self.start(show=False)
        self.assertIsNone(display.wayvnc)
        self.assertEqual(self.events, [])

    @unittest.skipUnless(Path(os.environ.get("START_APP_WESTON", "/nonexistent")).with_name("weston-flower").exists(),
                         "needs a Wayland demo client (weston-flower) from the runtime closure")
    def test_real_client_maps_then_closing_it_stops_ombp(self):
        display = self.start(show=True)
        client = subprocess.Popen([str(Path(os.environ["START_APP_WESTON"]).with_name("weston-flower"))],
                                  env={**os.environ, "WAYLAND_DISPLAY": str(display.socket),
                                       "XDG_RUNTIME_DIR": str(self.root)},
                                  stdout=self.log, stderr=self.log)
        self.addCleanup(client.kill)
        display.wait_mapped(client, 30)
        client.terminate()
        client.wait(timeout=10)
        self.until(lambda: display.poll() is not None)
        self.assertEqual(display.poll(), 0)
        self.assertEqual(self.ended, [display])
        self.assertEqual(self.events[-1]["state"], "closed")


if __name__ == "__main__":
    unittest.main()
