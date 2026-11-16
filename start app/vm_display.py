"""Guest-only isolated displays for the macOS Linux VM: headless Sway plus wayvnc on guest loopback.

Each display has a private runtime directory (Sway IPC, wayvnc control socket, configuration, the compositor's
own Wayland socket) and a public capability directory holding only a hard link to the intended Wayland socket
(plus, for the browser display, BrowserDisplay's request.sock). Only the public directory reaches the container.
The nested Weston path in linux_runtime.py stays the Linux host's display; wayvnc does not support Weston.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

# Linux sockaddr_un.sun_path holds 108 bytes including the terminator.
SOCKET_PATH_LIMIT = 107
COMPOSITOR_TIMEOUT = 15
SURFACE_TIMEOUT = 30
KINDS = ("ombp", "browser")

# No key bindings (so nothing can launch a shell), bars, Xwayland, swaynag or window frames. The application fills
# the output; Sway floats dialogs and popups itself, and the browser keeps its own tabs and address bar. Zenity file
# pickers (OMBP's sandbox dialog) float over the whole output so their OK/Cancel controls stay reachable.
PICKER = '[app_id="^zenity$"]'
PICKER_GEOMETRY = "resize set width 100 ppt height 100 ppt, move position center"
SWAY_CONFIG = f"""\
xwayland disable
swaynag_command -
default_border none
default_floating_border none
hide_edge_borders both
focus_on_window_activation focus
for_window {PICKER} fullscreen disable, floating enable, {PICKER_GEOMETRY}
"""

_IPC_MAGIC = b"i3-ipc"
_IPC_RUN_COMMAND = 0
_IPC_SUBSCRIBE = 2
_IPC_GET_TREE = 4
_EVENT_OUTPUT = 0x80000001
_EVENT_WINDOW = 0x80000003
_EVENT_SHUTDOWN = 0x80000006


class _Ipc:
    """One Sway IPC connection (private socket; never reachable from the container)."""

    def __init__(self, path, timeout=5):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        try:
            self.socket.connect(str(path))
        except OSError:
            self.socket.close()
            raise

    def send(self, kind, payload=b""):
        self.socket.sendall(_IPC_MAGIC + struct.pack("=II", len(payload), kind) + payload)

    def _exact(self, size):
        data = bytearray()
        while len(data) < size:
            chunk = self.socket.recv(size - len(data))
            if not chunk:
                raise EOFError("Sway IPC closed")
            data += chunk
        return bytes(data)

    def receive(self):
        header = self._exact(14)
        if header[:6] != _IPC_MAGIC:
            raise ValueError("Invalid Sway IPC reply")
        size, kind = struct.unpack("=II", header[6:])
        if size > 16 << 20:
            raise ValueError("Oversized Sway IPC reply")
        return kind, json.loads(self._exact(size))

    def request(self, kind, payload=b""):
        self.send(kind, payload)
        while True:
            reply_kind, value = self.receive()
            if reply_kind == kind:
                return value

    def close(self):
        self.socket.close()


def count_views(node):
    """Mapped application surfaces in a Sway tree: containers that carry a view (`shell`)."""
    own = 1 if node.get("shell") else 0
    return own + sum(count_views(child) for key in ("nodes", "floating_nodes") for child in node.get(key, ()))


def _check_socket_path(path):
    if len(os.fsencode(path)) > SOCKET_PATH_LIMIT:
        raise ValueError(f"Display socket path is too long for a Unix socket: {path}")


def _private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError(f"Display directory must be a private, owner-only directory: {path}")


class HeadlessDisplay:
    """One compositor (and, when shown, one VNC server) with Popen-like lifetime for linux_runtime's callers.

    returncode is 0 after the user closed the final OMBP surface or an owner retired it, nonzero after a failure;
    `failure` then describes it. All of its processes retire together.
    """

    def __init__(self, displays, kind, generation, public, name, show, children, log, on_end):
        self.displays = displays
        self.kind = kind
        self.generation = generation
        self.public = Path(public)
        self.name = name
        self.socket = self.public / name
        self.show = show
        self.children = children
        self.log = log
        self.on_end = on_end
        self.private = displays.root / f"{kind}-{generation}"
        self.vnc_port = None
        self.failure = ""
        self.returncode = None
        self.sway = None
        self.wayvnc = None
        self._listener = None
        self._ipc = None
        self._lock = threading.Lock()
        self._retired = threading.Event()
        self._finished = threading.Event()
        self._mapped = threading.Event()
        self._views = 0
        self._announced = False

    # --- startup -------------------------------------------------------------------------------------------------

    def start(self):
        try:
            self._start_compositor()
            if self.show:
                self._start_vnc()
            # Announce before starting monitors, so a rapid failure can never publish ready after closed/failed.
            if self.show:
                self._announced = True
                self.displays.emit({"event": "display", "kind": self.kind, "generation": self.generation,
                                    "state": "ready", "vnc_port": self.vnc_port})
            threading.Thread(target=self._monitor, name=f"display-{self.kind}-{self.generation}",
                             daemon=True).start()
            threading.Thread(target=self._watch, name=f"display-watch-{self.kind}-{self.generation}",
                             daemon=True).start()
        except BaseException:
            self._retire(1, "")
            raise
        return self

    def _environment(self):
        environment = {key: os.environ[key] for key in ("PATH", "LANG", "LOCALE_ARCHIVE", "FONTCONFIG_FILE")
                       if key in os.environ}
        if os.environ.get("START_APP_FONTCONFIG"):
            environment["FONTCONFIG_FILE"] = os.environ["START_APP_FONTCONFIG"]
        environment.update(HOME=str(self.private), XDG_RUNTIME_DIR=str(self.private),
                           XDG_CONFIG_HOME=str(self.private / "config"),
                           WLR_BACKENDS="headless", WLR_RENDERER="pixman", WLR_LIBINPUT_NO_DEVICES="1",
                           WLR_HEADLESS_OUTPUTS="1")
        return environment

    def _spawn(self, program, arguments, environment, pass_fds=()):
        # desktop.py retires the compositor and VNC server when the guest supervisor dies, not only on stop().
        return self.children.popen(
            [sys.executable, str(Path(__file__).with_name("desktop.py")), str(os.getpid()), program, *arguments],
            env=environment, stdout=self.log, stderr=self.log, stdin=subprocess.DEVNULL,
            start_new_session=True, pass_fds=pass_fds)

    def _start_compositor(self):
        sway = os.environ.get("START_APP_SWAY")
        if not sway:
            raise ValueError("The isolated VM display requires the guest runtime's Sway (START_APP_SWAY)")
        if self.private.exists() or self.private.is_symlink():
            shutil.rmtree(self.private)
        _private_directory(self.private)
        _private_directory(self.public)
        _check_socket_path(self.socket)
        self.ipc_path = self.private / "sway-ipc.sock"
        _check_socket_path(self.ipc_path)
        if os.stat(self.private).st_dev != os.stat(self.public).st_dev:
            raise ValueError("Display private and public directories must share one filesystem")
        self.socket.unlink(missing_ok=True)
        config = self.private / "sway.config"
        config.write_text(SWAY_CONFIG)
        # Sway 1.12 uses a not-yet-existing SWAYSOCK as its IPC path: keep it in the private directory.
        environment = {**self._environment(), "SWAYSOCK": str(self.ipc_path)}
        self.sway = self._spawn(sway, ["--config", str(config)], environment)
        deadline = time.monotonic() + COMPOSITOR_TIMEOUT
        while True:
            wayland = [path for path in self.private.glob("wayland-*")
                       if not path.name.endswith(".lock") and path.is_socket()]
            if wayland and self.ipc_path.is_socket():
                break
            if self.sway.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(f"Isolated {self.kind} compositor did not start; inspect launch.log")
            time.sleep(0.05)
        if len(wayland) != 1:
            raise RuntimeError("Isolated compositor created unexpected Wayland sockets")
        self.wayland = wayland[0]
        # Only this one socket inode enters the public capability directory; Sway IPC stays private.
        os.link(self.wayland, self.socket)
        # The socket file appears at bind(); Sway accepts only once it listens.
        while self._ipc is None:
            try:
                self._ipc = _Ipc(self.ipc_path)
            except OSError:
                if self.sway.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"Isolated {self.kind} compositor IPC did not start; inspect launch.log")
                time.sleep(0.05)
        self._ipc.send(_IPC_SUBSCRIBE, json.dumps(["window", "output", "shutdown"]).encode())
        kind, reply = self._ipc.receive()
        if kind != _IPC_SUBSCRIBE or not reply.get("success"):
            raise RuntimeError("Could not monitor isolated compositor windows")
        self._ipc.socket.settimeout(None)

    def _start_vnc(self):
        wayvnc = os.environ.get("START_APP_WAYVNC")
        if not wayvnc:
            raise ValueError("The isolated VM viewer requires the guest runtime's wayvnc (START_APP_WAYVNC)")
        config = self.private / "wayvnc.config"
        config.write_text("address=127.0.0.1\n")
        control = self.private / "wayvnc.sock"
        _check_socket_path(control)
        # A listener this process bound itself: guest loopback only, no port race, handed over as fd:N.
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.vnc_port = self._listener.getsockname()[1]
        descriptor = self._listener.fileno()
        environment = {**self._environment(), "WAYLAND_DISPLAY": self.wayland.name}
        self.wayvnc = self._spawn(wayvnc, ["--config", str(config), "--socket", str(control),
                                           "--log-level=warning", f"fd:{descriptor}"],
                                  environment, pass_fds=(descriptor,))
        deadline = time.monotonic() + COMPOSITOR_TIMEOUT
        while True:
            if self.wayvnc.poll() is not None:
                raise RuntimeError(f"Isolated {self.kind} VNC server did not start; inspect launch.log")
            try:
                with socket.create_connection(("127.0.0.1", self.vnc_port), timeout=1) as probe:
                    if probe.recv(12).startswith(b"RFB "):
                        return
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Isolated {self.kind} VNC server did not become ready; inspect launch.log")
            time.sleep(0.1)

    # --- supervision ---------------------------------------------------------------------------------------------

    def _monitor(self):
        """Follow window events; after the first OMBP surface, closing the last one is the user's Stop.

        A viewer resize changes the output: an open picker then gets the new output's size again.
        """
        try:
            while not self._retired.is_set():
                kind, value = self._ipc.receive()
                if kind == _EVENT_SHUTDOWN:
                    break
                if kind == _EVENT_OUTPUT:
                    self._command(f"{PICKER} {PICKER_GEOMETRY}")
                    continue
                if kind != _EVENT_WINDOW:
                    continue
                query = _Ipc(self.ipc_path)
                try:
                    views = count_views(query.request(_IPC_GET_TREE))
                finally:
                    query.close()
                self._views = views
                if views:
                    self._mapped.set()
                elif self._mapped.is_set() and self.kind == "ombp":
                    self._end(0, "")
                    return
        except (OSError, EOFError, ValueError):
            pass
        if not self._retired.is_set():
            self._end(1, f"Isolated {self.kind} compositor stopped unexpectedly")

    def _command(self, command):
        """Run one Sway command on a separate private connection; no matching window is not an error."""
        connection = _Ipc(self.ipc_path)
        try:
            connection.request(_IPC_RUN_COMMAND, command.encode())
        finally:
            connection.close()

    def _watch(self):
        while not self._retired.wait(0.25):
            if self.sway.poll() is not None:
                self._end(1, f"Isolated {self.kind} compositor stopped unexpectedly")
            elif self.wayvnc is not None and self.wayvnc.poll() is not None:
                self._end(1, f"Isolated {self.kind} VNC server stopped unexpectedly")

    def _end(self, code, failure):
        if self._retire(code, failure) and self.on_end is not None:
            self.on_end(self)

    def wait_mapped(self, process, timeout=SURFACE_TIMEOUT):
        """Block until the application maps its first surface; its exit, display failure or timeout is an error."""
        deadline = time.monotonic() + timeout
        while not self._mapped.wait(0.1):
            if self._retired.is_set():
                raise RuntimeError(self.failure or f"Isolated {self.kind} display closed before OMBP appeared")
            if process.poll() is not None:
                raise RuntimeError(f"OMBP exited ({process.returncode}) before showing a window; see launch.log")
            if time.monotonic() >= deadline:
                raise RuntimeError(f"OMBP showed no window within {timeout} seconds; see launch.log")
        if self._retired.is_set():
            raise RuntimeError(self.failure or f"Isolated {self.kind} display closed")
        if process.poll() is not None:
            raise RuntimeError(f"OMBP exited ({process.returncode}) during window startup; see launch.log")

    def _retire(self, code, failure):
        """Stop every process of this display once; True for the call that did it."""
        with self._lock:
            if self._retired.is_set():
                return False
            self.failure = failure
            self._retired.set()
        for process in (self.wayvnc, self.sway):
            if process is not None and process.poll() is None:
                process.terminate()
        for process in (self.wayvnc, self.sway):
            if process is not None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if self._ipc is not None:
            try:
                # Wakes the monitor thread's blocking receive; close() alone does not on Linux.
                self._ipc.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for resource in (self._ipc, self._listener):
            if resource is not None:
                try:
                    resource.close()
                except OSError:
                    pass
        self.socket.unlink(missing_ok=True)
        shutil.rmtree(self.private, ignore_errors=True)
        self.returncode = code
        self._finished.set()
        if self._announced:
            self.displays.emit({"event": "display", "kind": self.kind, "generation": self.generation,
                                "state": "failed" if code else "closed", "vnc_port": None})
        return True

    # --- Popen-like interface ------------------------------------------------------------------------------------

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if not self._finished.wait(timeout):
            raise subprocess.TimeoutExpired("isolated display", timeout)
        return self.returncode

    def terminate(self):
        self._retire(0, "")

    kill = terminate


class HeadlessDisplays:
    """The guest's display backend for ContainerBackend(displays=...): software-rendered Sway, never a GPU."""

    headless = True

    def __init__(self, root, emit):
        self.root = Path(root)
        self.emit = emit
        self._generation = 0
        self._lock = threading.Lock()

    def start(self, kind, public, name, show, children, log, on_end=None):
        """A ready display serving public/name. `show` adds a loopback VNC listener and display events."""
        if kind not in KINDS:
            raise ValueError("Unknown display kind")
        _private_directory(self.root)
        with self._lock:
            self._generation += 1
            generation = self._generation
        return HeadlessDisplay(self, kind, generation, public, name, show, children, log, on_end).start()
