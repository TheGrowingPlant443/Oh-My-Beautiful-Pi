import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
import unittest

from policy import Policy
import browser
from runtime import Cancelled, OwnedChildren, Runtime


def _until(condition, timeout=10):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError("Condition not reached in time")
        time.sleep(0.01)


NIX = """#!/bin/sh
echo $$ > "$OMBP_TEST_DIR/nix-pid"
printf '%s\\n' "$@" > "$OMBP_TEST_DIR/nix-args"
case "$(cat "$OMBP_TEST_DIR/build-mode")" in
  fail) echo "build failed" >&2; exit 1 ;;
  hang) exec sleep 60 ;;
  late) trap '' TERM; : > "$OMBP_TEST_DIR/trapped"; sleep 1; cat "$OMBP_TEST_DIR/build-output" ;;
  *) cat "$OMBP_TEST_DIR/build-output" ;;
esac
"""

APP = """#!/bin/sh
echo "$OMBP_AGENT" >> "$OMBP_TEST_DIR/launched"
if [ -f "$OMBP_TEST_DIR/app-exit" ]; then exit "$(cat "$OMBP_TEST_DIR/app-exit")"; fi
exec sleep 60
"""


class FakeNix:
    """A real `nix` executable on PATH and a store-like build output whose behaviour each test chooses."""

    def __init__(self, test, root):
        self.root = root
        directory = root / "bin"
        directory.mkdir()
        (directory / "nix").write_text(NIX)
        (directory / "nix").chmod(0o755)
        self.output = root / "store" / ("0" * 32 + "-ombp")
        app = self.output / "bin/omp-manager"
        app.parent.mkdir(parents=True)
        app.write_text(APP)
        app.chmod(0o755)
        self.source = root / "checkout"
        self.source.mkdir()
        (self.source / "flake.nix").write_text("{}")
        for active in (patch.dict(os.environ, {"PATH": f"{directory}:{os.environ.get('PATH', os.defpath)}",
                                               "OMBP_TEST_DIR": str(root)}),
                       patch("runtime.STORE", f"{root / 'store'}/")):
            active.start()
            test.addCleanup(active.stop)
        self.behave("ok")

    def behave(self, mode, output=None):
        (self.root / "build-mode").write_text(mode)
        (self.root / "build-output").write_text(f"{self.output}\n" if output is None else output)

    def read(self, name):
        path = self.root / name
        return path.read_text().splitlines() if path.exists() else []

    def reset(self):
        for name in ("nix-args", "nix-pid", "launched"):
            (self.root / name).unlink(missing_ok=True)


class FakeVm:
    """A macOS VM backend stand-in whose launch waits, recording what each launch was admitted with."""
    name = "linux-vm"
    container = None
    run = None

    def __init__(self):
        self.admitted = threading.Event()
        self.released = threading.Event()
        self.received = []
        self.asked = "never"

    def status_fields(self):
        return {"desktops": [], "catalog_generation": 1, "policy_generation": 0, "applied_policy_generation": 0}

    def requirements_status(self, installation=None):
        self.asked = installation
        return []

    def launch(self, settings, log, children, advance, *, installation):
        self.received.append(installation)
        self.admitted.set()
        while not self.released.wait(0.05):
            children.check()

    def cancel_preparation(self):
        self.released.set()

    close = cancel_preparation


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.nix = FakeNix(self, self.root)
        self.policy = Policy(self.root / "state")
        self.runtime = Runtime(self.policy)
        self.addCleanup(self.runtime.close)

    def start(self, agent="omp", mode="normal"):
        return self.runtime.start(str(self.nix.source), mode, False, "none", agent)

    def until_phase(self, *phases):
        _until(lambda: self.runtime.status()["phase"] in phases)
        return self.runtime.status()

    def stop(self):
        self.runtime.stop()
        return self.until_phase("stopped")

    def test_start_returns_an_operation_and_reports_running_only_once_live(self):
        self.nix.behave("hang")
        operation = self.start()
        self.assertRegex(operation, r"^[0-9a-f]{32}$")
        _until(lambda: self.nix.read("nix-args"))
        status = self.runtime.status()
        self.assertEqual((status["phase"], status["operation_id"], status["backend"]), ("building", operation, "native"))
        self.assertTrue(status["starting"])
        self.assertFalse(status["running"])
        self.assertEqual(status["desktops"], [])
        with self.assertRaisesRegex(ValueError, "building"):
            self.start()
        self.stop()

        self.nix.reset()
        self.nix.behave("ok")
        operation = self.start(agent="omsp")
        status = self.until_phase("running")
        self.assertTrue(status["running"])
        self.assertFalse(status["starting"])
        self.assertEqual((status["operation_id"], status["launch"]["agent"]), (operation, "omsp"))
        _until(lambda: self.nix.read("launched"))
        self.assertEqual(self.nix.read("launched"), ["omsp"])
        self.assertEqual(self.nix.read("nix-args"), ["--extra-experimental-features", "nix-command flakes", "build",
                                                     "path:.#omsp", "--no-link", "--print-out-paths",
                                                     "--print-build-logs", "--no-write-lock-file"])
        with self.assertRaisesRegex(ValueError, "Already running"):
            self.start()
        status = self.stop()
        self.assertEqual((status["running"], status["operation_id"], status["error"]), (False, None, ""))

    def test_failed_build_never_launches_the_previous_app(self):
        self.start()
        self.until_phase("running")
        _until(lambda: self.nix.read("launched"))
        self.stop()
        self.nix.reset()
        self.nix.behave("fail")
        self.start()
        status = self.until_phase("failed")
        self.assertIn("OMBP build failed", status["error"])
        self.assertIn("path:.#default", self.nix.read("nix-args"))
        self.assertEqual(self.nix.read("launched"), [])
        self.assertIsNone(status["launch"])
        self.assertFalse(status["running"])

    def test_ambiguous_build_output_never_launches(self):
        self.nix.behave("ok", f"{self.nix.output}\n{self.nix.output}\n")
        self.start()
        self.assertIn("one Nix store output", self.until_phase("failed")["error"])
        self.assertEqual(self.nix.read("launched"), [])

    def test_stop_during_build_never_launches_late(self):
        # The build ignores Stop's SIGTERM and still returns a valid output afterwards.
        self.nix.behave("late")
        self.start()
        _until((self.root / "trapped").exists)
        self.runtime.stop()
        self.assertEqual(self.runtime.status()["phase"], "stopping")
        status = self.until_phase("stopped")
        self.assertEqual(status["error"], "")
        self.assertEqual(self.nix.read("launched"), [])
        self.assertFalse((self.policy.directory / "last-launch.json").exists())

    def test_close_during_build_reaps_child_and_refuses_new_launches(self):
        self.nix.behave("hang")
        self.start()
        _until(lambda: self.nix.read("nix-pid"))
        build = int(self.nix.read("nix-pid")[0])
        self.runtime.close()
        with self.assertRaises(ProcessLookupError):
            os.kill(build, 0)
        status = self.runtime.status()
        self.assertEqual((status["phase"], status["running"], status["launch"]), ("stopped", False, None))
        with self.assertRaisesRegex(RuntimeError, "closing"):
            self.start()
        self.assertEqual(self.nix.read("launched"), [])

    def test_application_crash_fails_but_clean_exit_stops(self):
        (self.root / "app-exit").write_text("3")
        self.start()
        self.assertTrue(self.until_phase("failed")["error"].startswith("Process exited 3"))
        (self.root / "app-exit").write_text("0")
        self.start()
        _until(lambda: len(self.nix.read("launched")) == 2)
        self.assertEqual(self.until_phase("stopped")["error"], "")

    def test_last_launch_is_written_only_when_the_operation_reaches_running(self):
        record = self.policy.directory / "last-launch.json"
        self.nix.behave("fail")
        self.start()
        self.until_phase("failed")
        self.nix.behave("hang")
        self.start()
        _until(lambda: self.nix.read("nix-args"))
        self.stop()
        self.assertFalse(record.exists())
        enabled = self.policy.snapshot()
        enabled["auto_start"] = {"source": str(self.nix.source), "mode": "normal", "desktop": True, "gpu": "none",
                                 "agent": "omp"}
        self.policy.replace(enabled)
        self.nix.behave("ok")
        self.start(agent="omsp")
        self.until_phase("running")
        _until(record.exists)
        expected = {"source": str(self.nix.source.resolve()), "mode": "normal", "desktop": False, "gpu": "none",
                    "agent": "omsp"}
        self.assertEqual(json.loads(record.read_text()), expected)
        self.assertEqual(self.policy.last_launch(), expected)
        # Enabled automatic start follows the launch that actually ran.
        _until(lambda: self.policy.snapshot()["auto_start"] == expected)

    def test_isolated_launch_keeps_the_installation_it_was_admitted_with(self):
        original, vm = self.runtime.isolated, FakeVm()
        if hasattr(original, "close"):
            self.addCleanup(original.close)
        self.runtime.host, self.runtime.isolated = "darwin", vm
        desired = self.policy.snapshot()
        desired.update(installed_mode=True, selected_packages=["gh"])
        self.policy.replace(desired)
        self.runtime.start(str(self.nix.source), "container", False, "none", "omp")
        self.assertTrue(vm.admitted.wait(5))
        # Saved while the launch prepares: next Start's choice, never this launch's.
        changed = self.policy.snapshot()
        changed.update(installed_mode=False, selected_packages=["ssh"])
        self.policy.replace(changed)
        launch = self.runtime.status()["launch"]
        self.assertEqual((launch["installed_mode"], launch["selected_packages"], launch["executable"]),
                         (True, ["gh"], None))
        self.assertEqual(vm.received, [{"installed_mode": True, "selected_packages": ["gh"]}])
        self.runtime.requirements_status()
        self.assertEqual(vm.asked, {"installed_mode": True, "selected_packages": ["gh"]})
        self.stop()
        self.runtime.requirements_status()
        self.assertIsNone(vm.asked, "An idle launcher shows the desired policy")
        self.assertFalse((self.policy.directory / "last-launch.json").exists())

    def test_invalid_settings_are_rejected_before_admission(self):
        with self.assertRaisesRegex(ValueError, "Invalid launch settings"):
            self.start(agent="bad")
        (self.nix.source / "flake.nix").unlink()
        with self.assertRaisesRegex(ValueError, "source folder"):
            self.start()
        for source in ("", "   "):
            with self.assertRaisesRegex(ValueError, "source folder"):
                self.runtime.start(source, "normal", False, "none", "omp")
        status = self.runtime.status()
        self.assertEqual((status["phase"], status["operation_id"]), ("stopped", None))
        self.assertEqual(self.nix.read("nix-args"), [])

    @unittest.skipUnless(sys.platform == "darwin", "The macOS VM backend reads Mac hardware facts")
    def test_macos_isolated_mode_runs_in_the_vm_backend_never_on_the_host(self):
        runtime = Runtime(self.policy, host="darwin")
        self.addCleanup(runtime.close)
        with self.assertRaisesRegex(ValueError, "GPU passthrough is not available"):
            runtime.start(str(self.nix.source), "container", True, "amd", "omp")
        status = runtime.status()
        self.assertEqual((status["phase"], status["backend"], status["container"]), ("stopped", "linux-vm", None))
        runtime.isolated.limactl = runtime.isolated.template = None
        runtime.start(str(self.nix.source), "container", True, "none", "omp")
        _until(lambda: runtime.status()["phase"] == "failed")
        self.assertIn("supplied Nix launcher", runtime.status()["error"])
        # Isolated macOS launches never build or run OMBP on the Mac itself.
        self.assertEqual(self.nix.read("nix-args"), [])
        self.assertEqual(self.nix.read("launched"), [])

    def test_failure_before_admission_is_reported(self):
        self.runtime.fail("Automatic start failed: missing checkout")
        status = self.runtime.status()
        self.assertEqual((status["phase"], status["error"]), ("failed", "Automatic start failed: missing checkout"))
        self.start()
        self.assertEqual(self.runtime.status()["error"], "")


class OwnedChildrenTests(unittest.TestCase):
    def test_cancel_ends_running_child_and_refuses_new_ones(self):
        children = OwnedChildren()
        errors = []

        def run():
            try:
                children.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=60)
            except Cancelled as error:
                errors.append(str(error))
        worker = threading.Thread(target=run)
        worker.start()
        _until(lambda: children._processes)
        children.cancel()
        worker.join(10)
        self.assertFalse(worker.is_alive(), "Cancellation did not reach the owned child")
        self.assertEqual(errors, ["Launch cancelled"])
        with patch("runtime.subprocess.Popen") as spawn, self.assertRaises(Cancelled):
            children.popen(["true"])
        spawn.assert_not_called()
        children.retire()

    def test_child_ignoring_terminate_is_killed_after_grace(self):
        children = OwnedChildren()
        child = children.popen([sys.executable, "-c",
                                "import signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                                "print('ready', flush=True); time.sleep(60)"], stdout=subprocess.PIPE)
        self.assertEqual(child.stdout.readline(), b"ready\n")
        children.cancel(grace=0.2)
        children.retire()
        self.assertEqual(child.returncode, -9)
        child.stdout.close()

    def test_run_lines_delivers_output_while_the_child_still_runs(self):
        children = OwnedChildren()
        self.addCleanup(children.retire)
        lines, first = [], threading.Event()

        def on_line(line):
            lines.append(line)
            first.set()
        script = ("import sys, time; print(sys.stdin.read().strip(), flush=True); time.sleep(0.5); "
                  "print('done'); sys.exit(3)")
        worker = threading.Thread(target=lambda: lines.append(children.run_lines(
            [sys.executable, "-c", script], timeout=30, on_line=on_line, input=b"hello\n")))
        worker.start()
        self.assertTrue(first.wait(5))
        self.assertEqual(lines, [b"hello\n"])  # Delivered before the child exited.
        worker.join(10)
        self.assertEqual(lines, [b"hello\n", b"done\n", 3])
        self.assertEqual(children._processes, [])
        with self.assertRaises(subprocess.TimeoutExpired):
            children.run_lines([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.3, on_line=print)


class BrowserWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.request = str(Path(self.temp.name) / "request.sock")
        environment = patch.dict(os.environ, {"START_APP_BROWSER": "/real/chrome", "WAYLAND_DISPLAY": "host"})
        environment.start()
        self.addCleanup(environment.stop)

    def serve(self, reply):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(self.request)
        server.listen()

        def answer():
            connection, _ = server.accept()
            self.addCleanup(connection.close)
            connection.sendall(reply)
            if not reply:
                connection.close()
        threading.Thread(target=answer, daemon=True).start()

    def test_ready_window_hands_inheritable_connection_to_real_browser(self):
        self.serve(b"ready\n")
        with patch("browser.REQUEST", self.request), patch("browser.os.execv") as execv:
            client = browser.main(["google-chrome-stable", "--remote-debugging-port=0"])
        self.addCleanup(client.close)
        execv.assert_called_once_with("/real/chrome", ["/real/chrome", "--remote-debugging-port=0"])
        self.assertTrue(os.get_inheritable(client.fileno()))
        self.assertEqual(os.environ["WAYLAND_DISPLAY"], browser.DISPLAY)

    def test_failed_window_never_starts_browser(self):
        self.serve(b"")
        with patch("browser.REQUEST", self.request), patch("browser.os.execv") as execv:
            with self.assertRaises(SystemExit):
                browser.main(["chrome"])
        execv.assert_not_called()

    def test_without_window_service_browser_starts_unchanged(self):
        with patch("browser.REQUEST", self.request), patch("browser.os.execv") as execv:
            self.assertIsNone(browser.main(["chromium", "--headless"]))
        execv.assert_called_once_with("/real/chrome", ["/real/chrome", "--headless"])
        self.assertEqual(os.environ["WAYLAND_DISPLAY"], "host")


if __name__ == "__main__":
    unittest.main()
