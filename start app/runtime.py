"""Portable launch lifecycle: one owned operation from validation to a live OMBP, then its teardown.

Linux execution (container, FUSE, nested desktop) lives in linux_runtime.py and is imported only on Linux.
"""
from datetime import datetime
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid

from omp_copy import read_copy_request

STORE = "/nix/store/"
# Shipped Nix invocations must work on a fresh Nix without changing the user's global configuration.
NIX = ("nix", "--extra-experimental-features", "nix-command flakes")
STARTING = ("preparing", "building", "starting")


def step(log, text):
    """Mark the start of one slow launch step in launch.log; the control UI shows the latest `==> ` line."""
    log.write(f"==> {text}\n".encode())


class Cancelled(RuntimeError):
    """The launch was stopped or the launcher is closing; nothing more may start for it."""


def terminate(process, timeout):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


def _signal(process, group, number):
    try:
        if group:
            if process.poll() is None:
                os.killpg(process.pid, number)
        else:
            process.send_signal(number)
    except (ProcessLookupError, PermissionError):
        pass


class OwnedChildren:
    """Every child process of one launch, so cancellation reaches each without any lifecycle lock.

    After cancel() no further child can be spawned: this is what keeps a stopped launch from starting late.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._processes = []
        self._reaper = None
        self.cancelled = False

    def check(self):
        if self.cancelled:
            raise Cancelled("Launch cancelled")

    def popen(self, args, **kwargs):
        with self._lock:
            self.check()
            process = subprocess.Popen(args, **kwargs)
            self._processes.append((process, bool(kwargs.get("start_new_session"))))
        return process

    def adopt(self, process, *, group=False):
        """Temporarily include an existing owned child in this operation's cancellation boundary."""
        with self._lock:
            self.check()
            self._processes.append((process, group))

    def release(self, process):
        """Transfer a live child to its longer-lived backend only while this operation is still admitted."""
        with self._lock:
            self.check()
            self._processes = [item for item in self._processes if item[0] is not process]

    def run(self, args, *, timeout, check=False, capture_output=False, input=None, **kwargs):
        """subprocess.run for an owned child; cancel() ends it instead of waiting out its timeout."""
        if capture_output:
            kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if input is not None:
            kwargs["stdin"] = subprocess.PIPE
        process = self.popen(args, **kwargs)
        try:
            stdout, stderr = process.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        finally:
            with self._lock:
                self._processes = [item for item in self._processes if item[0] is not process]
        self.check()
        if check and process.returncode:
            raise subprocess.CalledProcessError(process.returncode, args, stdout, stderr)
        return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)

    def run_lines(self, args, *, timeout, on_line, input=None, **kwargs):
        """run() whose stdout reaches `on_line` line by line as it is produced; returns the exit code."""
        kwargs["stdout"] = subprocess.PIPE
        if input is not None:
            kwargs["stdin"] = subprocess.PIPE
        process = self.popen(args, **kwargs)
        expired = False

        def expire():
            nonlocal expired
            expired = True
            process.kill()

        def feed():
            try:
                process.stdin.write(input)
            except (BrokenPipeError, OSError, ValueError):
                pass  # The child exited early; its exit code reports why.
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        timer = threading.Timer(timeout, expire)
        timer.daemon = True
        timer.start()
        feeder = threading.Thread(target=feed, daemon=True) if input is not None else None
        try:
            if feeder:
                feeder.start()
            for line in process.stdout:
                on_line(line)
            process.wait()
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            if feeder:
                feeder.join()
            with self._lock:
                self._processes = [item for item in self._processes if item[0] is not process]
        if expired:
            raise subprocess.TimeoutExpired(args, timeout)
        self.check()
        return process.returncode

    def cancel(self, grace=10):
        """Refuse new children, ask every owned one to exit and kill any still alive after `grace` seconds."""
        with self._lock:
            if self.cancelled:
                return
            self.cancelled = True
            owned = list(self._processes)
            for process, group in owned:
                _signal(process, group, signal.SIGTERM)
            self._reaper = threading.Thread(target=self._escalate, args=(owned, grace), daemon=True)
            self._reaper.start()

    @staticmethod
    def _escalate(owned, grace):
        deadline = time.monotonic() + grace
        for process, group in owned:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                _signal(process, group, signal.SIGKILL)
                process.wait()

    def retire(self):
        self.cancel()
        self._reaper.join()


class Operation:
    def __init__(self, generation, settings, kind="launch", installation=None):
        self.id = uuid.uuid4().hex
        self.generation = generation
        self.settings = settings
        # Launches only: {installed_mode, selected_packages} captured at admission; later policy edits never change it.
        self.installation = installation
        self.kind = kind
        self.children = OwnedChildren()
        self.stopping = threading.Event()
        self.process = None
        self.thread = None
        # Where this operation's output begins in launch.log, and when it was admitted (epoch seconds).
        self.log_start = 0
        self.started = None


class Runtime:
    """Admits one launch at a time; a single owned worker prepares, builds, starts, watches and retires it.

    `lock` guards only status fields and is never held while building, starting or waiting.
    """

    def __init__(self, policy, host=sys.platform):
        self.policy = policy
        self.host = host
        self.lock = threading.Lock()
        self.generation = 0
        self.operation = None
        # The latest admitted operation, kept after it ends so a failed launch's log stays viewable.
        self.last_operation = None
        self.log_path = policy.directory / "launch.log"
        self.phase = "stopped"
        self.process = None
        self.mode = None
        self.launch = None
        self.last_error = ""
        self.closing = False
        self._catalog = None
        if host.startswith("linux"):
            from linux_runtime import ContainerBackend
            self.isolated = ContainerBackend(policy)
            self.backend = self.isolated.name
        elif host == "darwin":
            # macOS isolation runs the Linux backend inside the launcher's own VM; programs resolve there.
            from macos_runtime import VmBackend
            self.isolated = VmBackend(policy)
            policy.program_resolver = self.isolated.resolve_program
            self.backend = self.isolated.name
        else:
            self.isolated = None
            self.backend = "native"

    def status(self):
        extra = self.isolated.status_fields() if self.host == "darwin" else {
            "desktops": [], "catalog_generation": 1, "policy_generation": 0, "applied_policy_generation": 0}
        with self.lock:
            operation, last = self.operation, self.last_operation
            return {"running": self.phase == "running" and self.process is not None and self.process.poll() is None,
                    "starting": self.phase in STARTING, "phase": self.phase, "backend": self.backend,
                    "operation_id": operation.id if operation else None, "mode": self.mode,
                    "operation": operation.kind if operation else None,
                    "log_start": last.log_start if last else None,
                    "operation_started": last.started if last else None,
                    "launch": dict(self.launch) if self.launch else None,
                    "container": self.isolated.container if self.isolated else None,
                    "omp_copy_pending": (self.policy.directory / "omp-recopy.json").exists(),
                    "error": self.last_error, **extra}

    def log_origin(self):
        """Where the current (or last) operation's output begins in launch.log; None before any operation."""
        with self.lock:
            return self.last_operation.log_start if self.last_operation else None

    def catalog(self):
        """The current program/folder catalog of the backend that runs isolated programs."""
        if self.host == "darwin":
            return self.isolated.catalog()
        with self.lock:
            cached = self._catalog
        if cached is None:
            from catalog import catalog
            machine = {"arm64": "aarch64"}.get(os.uname().machine, os.uname().machine)
            system = f"{machine}-{'linux' if self.host.startswith('linux') else self.host}"
            found = catalog()
            cached = {**found, "programs": [{**item, "system": system} for item in found["programs"]],
                      "program_domain": "host", "runtime_system": system, "program_catalog_ready": True,
                      "generation": 1}
            with self.lock:
                self._catalog = cached
        return cached

    def requirements_status(self):
        if not self.isolated:
            return []
        with self.lock:
            operation = self.operation
        # While an isolated launch is admitted its captured mode decides; otherwise the desired policy does.
        active = (operation.installation if operation is not None and operation.installation is not None
                  and operation.settings["mode"] != "normal" else None)
        return self.isolated.requirements_status(active)

    def copy_omp_again(self, confirmation):
        """Authorize one replacement at the next isolated Start, never during a live operation."""
        if confirmation is not True:
            raise ValueError("Confirm replacement of the private OMP copy and its previous backup")
        with self.lock:
            if self.closing or self.operation is not None:
                raise ValueError("Stop OMBP and wait for it to finish before requesting Copy again")
            if self.isolated is None:
                raise ValueError("Private OMP copies require an isolated backend")
            if read_copy_request(self.policy.directory) is None:
                self.policy.save("omp-recopy.json", {"replace_previous": True, "request_id": uuid.uuid4().hex})
                # Persist the directory entry before any backend can apply this authorization.
                descriptor = os.open(self.policy.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)

    @staticmethod
    def _launch_source(source, mode, desktop, gpu, agent):
        """The resolved OMBP checkout, once every launch setting is valid."""
        if (mode not in ("normal", "container") or gpu not in ("none", "amd", "nvidia")
                or not isinstance(desktop, bool) or agent not in ("omp", "omsp")):
            raise ValueError("Invalid launch settings")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("Choose the OMBP source folder containing flake.nix")
        source = Path(source).expanduser().resolve(strict=True)
        if not source.is_dir() or not (source / "flake.nix").is_file():
            raise ValueError("Choose the OMBP source folder containing flake.nix")
        return source

    def _backend(self, mode):
        if mode == "normal":
            return "native"
        if self.isolated is None:
            raise ValueError("Isolated mode is not supported on this host")
        return self.isolated.name

    def start(self, source, mode, desktop, gpu, agent):
        """Validate now, admit one launch and return its operation ID; the worker does everything slow."""
        source = self._launch_source(source, mode, desktop, gpu, agent)
        backend = self._backend(mode)
        if backend == "linux-vm" and gpu != "none":
            raise ValueError("GPU passthrough is not available in the macOS Linux VM; choose Software rendering")
        settings = {"source": str(source), "mode": mode, "desktop": desktop, "gpu": gpu, "agent": agent}
        # Captured now: tool choices saved while this launch prepares or runs apply only to the next Start.
        installation = (self.policy.installation() if mode != "normal"
                        else {"installed_mode": False, "selected_packages": [], "keyboard_layout": "default"})
        return self._admit(Operation(0, settings, installation=installation), backend, mode)

    def prepare(self):
        """Prepare the macOS Linux runtime and its program catalog without starting OMBP."""
        if self.host != "darwin":
            raise ValueError("Only the macOS launcher has a Linux runtime to prepare")
        return self._admit(Operation(0, {"mode": "container"}, kind="prepare"), self.isolated.name, "container")

    def _admit(self, operation, backend, mode):
        try:
            log_start = os.path.getsize(self.log_path)
        except FileNotFoundError:
            log_start = 0
        with self.lock:
            if self.closing:
                raise RuntimeError("Launcher is closing")
            if self.operation is not None:
                raise ValueError("Already running" if self.phase == "running" else f"OMBP is {self.phase}")
            self.generation += 1
            operation.generation = self.generation
            self.operation = operation
            operation.log_start, operation.started = log_start, time.time()
            self.last_operation = operation
            self.phase, self.backend, self.mode, self.last_error = "preparing", backend, mode, ""
            self.launch = self._launch_record(operation, None) if operation.installation is not None else None
            operation.thread = threading.Thread(target=self._run, args=(operation,),
                                                name=f"ombp-{operation.kind}-{operation.id[:8]}", daemon=True)
            operation.thread.start()
        return operation.id

    @staticmethod
    def _launch_record(operation, executable):
        """What status reports for an admitted launch, including the installation it was admitted with."""
        settings, installation = operation.settings, operation.installation
        return {"source": settings["source"], "executable": executable, "desktop": settings["desktop"],
                "gpu": settings["gpu"], "agent": settings["agent"], "installed_mode": installation["installed_mode"],
                "selected_packages": list(installation["selected_packages"])}

    def _advance(self, operation, phase, launch=None, process=None):
        with self.lock:
            if operation.generation != self.generation or operation.stopping.is_set():
                raise Cancelled("Launch cancelled")
            self.phase = phase
            if launch is not None:
                self.launch = launch
            if process is not None:
                self.process = process

    @staticmethod
    def _mark(log, text):
        """A best-effort final step marker: a full disk must not keep the operation admitted."""
        try:
            step(log, text)
        except OSError:
            pass

    def _run(self, operation):
        error = ""
        log = None
        try:
            log = open(self.log_path, "ab", buffering=0)
            step(log, f"{operation.kind.capitalize()} started "
                      f"{datetime.fromtimestamp(operation.started).astimezone().isoformat(timespec='seconds')} "
                      f"(operation {operation.id})")
            if operation.kind == "prepare":
                self.isolated.prepare(operation.children, log)
            else:
                process = self._launch(operation, log)
                error = self._await_exit(operation, process)
        except Cancelled:
            pass
        except Exception as failure:  # Every failure must reach the UI, not die with this thread.
            if not operation.stopping.is_set():
                error = str(failure) or type(failure).__name__
                if log:
                    log.write(traceback.format_exc().encode())
        finally:
            with self.lock:
                self.phase = "stopping"
            launch = operation.kind != "prepare"
            if log and launch:
                self._mark(log, "Stopping")
            try:
                self._teardown(operation)
            except Exception as failure:
                error = error or f"Stop failed: {failure}"
            operation.children.retire()
            if log:
                self._mark(log, f"{operation.kind.capitalize()} failed: {error}" if error
                           else "Stopped" if launch else "Linux runtime prepared")
                log.close()
            with self.lock:
                self.operation = None
                self.process = None
                self.launch = None
                self.phase = "failed" if error else "stopped"
                if error:
                    self.last_error = error

    def _launch(self, operation, log):
        settings = operation.settings
        source, agent = settings["source"], settings["agent"]
        if settings["mode"] != "normal" and self.host == "darwin":
            return self._launch_vm(operation, log)
        self._advance(operation, "building")
        step(log, f"Building OMBP ({agent})")
        build = operation.children.popen(
            [*NIX, "build", f"path:.#{'default' if agent == 'omp' else 'omsp'}", "--no-link",
             "--print-out-paths", "--print-build-logs", "--no-write-lock-file"],
            cwd=source, stdout=subprocess.PIPE, stderr=log, text=True)
        output, _ = build.communicate()
        # A build that finishes after Stop never launches, even when it succeeded.
        operation.children.check()
        if build.returncode:
            raise RuntimeError(f"OMBP build failed; see {self.policy.directory / 'launch.log'}")
        outputs = output.splitlines()
        if len(outputs) != 1 or not outputs[0].startswith(STORE):
            raise RuntimeError("OMBP build did not return one Nix store output")
        executable = str((Path(outputs[0]) / "bin/omp-manager").resolve(strict=True))
        if not Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise ValueError("OMBP build has no executable bin/omp-manager")
        self._advance(operation, "starting", launch=self._launch_record(operation, executable))
        if settings["mode"] == "normal":
            step(log, "Starting OMBP")
            process = operation.process = operation.children.popen(
                [executable], stdout=log, stderr=log, env={**os.environ, "OMBP_AGENT": agent},
                start_new_session=True)
        else:
            process = operation.process = self.isolated.start(
                executable, settings["desktop"], settings["gpu"], Path(source), agent, log, operation.children,
                installation=operation.installation, git_discovery_home="/host" + str(Path.home().resolve()))
        return self._running(operation, process)

    def _launch_vm(self, operation, log):
        """macOS isolated mode: the VM backend snapshots, builds and starts OMBP inside the Linux guest."""
        settings = operation.settings
        self._advance(operation, "preparing", launch=self._launch_record(operation, None))
        process = operation.process = self.isolated.launch(
            settings, log, operation.children, lambda phase: self._advance(operation, phase),
            installation=operation.installation)
        return self._running(operation, process)

    def _running(self, operation, process):
        self._advance(operation, "running", process=process)
        try:
            self.policy.record_launch(operation.settings)
        except (OSError, ValueError) as failure:
            with self.lock:
                self.last_error = f"OMBP is running, but its launch settings were not saved: {failure}"
        return process

    def _await_exit(self, operation, process):
        """Wait until the application exits or Stop is requested; return the error to report, if any."""
        while not operation.stopping.is_set():
            try:
                code = process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                continue
            if operation.stopping.is_set() or not code:
                return ""
            if operation.settings["mode"] == "normal":
                return f"Process exited {code}; see {self.policy.directory / 'launch.log'}"
            return self.isolated.exit_error(code)
        return ""

    def _teardown(self, operation):
        if (self.host == "darwin" and operation.settings["mode"] != "normal"
                and operation.stopping.is_set() and self.isolated.run is None):
            self.isolated.cancel_preparation()
            return
        if operation.kind == "prepare":
            return  # A prepared VM stays up for catalog and program resolution until the launcher closes.
        if operation.settings["mode"] != "normal":
            self.isolated.stop()
            return
        process = operation.process
        if process is not None:
            # OMBP's whole session: background children are retired with it.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            terminate(process, 10)

    def fail(self, message):
        """Report a launch failure that happened before any operation was admitted."""
        with self.lock:
            self.last_error = message
            if self.operation is None:
                self.phase = "failed"

    def stop(self):
        """Cancel a pending launch or stop a running one; the operation's worker retires it."""
        with self.lock:
            operation = self.operation
            if operation is None:
                return
            self.generation += 1
            operation.stopping.set()
            self.phase = "stopping"
        operation.children.cancel()

    def close(self):
        """Refuse new launches, retire the current one and wait for its worker; on macOS stop the owned VM."""
        with self.lock:
            self.closing = True
            operation = self.operation
        self.stop()
        if operation is not None:
            operation.thread.join()
        if self.host == "darwin":
            self.isolated.close()
