"""Guest supervisor of the macOS launcher's own Linux VM: a fixed set of actions over host-initiated SSH stdio.

The trusted host controller starts every mode of this program over its own SSH connection; the application
never receives this channel, its keys or the host's control token.

  ombp-guest                        control session: framed JSON on stdin/stdout
  ombp-guest receive-snapshot ID    extract one source snapshot (a tar stream on stdin) into the build area
  ombp-guest receive-omp-copy TOKEN stage a full private ~/.omp tar; only its owning control session can publish it
  ombp-guest await-forwards         report once the host's reverse-forwarded sockets exist, then hold until EOF
  ombp-guest provision-emulation    root-only fixed provisioning of the owned guest's pinned static interpreter

Frames are a 4-byte big-endian length and a UTF-8 JSON object of at most 1 MiB. Requests are
{id, action, args}; replies {id, ok: true, result} or {id, ok: false, error}; events {event, ...} are separate
frames. The host is the only permission authority: this process applies the host's projection of program and
requirement choices, reports denials, and cannot grant anything itself.
"""
import copy
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import queue
import re
import resource
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time

LAUNCHER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAUNCHER))

from catalog import host_program, installed_programs  # noqa: E402
from file_broker import ProtocolError, RemoteHostFiles, encode_frame, read_frame  # noqa: E402
from omp_copy import copy_status, install_snapshot  # noqa: E402
from packages import validate_packages  # noqa: E402
from policy import KEYBOARD_LAYOUTS, nix_program  # noqa: E402
from requirements import FOLDERS  # noqa: E402
from runtime import NIX, STORE, Cancelled, OwnedChildren, step  # noqa: E402

STATE = Path(os.environ.get("OMBP_GUEST_STATE") or Path.home() / ".local/state/ombp-guest")
SYSTEM = {"aarch64": "aarch64-linux", "arm64": "aarch64-linux", "x86_64": "x86_64-linux"}.get(platform.machine(), "")
_ELF_MACHINE = {"aarch64-linux": 183, "x86_64-linux": 62}
_MACH_O = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
_SNAPSHOT_ID = re.compile(r"[0-9a-f]{32}")
_REQUIREMENT_ID = re.compile(r"[a-z][a-z0-9-]{0,79}")
SNAPSHOT_LIMITS = {"entries": 500_000, "bytes": 8 << 30}
LOG_CHUNK = 16 << 10
LOCK_WAIT = 10


def installation_settings(value):
    """The host's captured installation choice, revalidated for this guest's Linux system."""
    if (not isinstance(value, dict) or set(value) != {"installed_mode", "selected_packages", "keyboard_layout"}
            or not isinstance(value["installed_mode"], bool) or value["keyboard_layout"] not in KEYBOARD_LAYOUTS):
        raise ValueError("Invalid installation settings")
    return {"installed_mode": value["installed_mode"], "selected_packages": validate_packages(value["selected_packages"]),
            "keyboard_layout": value["keyboard_layout"]}


def discovery_home(value):
    """The host user's home as mirrored under /host: a repository-discovery ceiling, never an access grant."""
    if (not isinstance(value, str) or len(value) > 4096 or "\x00" in value or not value.startswith("/host/")
            or str(PurePosixPath(value)) != value or ".." in PurePosixPath(value).parts):
        raise ValueError("Invalid repository discovery home")
    return value


def private_directory(path):
    """An owner-only real directory (never a symlink) at `path`, created if needed."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise RuntimeError(f"{path} must be a directory owned by the guest user")
    if metadata.st_mode & 0o077:
        os.chmod(path, 0o700)
    return path


class Layout:
    """Fixed guest paths; the host learns the forward targets from `status`, never chooses them."""

    def __init__(self, root=STATE):
        self.root = root
        self.state = root / "state"          # ContainerBackend's private state: home, rootfs, access, display
        self.network = root / "network"      # Mounted at /network: holds only the forwarded proxy.sock
        self.broker = root / "broker"        # Forwarded host file broker; never mounted
        self.trust = root / "trust"          # The host gateway's public CA certificate only
        self.snapshots = root / "snapshots"
        self.proxy_socket = self.network / "proxy.sock"
        self.broker_socket = self.broker / "broker.sock"
        self.ca = self.trust / "ca.pem"
        self.log = root / "launch.log"

    def create(self):
        for directory in (self.root, self.state, self.network, self.broker, self.trust, self.snapshots):
            private_directory(directory)
        return self


class Channel:
    """Framed messages on the inherited stdio pipes; one writer lock keeps frames whole."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.lock = threading.Lock()
        self.closed = False

    def recv_into(self, view):
        return self.reader.readinto(view)

    def read(self):
        return read_frame(self)

    def send(self, message):
        frame = encode_frame(message)
        with self.lock:
            if self.closed:
                return False
            try:
                self.writer.write(frame)
                self.writer.flush()
            except OSError:
                self.closed = True
                return False
        return True


class GuestPolicy:
    """The host's current projection of program and requirement choices; denials are only reported back."""

    def __init__(self, directory, emit):
        self.directory = directory
        self.private_paths = (str(STATE),)
        self.emit = emit
        self.lock = threading.RLock()
        self.data = {"programs": [], "disabled_requirements": [], "folders": []}
        self.generation = 0
        self.history_generation = 0

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.data)

    def save(self, name, value):
        temporary = self.directory / f".{name}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.directory / name)

    @staticmethod
    def validated(projection):
        if not isinstance(projection, dict) or set(projection) != {"programs", "disabled_requirements", "folders"}:
            raise ValueError("Invalid policy projection")
        programs, disabled, folders = (projection[key] for key in ("programs", "disabled_requirements", "folders"))
        if not all(isinstance(value, list) for value in (programs, disabled, folders)):
            raise ValueError("Invalid policy projection")
        if any(not isinstance(key, str) or not _REQUIREMENT_ID.fullmatch(key) for key in disabled):
            raise ValueError("Invalid disabled requirement")
        for item in folders:
            if (not isinstance(item, dict) or set(item) != {"path", "write"} or not isinstance(item["path"], str)
                    or not item["path"].startswith("/") or not isinstance(item["write"], bool)):
                raise ValueError("Invalid folder projection")
        return {"programs": sorted({nix_program(path) for path in programs}),
                "disabled_requirements": sorted(set(disabled)), "folders": folders}

    def apply(self, generation, projection):
        if type(generation) is not int or generation < 1:
            raise ValueError("Invalid policy generation")
        data = self.validated(projection)
        with self.lock:
            if generation < self.generation:
                raise ValueError(f"Stale policy generation {generation}; applied {self.generation}")
            self.data, self.generation = data, generation
        return generation

    def deny(self, kind, target, reason, site=None):
        self.emit({"event": "denial", "kind": kind, "target": str(target)[:2048], "reason": str(reason)[:300]})


def resolve_program(value):
    """A Linux Nix executable in this guest's store for a name or path; Darwin/native binaries are refused."""
    if not isinstance(value, str) or not value.strip() or "\x00" in value or len(value) > 4096:
        raise ValueError("Program must be an executable name or path")
    value = value.strip()
    if value.endswith(".app") or "/Applications/" in value or value.startswith(("/Users/", "/System/")):
        raise ValueError("macOS applications cannot run in the Linux runtime; choose a Linux Nix program")
    if "/" not in value:
        found = host_program((value,))
        if found is None:
            raise ValueError(f"Program is not installed in the Linux runtime: {value}")
        value = found
    path = Path(value).resolve(strict=True)
    if not str(path).startswith(STORE) or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("Programs must be installed Linux Nix executables (use their bin paths)")
    with path.open("rb") as stream:
        header = stream.read(20)
    if header[:4] in _MACH_O:
        raise ValueError("Darwin executables cannot run in the Linux runtime")
    if header[:4] == b"\x7fELF":
        machine = int.from_bytes(header[18:20], "little" if header[5] == 1 else "big")
        if machine != _ELF_MACHINE.get(SYSTEM):
            raise ValueError(f"Executable is not built for {SYSTEM}")
    elif header[:2] != b"#!":
        raise ValueError("Programs must be Linux executables or scripts")
    return nix_program(str(path))


def closure(executable, run=subprocess.run):
    from linux_runtime import closure as resolve
    return resolve(executable, run)


def requirements(policy):
    """The sandbox requirements last computed here, or the private folders before any build."""
    manifest = policy.directory / "requirements.json"
    items = json.loads(manifest.read_text()) if manifest.exists() else [
        {"id": key, "label": label, "path": path, "kind": "folder"} for key, label, path in FOLDERS]
    copy_row = next({"id": key, "label": label, "path": path, "kind": "folder"}
                    for key, label, path in FOLDERS if key == "omp-copy")
    items = [copy_row if item["id"] in ("host-omp", "omp-copy") else item for item in items]
    if not any(item["id"] == "omp-copy" for item in items):
        items.append(copy_row)
    disabled = set(policy.snapshot()["disabled_requirements"])
    return [{**item, "enabled": item["id"] == "omp-copy" or item["id"] not in disabled} for item in items]


# Source snapshots -------------------------------------------------------------------------------------------------

def _member_path(name):
    if name in (".", "./"):
        return PurePosixPath(".")
    stripped = name.rstrip("/")
    if (not stripped or name.startswith("/") or "\x00" in name or len(name) > 4096
            or any(part in ("", ".", "..") for part in stripped.split("/"))):
        raise ValueError(f"Unsafe archive path: {name!r}")
    return PurePosixPath(stripped)


def _link_inside(path, target):
    if not target or target.startswith("/") or "\x00" in target:
        return False
    depth = len(path.parts) - 1
    for part in PurePosixPath(target).parts:
        depth += -1 if part == ".." else 0 if part == "." else 1
        if depth < 0:
            return False
    return True


def _parent_fd(root_fd, parts):
    """Descend `parts` below root with no-follow opens: an earlier symlink entry can never redirect a write."""
    fd = os.dup(root_fd)
    try:
        for part in parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def extract_snapshot(stream, destination, limits=SNAPSHOT_LIMITS):
    """Extract a tar stream of regular files, directories and internal relative symlinks only."""
    destination.mkdir(mode=0o700)
    root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    entries = total = 0
    try:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                entries += 1
                if entries > limits["entries"]:
                    raise ValueError("Source snapshot has too many entries")
                path = _member_path(member.name)
                if str(path) == ".":
                    continue
                parent = _parent_fd(root_fd, path.parts[:-1])
                try:
                    name = path.parts[-1]
                    if member.isdir():
                        os.mkdir(name, 0o755, dir_fd=parent)
                    elif member.isreg():
                        total += member.size
                        if total > limits["bytes"]:
                            raise ValueError("Source snapshot is too large")
                        mode = 0o755 if member.mode & 0o111 else 0o644
                        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     mode, dir_fd=parent)
                        with os.fdopen(fd, "wb") as output:
                            source = archive.extractfile(member)
                            remaining = member.size
                            while remaining:
                                chunk = source.read(min(remaining, 1 << 20))
                                if not chunk:
                                    raise ValueError("Truncated source snapshot")
                                output.write(chunk)
                                remaining -= len(chunk)
                    elif member.issym():
                        if not _link_inside(path, member.linkname):
                            raise ValueError(f"Symlink escapes the source snapshot: {member.name}")
                        os.symlink(member.linkname, name, dir_fd=parent)
                    else:
                        raise ValueError(f"Unsupported entry in source snapshot: {member.name}")
                finally:
                    os.close(parent)
    finally:
        os.close(root_fd)
    # Validate complete link chains too: lexical containment alone misses a/../x when a itself is a link.
    for directory, directories, files in os.walk(destination, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            if path.is_symlink():
                try:
                    inside = path.resolve().is_relative_to(destination.resolve())
                except (OSError, RuntimeError):
                    inside = False
                if not inside:
                    raise ValueError(f"Symlink chain escapes the source snapshot: {path}")


def receive_snapshot(layout, snapshot_id, stream):
    if not _SNAPSHOT_ID.fullmatch(snapshot_id):
        raise ValueError("Invalid snapshot id")
    destination = layout.snapshots / snapshot_id
    partial = layout.snapshots / f".{snapshot_id}.partial"
    if destination.exists() or partial.exists():
        raise ValueError("Snapshot already exists")
    try:
        extract_snapshot(stream, partial)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    os.rename(partial, destination)
    # Only the newest snapshot is kept; older ones were already built (or abandoned).
    for old in layout.snapshots.iterdir():
        if old.name != snapshot_id:
            shutil.rmtree(old, ignore_errors=True)

def receive_omp_copy(layout, token, stream):
    """Stage bytes only. A receiver can never publish, even if its SSH session outlives the controller."""
    if not isinstance(token, str) or not _SNAPSHOT_ID.fullmatch(token):
        raise ValueError("Invalid private-copy token")
    directory = layout.root / f"omp-incoming-{token}"
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError("Unsafe private-copy staging directory")
        fd = os.open("partial", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=descriptor)
        with os.fdopen(fd, "wb") as output:
            shutil.copyfileobj(stream, output, 1 << 20)
        os.rename("partial", "received", src_dir_fd=descriptor, dst_dir_fd=descriptor)
    finally:
        os.close(descriptor)


class OmpCopy:
    def __init__(self, layout, replace, request_id):
        self.token = secrets.token_hex(16)
        self.directory = layout.root / f"omp-incoming-{self.token}"
        self.directory.mkdir(mode=0o700)
        self.replace = replace
        self.request_id = request_id
        self.cancelled = threading.Event()
        self.installing = False



# Control session --------------------------------------------------------------------------------------------------

class Run:
    def __init__(self, generation, args):
        self.generation = generation
        self.args = args
        self.children = OwnedChildren()
        self.stopping = threading.Event()
        self.thread = None
        self.backend = None
        self.process = None
        self.files = None


class Supervisor:
    """One control session. The reader stays responsive while at most one owned worker builds and runs OMBP."""

    def __init__(self, channel, layout):
        self.channel = channel
        self.layout = layout
        self.lock = threading.Lock()
        self.policy = GuestPolicy(layout.state, self.emit)
        self.run = None
        self.runs = 0
        self.phase = "idle"
        self.omp_copy = None
        self.keyring_backend = None  # Set by recovery before the control channel announces readiness.
        self.log_read, self.log_write = os.pipe()
        self.log = os.fdopen(self.log_write, "ab", buffering=0)
        self.management_children = OwnedChildren()
        self.log_thread = threading.Thread(target=self._forward_log, name="guest-log", daemon=True)
        self.log_thread.start()
        self.handlers = {"catalog": self.catalog, "resolve_program": self.resolve_program,
                         "resolve_closure": self.resolve_closure, "requirements": self.requirements,
                         "start": self.start, "stop": self.stop, "status": self.status, "policy": self.apply_policy,
                         "omp_copy_status": self.omp_copy_status, "omp_copy_begin": self.omp_copy_begin,
                         "omp_copy_commit": self.omp_copy_commit, "omp_copy_cancel": self.omp_copy_cancel}

    def emit(self, event):
        self.channel.send(event)

    def _forward_log(self):
        """Every guest build/container log byte goes to the guest log and, as bounded events, to the host log.

        The drain outlives a failing guest log (a full disk): builders block forever on this pipe otherwise.
        """
        with open(self.layout.log, "ab", buffering=0) as output:
            while True:
                data = os.read(self.log_read, LOG_CHUNK)
                if not data:
                    return
                try:
                    output.write(data)
                except OSError:
                    pass  # The host log below still receives every byte.
                self.emit({"event": "log", "text": data.decode("utf-8", "replace")})

    # Actions; each returns a JSON result or raises ValueError/RuntimeError/OSError with a user-facing message.

    def catalog(self, args):
        self._args(args, ())
        return {"system": SYSTEM,
                "programs": [{**item, "system": SYSTEM} for item in installed_programs()]}

    def resolve_program(self, args):
        self._args(args, ("value",))
        return {"path": resolve_program(args["value"]), "system": SYSTEM}

    def resolve_closure(self, args):
        self._args(args, ("executable",))
        return {"roots": closure(resolve_program(args["executable"]), self.management_children.run)}

    def requirements(self, args):
        self._args(args, ())
        return {"requirements": requirements(self.policy)}

    def status(self, args):
        self._args(args, ())
        with self.lock:
            run = self.run
            return {"phase": self.phase, "run": run.generation if run else None, "system": SYSTEM,
                    "applied_policy_generation": self.policy.generation,
                    "forwards": {"proxy": str(self.layout.proxy_socket), "broker": str(self.layout.broker_socket)}}

    def omp_copy_status(self, args):
        self._args(args, ())
        return copy_status(self.layout.state)

    def omp_copy_begin(self, args):
        self._args(args, ("replace", "request_id", "keyring_unlock"))
        if type(args["replace"]) is not bool:
            raise ValueError("Invalid private-copy authorization")
        request_id = args["request_id"]
        if args["replace"]:
            if not isinstance(request_id, str) or not _SNAPSHOT_ID.fullmatch(request_id):
                raise ValueError("Invalid private-copy request ID")
        elif request_id is not None:
            raise ValueError("A private-copy request ID requires replacement authorization")
        with self.lock:
            if self.run is not None or self.phase != "idle":
                raise ValueError("A private copy requires an idle guest")
            # Initialize the host-delivered unlock verifier before a first copy makes the guest home nonempty.
            # Existing homes still require their original verifier/key.
            self.keyring_backend._keyring_password(args["keyring_unlock"])
            transfer = OmpCopy(self.layout, args["replace"], request_id)
            self.omp_copy = transfer
            self.phase = "copying"
            return {"token": transfer.token}

    def _copy_check(self, transfer):
        if transfer.cancelled.is_set() or self.omp_copy is not transfer:
            raise Cancelled("Private copy cancelled")

    def _copy_cleanup(self, transfer):
        shutil.rmtree(transfer.directory, ignore_errors=True)
        with self.lock:
            if self.omp_copy is transfer:
                self.omp_copy = None
                self.phase = "idle"

    def omp_copy_cancel(self, args):
        self._args(args, ("token",))
        with self.lock:
            transfer = self.omp_copy
            if transfer is None or transfer.token != args["token"]:
                return {"cancelled": False}
            transfer.cancelled.set()
            installing = transfer.installing
        if not installing:
            self._copy_cleanup(transfer)
        return {"cancelled": True}

    def omp_copy_commit(self, args):
        self._args(args, ("token", "digest"))
        if not isinstance(args["digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", args["digest"]):
            raise ValueError("Invalid private-copy digest")
        with self.lock:
            transfer = self.omp_copy
            if (transfer is None or transfer.token != args["token"] or transfer.installing
                    or self.run is not None or self.phase != "copying"):
                raise ValueError("Private-copy session is no longer owned")
            self._copy_check(transfer)
            transfer.installing = True
        try:
            fd = os.open(transfer.directory / "received", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("Invalid private-copy archive")
                digest = hashlib.sha256()
                while chunk := stream.read(1 << 20):
                    self._copy_check(transfer)
                    digest.update(chunk)
                if digest.hexdigest() != args["digest"]:
                    raise ValueError("Private-copy transport was incomplete")
                stream.seek(0)
                return install_snapshot(stream, self.layout.state, replace=transfer.replace,
                                        request_id=transfer.request_id, check=lambda: self._copy_check(transfer))
        finally:
            self._copy_cleanup(transfer)

    def apply_policy(self, args):
        self._args(args, ("generation", "projection"))
        return {"applied": self.policy.apply(args["generation"], args["projection"])}

    def start(self, args):
        self._args(args, ("source_snapshot_id", "desktop", "gpu", "agent", "keyring_unlock", "proxy_ca", "workspace",
                          "installation", "git_discovery_home"))
        if not isinstance(args["source_snapshot_id"], str) or not _SNAPSHOT_ID.fullmatch(args["source_snapshot_id"]):
            raise ValueError("Invalid source snapshot")
        if not (self.layout.snapshots / args["source_snapshot_id"]).is_dir():
            raise ValueError("Source snapshot was not received")
        if (not isinstance(args["desktop"], bool) or args["gpu"] != "none" or args["agent"] not in ("omp", "omsp")
                or not isinstance(args["keyring_unlock"], str) or not isinstance(args["proxy_ca"], str)):
            raise ValueError("Invalid launch settings")
        workspace = args["workspace"]
        if workspace is not None and (not isinstance(workspace, dict)
                                      or set(workspace) != {"host_workspace", "container_workspace"}
                                      or not all(isinstance(value, str) and value.startswith("/")
                                                 for value in workspace.values())):
            raise ValueError("Invalid workspace mapping")
        args = {**args, "installation": installation_settings(args["installation"]),
                "git_discovery_home": discovery_home(args["git_discovery_home"])}
        with self.lock:
            if self.run is not None or self.phase != "idle":
                raise ValueError(f"A launch is already {self.phase}")
            self.runs += 1
            run = self.run = Run(self.runs, args)
            self.phase = "building"
            run.thread = threading.Thread(target=self._work, args=(run,), name="guest-launch", daemon=True)
            run.thread.start()
        return {"run": run.generation}

    def stop(self, args):
        self._args(args, ())
        self.cancel()
        return {"stopping": True}

    @staticmethod
    def _args(args, required):
        if not isinstance(args, dict) or set(args) != set(required):
            raise ValueError("Invalid action arguments")

    # Worker.

    def _phase(self, run, phase):
        with self.lock:
            if run.stopping.is_set():
                raise Cancelled("Launch cancelled")
            self.phase = phase
        self.emit({"event": "phase", "run": run.generation, "phase": phase})

    def _build(self, run):
        source = self.layout.snapshots / run.args["source_snapshot_id"]
        attribute = "default" if run.args["agent"] == "omp" else "omsp"
        step(self.log, f"Building OMBP ({run.args['agent']})")
        build = run.children.popen(
            [*NIX, "build", f"path:.#{attribute}", "--no-link", "--print-out-paths", "--print-build-logs",
             "--no-write-lock-file"],
            cwd=source, stdout=subprocess.PIPE, stderr=self.log, text=True, start_new_session=True)
        output, _ = build.communicate()
        # A build that finishes after Stop never launches, even when it succeeded.
        run.children.check()
        if build.returncode:
            raise RuntimeError("OMBP build failed in the Linux runtime; see launch.log")
        outputs = output.splitlines()
        if len(outputs) != 1 or not outputs[0].startswith(STORE):
            raise RuntimeError("OMBP build did not return one Nix store output")
        executable = Path(outputs[0]) / "bin/omp-manager"
        executable = executable.resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("OMBP build has no executable bin/omp-manager")
        return str(executable), source

    def _write_ca(self, pem):
        if (len(pem) > 16384 or not pem.startswith("-----BEGIN CERTIFICATE-----")
                or "PRIVATE KEY" in pem or not pem.rstrip().endswith("-----END CERTIFICATE-----")):
            raise ValueError("The host must send only its public gateway CA certificate")
        temporary = self.layout.trust / ".ca.pem.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as output:
            output.write(pem)
        os.replace(temporary, self.layout.ca)

    def _work(self, run):
        error = ""
        code = 0
        try:
            executable, source = self._build(run)
            self._phase(run, "starting")
            self._write_ca(run.args["proxy_ca"])
            from linux_runtime import ContainerBackend, ProxyEndpoint
            from vm_display import HeadlessDisplays
            run.files = RemoteHostFiles.connect(self.layout.broker_socket)
            displays = HeadlessDisplays(root=self.layout.state / "display",
                                        emit=lambda event: self.emit({**event, "run": run.generation}),
                                        keyboard=run.args["installation"]["keyboard_layout"])
            # Constructing retires any leftover container (slow); never under the status lock.
            step(self.log, "Preparing container runtime")
            run.backend = ContainerBackend(self.policy, host_files=run.files, external_network=True,
                                           displays=displays)
            run.children.check()
            run.process = run.backend.start(
                executable, run.args["desktop"], run.args["gpu"], source, run.args["agent"], self.log, run.children,
                installation=run.args["installation"], git_discovery_home=run.args["git_discovery_home"],
                proxy=ProxyEndpoint(self.layout.proxy_socket, self.layout.ca),
                keyring_password=run.args["keyring_unlock"], workspace=run.args["workspace"])
            self.emit({"event": "requirements", "run": run.generation, "requirements": requirements(self.policy)})
            self._phase(run, "running")
            while not run.stopping.is_set():
                try:
                    code = run.process.wait(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if not run.stopping.is_set():
                error = run.backend.exit_error(code)
        except Cancelled:
            pass
        except Exception as failure:  # Every failure must reach the host, not die with this thread.
            if not run.stopping.is_set():
                error = str(failure) or type(failure).__name__
        finally:
            with self.lock:
                self.phase = "stopping"
            cleanup_failed = False
            try:
                if run.backend is not None:
                    run.backend.stop()
            except Exception as failure:
                cleanup_failed = True
                error = error or f"Stop failed: {failure}"
            if run.files is not None:
                run.files.close_all()
            run.children.retire()
            with self.lock:
                self.run = None
                self.phase = "retirement-failed" if cleanup_failed else "idle"
            self.emit({"event": "exited", "run": run.generation, "code": code, "error": error})

    def cancel(self):
        with self.lock:
            transfer = self.omp_copy
        if transfer is not None:
            self.omp_copy_cancel({"token": transfer.token})
        with self.lock:
            run = self.run
            if run is None:
                return None
            run.stopping.set()
            self.phase = "stopping"
        run.children.cancel()
        return run

    def _dispatch(self, message):
        request_id = message.get("id")
        if type(request_id) is not int or set(message) != {"id", "action", "args"}:
            raise ProtocolError("Invalid request envelope")
        handler = self.handlers.get(message["action"])
        try:
            if handler is None:
                raise ValueError("Unknown action")
            reply = {"id": request_id, "ok": True, "result": handler(message["args"])}
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as failure:
            reply = {"id": request_id, "ok": False, "error": str(failure)[:2000] or type(failure).__name__}
        self.channel.send(reply)

    def serve(self):
        """Read requests until EOF; slow actions run off the reader so Stop, policy and EOF stay prompt."""
        slow = queue.Queue(64)
        worker = threading.Thread(target=self._slow_actions, args=(slow,), name="guest-actions", daemon=True)
        worker.start()
        try:
            while True:
                message = self.channel.read()
                if message is None:
                    break
                if message.get("action") in ("catalog", "resolve_program", "resolve_closure", "omp_copy_commit"):
                    try:
                        slow.put_nowait(message)
                    except queue.Full:
                        self.channel.send({"id": message.get("id"), "ok": False, "error": "Too many pending actions"})
                else:
                    self._dispatch(message)
        except (ProtocolError, OSError):
            pass
        finally:
            # EOF or a broken host connection: retire every owned process before joining workers.
            self.management_children.cancel()
            run = self.cancel()
            while True:
                try:
                    slow.get_nowait()
                except queue.Empty:
                    break
            slow.put(None)
            worker.join()
            self.management_children.retire()
            if run is not None:
                run.thread.join()
            self.log.close()
            self.log_thread.join()
            os.close(self.log_read)

    def _slow_actions(self, slow):
        while (message := slow.get()) is not None:
            try:
                self._dispatch(message)
            except ProtocolError:
                self.channel.send({"id": -1, "ok": False, "error": "Invalid request envelope"})


def _lock(layout):
    """One supervisor per guest; a replacement waits (bounded) for the previous one to finish retiring."""
    fd = os.open(layout.root / "supervisor.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    deadline = time.monotonic() + LOCK_WAIT
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(fd)
                raise RuntimeError("Another guest supervisor is still retiring its workload")
            time.sleep(0.1)


def retire_engine_sockets(directory):
    """After acquiring the supervisor lock, retire only unreachable, owned engine socket inodes.

    A VM power loss leaves Unix socket nodes without listeners. Live listeners, foreign files, symlinks
    or unsafe directories are errors, not permission to replace another service.
    """
    for relative in ("engine/upstream/podman.sock", "engine/api/podman.sock", "engine/api/sonar.sock"):
        path = directory / relative
        missing = False
        for parent in (directory / "engine", path.parent):
            try:
                info = parent.lstat()
            except FileNotFoundError:
                missing = True
                break
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077):
                raise RuntimeError(f"Unsafe owned engine socket directory: {parent}")
        if missing:
            continue
        try:
            before = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid():
            raise RuntimeError(f"Refusing to replace an unexpected engine socket object: {path}")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            try:
                probe.connect(str(path))
            except OSError as error:
                if error.errno not in (errno.ECONNREFUSED, errno.ENOENT):
                    raise
            else:
                raise RuntimeError("A previous engine service is still live; close the launcher to stop its owned VM")
        try:
            after = path.lstat()
        except FileNotFoundError:
            continue
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("An engine socket changed while retiring it")
        path.unlink()


def _retire_leftovers(policy):
    """Whatever an earlier, uncleanly ended supervisor left behind: its recorded container and FUSE mount."""
    from linux_runtime import ContainerBackend
    backend = ContainerBackend(policy, external_network=True)
    backend.stop()
    retire_engine_sockets(policy.directory)
    return backend


def prepare_descriptor_limit():
    """FUSE retains descriptors for mapped libraries across every app/browser process in this guest."""
    required = 65536
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < required:
        raise RuntimeError("The Linux guest supervisor needs a NOFILE hard limit of at least 65536; "
                           "raise the guest user's limit before preparing this runtime")
    if soft != resource.RLIM_INFINITY and soft < required:
        resource.setrlimit(resource.RLIMIT_NOFILE, (required, hard))


def serve_control():
    prepare_descriptor_limit()
    layout = Layout().create()
    # Frames own the real stdout; anything a library prints goes to stderr (the host's launch log).
    writer = os.fdopen(os.dup(1), "wb", buffering=0)
    reader = os.fdopen(os.dup(0), "rb", buffering=0)
    os.dup2(2, 1)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    channel = Channel(reader, writer)
    lock = _lock(layout)
    try:
        supervisor = Supervisor(channel, layout)
        supervisor.keyring_backend = _retire_leftovers(supervisor.policy)
        channel.send({"event": "hello", "system": SYSTEM, "pid": os.getpid()})
        supervisor.serve()
    finally:
        os.close(lock)


def await_forwards():
    """Run as the command of the host's forwarding connection: ready once both sockets exist, then hold."""
    layout = Layout().create()
    deadline = time.monotonic() + 10
    for path in (layout.proxy_socket, layout.broker_socket):
        while True:
            try:
                if stat.S_ISSOCK(os.lstat(path).st_mode):
                    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        probe.connect(str(path))
                    finally:
                        probe.close()
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                print(f"missing {path.name}", flush=True)
                return 1
            time.sleep(0.05)
    print("ready", flush=True)
    while sys.stdin.buffer.read(4096):
        continue
    return 0


def main(argv):
    # A broken output pipe must raise, not kill us before the EOF/worker cleanup runs.
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    def interrupted(_number, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    if not SYSTEM:
        print(f"Unsupported guest architecture {platform.machine()}", file=sys.stderr)
        return 2
    if argv == ["provision-emulation"]:
        from vm.emulation import provision
        provision()
        return 0
    if argv == []:
        serve_control()
        return 0
    if len(argv) == 2 and argv[0] == "receive-snapshot":
        layout = Layout().create()
        try:
            receive_snapshot(layout, argv[1], sys.stdin.buffer)
        except (ValueError, OSError, tarfile.TarError) as failure:
            print(f"Source snapshot rejected: {failure}", file=sys.stderr)
            return 1
        print("ok", flush=True)
        return 0
    if len(argv) == 2 and argv[0] == "receive-omp-copy":
        try:
            receive_omp_copy(Layout(), argv[1], sys.stdin.buffer)
        except (ValueError, OSError):
            print("Private ~/.omp transport rejected", file=sys.stderr)
            return 1
        print("ok", flush=True)
        return 0
    if argv == ["await-forwards"]:
        return await_forwards()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
