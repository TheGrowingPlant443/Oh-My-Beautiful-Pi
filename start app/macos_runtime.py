"""macOS isolation: the launcher's own Linux VM (Lima, Virtualization.framework) running the Linux runtime.

The host stays the only permission authority. It keeps the policy, the website gateway (mac_network), the
host-file broker (file_broker over HostFiles) and the desktop viewer; the VM runs the unchanged rootless
container backend through vm/guest.py. No host directory is mounted into the VM: host files reach it only
through the broker's reverse-forwarded Unix socket, network only through the gateway's.

One VM belongs to one launcher state directory: LIMA_HOME is ~/.local/share/ombp-lima/<state id>, its
instance is `runtime`, and an ownership receipt (in LIMA_HOME and in the state directory) must match before
anything is adopted, started or stopped. The VM is never deleted as cleanup.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import queue
import secrets
import shlex
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time

from catalog import user_folders
from file_broker import FileBrokerServer, ProtocolError, encode_frame, read_frame
from host_files import HostFiles
from packages import LANGUAGE_SERVER_COMMANDS, PACKAGE_CHOICES
from policy import read_private_json
from requirements import CONTAINER_WORKSPACE, FOLDERS, HOST_WORKSPACE, prepare_workspace, requirement_enabled
from runtime import Cancelled, OwnedChildren, step, terminate

INSTANCE = "runtime"
RESOURCES = "vm.json"
STATE_RECEIPT = "vm-owner.json"
HOME_RECEIPT = ".ombp-owner.json"
# Lima's longest instance-directory socket name (ssh appends 16 random characters to ssh.sock).
LONGEST_LIMA_SOCKET = "ssh.sock.1234567890123456"
SOCKET_LIMIT = 104
OVERRIDES = ("default.yaml", "override.yaml", "base.yaml")
LAUNCHER = Path(__file__).resolve().parent
LAUNCHER_EXCLUDED = {".quality-coverage", ".coverage", "__pycache__", "result"}
# The root flake's source filter: these never enter a snapshot, nor do VCS metadata and editor/object files.
SOURCE_EXCLUDED = {"target", "node_modules", "dist", ".worktrees", "worktrees", "result", "__pycache__"}
VCS_DIRECTORIES = {".git", ".svn", "CVS", ".hg", ".jj", ".pijul"}
SNAPSHOT_BYTES = 8 << 30
GUEST_NIX = "/nix/var/nix/profiles/default/bin/nix"
ACK_DEADLINE = 5
RETIRE_DEADLINE = 10
GIB = 1 << 30
DISCLOSURE = ("Isolated mode on macOS runs OMBP in this launcher's own Linux VM: Linux Nix programs only, software "
              "rendering, and its own persistent OMP/OMSP configuration, logins and sessions inside the VM (your "
              "Mac ~/.omp is not shared and nothing is copied).")
_RECEIPT_FIELDS = {"generation", "instance", "arch", "image", "state", "created"}


def host_arch():
    machine = platform.machine()
    if machine in ("arm64", "aarch64"):
        return "aarch64"
    if machine == "x86_64":
        return "x86_64"
    raise ValueError(f"Unsupported Mac architecture {machine}")


def host_memory_gib():
    result = subprocess.run(["/usr/sbin/sysctl", "-n", "hw.memsize"], capture_output=True, text=True,
                            check=True, timeout=10)
    return int(result.stdout.strip()) // GIB


# Resources ---------------------------------------------------------------------------------------------------------

def default_resources(cpus, memory_gib):
    if memory_gib < 8:
        raise ValueError("The macOS Linux runtime needs a Mac with at least 8 GiB of memory")
    return {"cpus": min(6, cpus), "memory_gib": 10 if memory_gib >= 16 else memory_gib - 4, "disk_gib": 64}


def validate_resources(value, cpus, memory_gib, path):
    if (not isinstance(value, dict) or set(value) != {"cpus", "memory_gib", "disk_gib"}
            or any(type(value[key]) is not int for key in value)):
        raise ValueError(f"{path} must be exactly {{\"cpus\": N, \"memory_gib\": N, \"disk_gib\": N}} with integers")
    if not 1 <= value["cpus"] <= cpus:
        raise ValueError(f"{path}: cpus must be between 1 and this Mac's {cpus} CPUs")
    if not 4 <= value["memory_gib"] <= memory_gib - 4:
        raise ValueError(f"{path}: memory_gib must be at least 4 and leave 4 GiB of this Mac's {memory_gib} GiB")
    if value["disk_gib"] < 32:
        raise ValueError(f"{path}: disk_gib must be at least 32")
    return dict(value)


def load_resources(policy, cpus, memory_gib):
    """(resources, saved): the validated vm.json, or this Mac's defaults when none was written yet."""
    path = policy.directory / RESOURCES
    if not os.path.lexists(path):
        return default_resources(cpus, memory_gib), False
    try:
        value = read_private_json(path, "VM resource settings")
    except (OSError, ValueError) as error:
        raise ValueError(f"{path} is not valid JSON: {error}") from error
    return validate_resources(value, cpus, memory_gib, path), True


# Private Lima home -------------------------------------------------------------------------------------------------

def lima_home(policy, home=None):
    return (Path.home() if home is None else Path(home)) / ".local/share/ombp-lima" / policy.state_id


def _owner_only(path, create):
    if create and not os.path.lexists(path):
        os.mkdir(path, 0o700)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{path} must be a real directory, not a symlink")
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ValueError(f"{path} must be owned by you and private (mode 700)")


def prepare_lima_home(path):
    """Create/check the private LIMA_HOME; refuse global overrides and paths too long for Lima's sockets."""
    path = Path(path)
    owned_root = path.parent  # ~/.local/share/ombp-lima
    for ancestor in (owned_root.parent.parent, owned_root.parent):  # ~/.local, ~/.local/share
        if not os.path.lexists(ancestor):
            os.mkdir(ancestor, 0o700)
        elif os.path.islink(ancestor) or not os.path.isdir(ancestor):
            raise ValueError(f"{ancestor} must be a real directory, not a symlink")
    _owner_only(owned_root, True)
    _owner_only(path, True)
    if Path(os.path.realpath(path)) != path:
        raise ValueError(f"{path} must be a canonical path without symlinks")
    longest = path / INSTANCE / LONGEST_LIMA_SOCKET
    if len(os.fsencode(str(longest))) >= SOCKET_LIMIT:
        raise ValueError(f"The VM's socket paths under {path} exceed macOS's {SOCKET_LIMIT}-byte limit; "
                         "use a shorter home directory path")
    for name in OVERRIDES:
        if os.path.lexists(path / "_config" / name):
            raise ValueError(f"Unexpected Lima override {path / '_config' / name}; remove it: this VM's "
                             "configuration must come only from the launcher")
    return path


def _get(config, *keys):
    for key in keys:
        if not isinstance(config, dict):
            return None
        config = config.get(key)
    return config


def verify_config(instance, arch, resources):
    """Refuse a VM whose effective Lima configuration differs from the launcher's isolation settings."""
    config = instance.get("config")
    problems = []
    expected = {("vmType",): "vz", ("arch",): arch, ("containerd", "system"): False, ("containerd", "user"): False,
                ("ssh", "forwardAgent"): False, ("ssh", "forwardX11"): False, ("ssh", "forwardX11Trusted"): False,
                ("ssh", "loadDotSSHPubKeys"): False, ("propagateProxyEnv",): False, ("plain",): False,
                ("vmOpts", "vz", "rosetta", "enabled"): False}
    for keys, value in expected.items():
        if _get(config, *keys) != value:
            problems.append(f"{'.'.join(keys)}={_get(config, *keys)!r}")
    for key in ("mounts", "additionalDisks", "networks", "copyToHost"):
        if _get(config, key):
            problems.append(f"{key} is not empty")
    forwards = _get(config, "portForwards") or []
    first = forwards[0] if forwards else {}
    if not (first.get("ignore") is True and first.get("guestIP") == "0.0.0.0" and first.get("proto") == "any"
            and not first.get("guestIPMustBeZero") and first.get("guestPortRange", [1, 65535]) == [1, 65535]
            and not first.get("guestSocket")):
        problems.append("the first port-forward rule does not ignore every guest port")
    if any(rule.get("ignore") is not True for rule in forwards):
        problems.append("a port-forward rule publishes guest ports")
    if instance.get("vmType") != "vz" or instance.get("arch") != arch:
        problems.append("instance type/architecture")
    if (instance.get("cpus") != resources["cpus"] or instance.get("memory") != resources["memory_gib"] * GIB
            or instance.get("disk") != resources["disk_gib"] * GIB):
        problems.append("resources differ from vm.json")
    if problems:
        raise RuntimeError("The owned Linux VM's effective configuration is not the launcher's isolated "
                           "configuration: " + "; ".join(problems))


# Snapshots ---------------------------------------------------------------------------------------------------------

def _excluded_source(name, kind):
    return (name in SOURCE_EXCLUDED or (kind == "dir" and name in VCS_DIRECTORIES)
            or name.endswith(("~", ".o", ".so")) or (name.startswith(".") and name[-4:-1] == ".sw")
            or (kind == "link" and name.startswith("result")))


def _excluded_launcher(name, kind):
    return name in LAUNCHER_EXCLUDED


def write_tree(output, root, excluded, limit=SNAPSHOT_BYTES):
    """Stream `root`'s current files as a tar: regular files, directories and internal relative symlinks.

    Nothing outside `root` is read; an escaping or absolute symlink or a special file is an error, not skipped.
    """
    root = Path(root)
    total = 0
    with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        # fwalk pins every directory and rechecks it before descending. All leaf operations use that fd,
        # so swapping a directory for an escaping symlink cannot redirect snapshot reads.
        for directory, directories, files, directory_fd in os.fwalk(root, follow_symlinks=False):
            relative = Path(directory).relative_to(root)
            for name in list(directories):
                if excluded(name, "dir"):
                    directories.remove(name)
            for leaf in sorted(directories + files):
                metadata = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
                kind = ("dir" if stat.S_ISDIR(metadata.st_mode) else "file" if stat.S_ISREG(metadata.st_mode)
                        else "link" if stat.S_ISLNK(metadata.st_mode) else "special")
                if excluded(leaf, kind):
                    continue
                name = (relative / leaf).as_posix()
                info = tarfile.TarInfo(name)
                info.mtime, info.uid, info.gid, info.uname, info.gname = int(metadata.st_mtime), 0, 0, "", ""
                if kind == "dir":
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                    archive.addfile(info)
                elif kind == "link":
                    target = os.readlink(leaf, dir_fd=directory_fd)
                    depth = len(Path(name).parts) - 1
                    inside = not target.startswith("/")
                    for part in Path(target).parts if inside else ():
                        depth += -1 if part == ".." else 0 if part == "." else 1
                        inside = inside and depth >= 0
                    if not inside:
                        raise ValueError(f"Symlink {name} points outside {root} (snapshots include only "
                                         "relative links inside it)")
                    info.type, info.linkname, info.mode = tarfile.SYMTYPE, target, 0o777
                    archive.addfile(info)
                elif kind == "file":
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory_fd)
                    with os.fdopen(fd, "rb") as stream:
                        opened = os.fstat(fd)
                        if (not stat.S_ISREG(opened.st_mode)
                                or (opened.st_ino, opened.st_dev) != (metadata.st_ino, metadata.st_dev)):
                            raise ValueError(f"{name} changed while taking the snapshot; retry")
                        total += opened.st_size
                        if total > limit:
                            raise ValueError("The selected checkout is too large to snapshot")
                        info.type, info.size = tarfile.REGTYPE, opened.st_size
                        info.mode = 0o755 if opened.st_mode & 0o111 else 0o644
                        archive.addfile(info, _Exact(stream, opened.st_size, name))
                else:
                    raise ValueError(f"{name} is a special file; snapshots include only files, folders and links")


class _Exact(io.RawIOBase):
    """Archive the size pinned at open; truncation fails rather than producing a malformed tar stream."""

    def __init__(self, stream, size, name):
        self.stream, self.remaining, self.name = stream, size, name

    def readable(self):
        return True

    def readinto(self, buffer):
        if not self.remaining:
            return 0
        count = self.stream.readinto(memoryview(buffer)[:min(len(buffer), self.remaining)])
        if not count:
            raise ValueError(f"{self.name} changed while taking the snapshot; retry")
        self.remaining -= count
        return count


def tree_digest(root, excluded):
    """(sha256, tar bytes) of a small tree such as the launcher's own sources."""
    data = io.BytesIO()
    write_tree(data, root, excluded, limit=64 << 20)
    return hashlib.sha256(data.getvalue()).hexdigest(), data.getvalue()


# Guest control session ---------------------------------------------------------------------------------------------

class _Pipe:
    def __init__(self, stream):
        self.stream = stream

    def recv_into(self, view):
        return self.stream.readinto(view)


class GuestSession:
    """The framed control channel to vm/guest.py over one owned SSH process."""

    def __init__(self, args, on_event, log, on_lost, children=None):
        self.on_event = on_event
        self.on_lost = on_lost
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.pending = {}
        self.next_id = 1
        self.alive = True
        self.hello = threading.Event()
        spawn = children.popen if children is not None else subprocess.Popen
        self.process = spawn(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                             bufsize=0, start_new_session=True)
        os.set_blocking(self.process.stdin.fileno(), False)
        self.reader = threading.Thread(target=self._read, name="guest-session", daemon=True)
        self.reader.start()
        if not self.hello.wait(60) or not self.alive:
            self.close()
            raise RuntimeError("The Linux runtime supervisor did not start; see launch.log")

    def _read(self):
        pipe = _Pipe(self.process.stdout)
        try:
            while True:
                message = read_frame(pipe)
                if message is None:
                    break
                if "event" in message:
                    if message["event"] == "hello":
                        self.hello.set()
                    else:
                        self.on_event(message)
                    continue
                with self.lock:
                    waiter = self.pending.pop(message.get("id"), None)
                if waiter is not None:
                    waiter.put(message)
        except (ProtocolError, OSError, ValueError):
            pass
        finally:
            self.process.stdout.close()
            with self.lock:
                self.alive = False
                pending, self.pending = self.pending, {}
            for waiter in pending.values():
                waiter.put(None)
            self.hello.set()
            self.on_lost(self)

    def request(self, action, timeout=30, **args):
        deadline = time.monotonic() + timeout
        waiter = queue.Queue(1)
        if not self.send_lock.acquire(timeout=timeout):
            raise TimeoutError(f"The Linux runtime transport is blocked during {action}")
        try:
            with self.lock:
                if not self.alive:
                    raise RuntimeError("The Linux runtime is not connected")
                request_id = self.next_id
                self.next_id += 1
                self.pending[request_id] = waiter
            frame = memoryview(encode_frame({"id": request_id, "action": action, "args": args}))
            descriptor = self.process.stdin.fileno()
            while frame:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [descriptor], [], remaining)[1]:
                    raise TimeoutError(f"The Linux runtime transport timed out during {action}")
                try:
                    frame = frame[os.write(descriptor, frame):]
                except BlockingIOError:
                    continue
        except BaseException:
            with self.lock:
                self.pending.pop(locals().get("request_id"), None)
                self.alive = False
            # A partially transmitted frame cannot be reused. EOF cancels the guest.
            self.process.terminate()
            raise
        finally:
            self.send_lock.release()
        try:
            reply = waiter.get(timeout=max(0, deadline - time.monotonic()))
        except queue.Empty:
            with self.lock:
                self.pending.pop(request_id, None)
            raise TimeoutError(f"The Linux runtime did not answer {action} within {timeout} s") from None
        if reply is None:
            raise RuntimeError("Lost the connection to the Linux runtime")
        if not reply.get("ok"):
            raise ValueError(str(reply.get("error") or "Linux runtime request failed"))
        return reply.get("result")

    def close(self, timeout=15):
        """EOF asks the guest to retire everything it owns; the SSH client is ended after `timeout`."""
        with self.lock:
            self.alive = False
        if not self.send_lock.acquire(timeout=5):
            terminate(self.process, 5)
            self.send_lock.acquire()
        try:
            self.process.stdin.close()
        except OSError:
            pass
        finally:
            self.send_lock.release()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            terminate(self.process, 5)
        self.reader.join(timeout=5)


class GuestWorkload:
    """The isolated OMBP inside the VM, shaped like a Popen for the portable lifecycle owner."""

    def __init__(self):
        self.returncode = None
        self.error = ""
        self.done = threading.Event()

    def finish(self, error):
        if not self.done.is_set():
            self.error = error
            self.returncode = 1 if error else 0
            self.done.set()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if not self.done.wait(timeout):
            raise subprocess.TimeoutExpired("linux-vm", timeout)
        return self.returncode


class VmRun:
    """Host-side capabilities of one isolated launch; all are revoked together."""

    def __init__(self):
        self.workload = GuestWorkload()
        self.events = queue.Queue()
        self.guest_run = None
        self.admitted = threading.Event()
        self.files = None
        self.broker = None
        self.network = None
        self.forward = None
        self.revoked = False
        self.retirement = threading.Lock()


# Backend -----------------------------------------------------------------------------------------------------------

class VmBackend:
    """Owns the app's Linux VM and the host side of isolated launches in it. Runtime owns the lifecycle."""

    name = "linux-vm"
    container = None

    def __init__(self, policy, environ=None, cpus=None, memory_gib=None, home=None):
        environ = os.environ if environ is None else environ
        self.policy = policy
        self.arch = host_arch()
        self.system = f"{self.arch}-linux"
        self.cpus = os.cpu_count() if cpus is None else cpus
        self.memory_gib = host_memory_gib() if memory_gib is None else memory_gib
        self.home = lima_home(policy, home)
        self.limactl = environ.get("START_APP_LIMACTL") or shutil.which("limactl")
        openssh = environ.get("START_APP_OPENSSH")
        self.ssh = str(Path(openssh) / "ssh") if openssh else shutil.which("ssh")
        self.template = environ.get("START_APP_LIMA_TEMPLATE")
        self.cacert = environ.get("START_APP_CACERT")
        self.novnc = environ.get("START_APP_NOVNC")
        self.lock = threading.Lock()          # status fields only
        self.vm_lock = threading.Lock()       # one VM boot/preparation at a time
        self._policy_send = threading.Lock()
        self.session = None
        self.wrapper = None
        self.run = None
        self._display_events = queue.Queue()
        self._display_worker = threading.Thread(target=self._display_events_run, name="vm-displays", daemon=True)
        self._display_worker.start()
        self.vm_state = "created" if (policy.directory / STATE_RECEIPT).exists() else "absent"
        self.catalog_programs = []
        self.catalog_ready = False
        self.catalog_generation = 0
        self.projection = None
        self.policy_generation = 0
        self.applied_policy_generation = 0
        self.viewer = None
        self.displays = {}
        self.log = None
        self.closing = False
        manifest = policy.directory / "requirements.json"
        self.requirements = json.loads(manifest.read_text()) if manifest.exists() else [
            {"id": key, "label": label, "path": path, "kind": "folder"} for key, label, path in FOLDERS]
        self._push = threading.Event()
        policy.add_listener(self._policy_changed)
        self._policy_changed()
        self._policy_worker = threading.Thread(target=self._push_policies, name="vm-policy", daemon=True)
        self._policy_worker.start()

    # Status ----------------------------------------------------------------------------------------------------

    def resources(self):
        return load_resources(self.policy, self.cpus, self.memory_gib)

    def status_fields(self):
        try:
            resources, saved = self.resources()
            resource_error = ""
        except ValueError as error:
            resources, saved, resource_error = None, False, str(error)
        with self.lock:
            return {"desktops": self.viewer.desktops() if self.viewer else [],
                    "catalog_generation": self.catalog_generation,
                    "policy_generation": self.policy_generation,
                    "applied_policy_generation": self.applied_policy_generation,
                    "vm": {"state": self.vm_state, "connected": self.session is not None and self.session.alive,
                           "resources": resources, "resources_saved": saved, "resources_error": resource_error,
                           "resources_path": str(self.policy.directory / RESOURCES),
                           "host": {"cpus": self.cpus, "memory_gib": self.memory_gib},
                           "system": self.system, "disclosure": DISCLOSURE}}

    def catalog(self):
        folders = user_folders()
        with self.lock:
            # Package choices are static launcher metadata for the VM's Linux system: available before it boots.
            return {"gpu": "none", "folders": folders, "programs": list(self.catalog_programs),
                    "program_domain": "linux-vm", "runtime_system": self.system, "system": self.system,
                    "packages": PACKAGE_CHOICES, "language_servers": LANGUAGE_SERVER_COMMANDS,
                    "program_catalog_ready": self.catalog_ready, "generation": self.catalog_generation}

    def requirements_status(self, installation=None):
        """`installation` is the admitted launch's captured choice; otherwise the desired policy applies."""
        snapshot = self.policy.snapshot()
        installed = (installation or snapshot)["installed_mode"]
        return [{**item, "enabled": requirement_enabled(item, installed, snapshot["disabled_requirements"]),
                 "label": ("Private persistent Linux VM home (separate OMP/OMSP state)"
                           if item["id"] == "sandbox-home" else "SonarQube engine (filtered VM Podman)"
                           if item["id"] == "sonar-engine" else item["label"])}
                for item in self.requirements if item["id"] != "host-omp"]

    def _save_requirements(self, items):
        rows = []
        for item in items:
            if not isinstance(item, dict) or not {"id", "label", "path", "kind"} <= set(item):
                continue
            row = {key: str(item[key]) for key in ("id", "label", "path", "kind")}
            programs = item.get("programs")
            # A bundle's actual command names; older guests and folder rows have none.
            if isinstance(programs, list) and all(isinstance(name, str) and 0 < len(name) <= 255
                                                  and "/" not in name and "\x00" not in name for name in programs):
                row["programs"] = sorted(set(programs))
            if row["id"] == "host-omp":
                continue  # The VM never binds the Mac's ~/.omp; there is no shared-state toggle to offer.
            if row["id"] == "sandbox-home":
                row["label"] = "Private OMBP home in the Linux VM (its own OMP/OMSP logins and sessions)"
            elif row["id"] == "sonar-engine":
                row["label"] = "SonarQube engine (filtered VM Podman)"
            rows.append(row)
        self.policy.save("requirements.json", rows)
        with self.lock:
            self.requirements = rows

    def exit_error(self, code):
        run = self.run
        error = run.workload.error if run else ""
        return error or (f"Isolated OMBP exited {code}; see {self.policy.directory / 'launch.log'}" if code else "")

    # Policy ----------------------------------------------------------------------------------------------------

    def _projection(self):
        snapshot = self.policy.snapshot()
        return {"programs": snapshot["programs"], "disabled_requirements": snapshot["disabled_requirements"],
                "folders": [item for item in snapshot["folders"] if item["path"] == HOST_WORKSPACE]}

    def _policy_changed(self):
        projection = self._projection()
        with self.lock:
            if projection == self.projection:
                return
            self.projection = projection
            self.policy_generation += 1
        self._push.set()

    def _push_policies(self):
        """Send each new projection to a live isolated workload; an unconfirmed one retires that workload."""
        while True:
            self._push.wait()
            self._push.clear()
            with self.lock:
                if self.closing:
                    return
                run, session = self.run, self.session
                generation, projection = self.policy_generation, self.projection
                if run is None or session is None or generation == self.applied_policy_generation:
                    continue
            try:
                self._send_policy(session, generation, projection)
            except (OSError, RuntimeError, ValueError) as error:
                self._retire_unconfirmed(run, f"The Linux runtime did not confirm a permission change ({error}); "
                                              "isolated OMBP was stopped")

    def _send_policy(self, session, generation, projection):
        deadline = time.monotonic() + ACK_DEADLINE
        if not self._policy_send.acquire(timeout=ACK_DEADLINE):
            raise TimeoutError("Previous policy acknowledgement is still pending")
        try:
            with self.lock:
                # A newer update can overtake a launch's captured projection; never send stale authority.
                generation, projection = self.policy_generation, self.projection
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Policy acknowledgement deadline expired")
            result = session.request("policy", timeout=remaining, generation=generation, projection=projection)
            if not isinstance(result, dict) or result.get("applied") != generation:
                raise RuntimeError("unexpected acknowledgement")
            with self.lock:
                self.applied_policy_generation = max(self.applied_policy_generation, generation)
        finally:
            self._policy_send.release()

    def resolve_program(self, value):
        """Policy's resolver for new program grants: a Linux Nix executable in the VM, never a Mac path."""
        session = self.session
        if session is None or not session.alive:
            raise ValueError("Prepare the Linux runtime to choose programs")
        result = session.request("resolve_program", timeout=30, value=value)
        return result["path"]

    # VM --------------------------------------------------------------------------------------------------------

    def _lima(self, args, children, timeout, log, check=True, capture=False):
        environment = {"LIMA_HOME": str(self.home), "HOME": str(Path.home()), "LANG": "C",
                       "PATH": os.pathsep.join((str(Path(self.ssh).parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin"))}
        return children.run([self.limactl, *args], timeout=timeout, check=check, env=environment,
                            stdin=subprocess.DEVNULL, **({"capture_output": True, "text": True} if capture
                                                         else {"stdout": log, "stderr": log}))

    def _instance(self, children, log):
        result = self._lima(["list", "--json"], children, 60, log, capture=True)
        instances = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        return next((item for item in instances if item.get("name") == INSTANCE), None)

    def _image(self):
        template = json.loads(Path(self.template).read_text())
        image = next(item for item in template["images"] if item["arch"] == self.arch)
        return template, {"location": image["location"], "digest": image["digest"]}

    def _receipts(self):
        values = []
        for path in (self.home / HOME_RECEIPT, self.policy.directory / STATE_RECEIPT):
            if not os.path.lexists(path):
                values.append(None)
                continue
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                metadata = os.fstat(fd)
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                        or metadata.st_mode & 0o077 or metadata.st_size > 4096):
                    raise RuntimeError(f"VM ownership receipt must be an owner-only regular file: {path}")
                value = json.loads(os.read(fd, 4097))
            finally:
                os.close(fd)
            if not isinstance(value, dict) or set(value) != _RECEIPT_FIELDS:
                raise RuntimeError(f"Invalid VM ownership receipt {path}")
            values.append(value)
        return values

    def _write_receipt(self, receipt):
        data = json.dumps(receipt)
        temporary = self.home / f".{HOME_RECEIPT}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.home / HOME_RECEIPT)
        self.policy.save(STATE_RECEIPT, receipt)

    def _owned_instance(self, children, log):
        """The verified owned instance (or None before creation) and its receipt; never another VM."""
        prepare_lima_home(self.home)
        if os.path.lexists(self.home / INSTANCE):
            _owner_only(self.home / INSTANCE, False)
        if os.path.lexists(self.home / "_config"):
            _owner_only(self.home / "_config", False)
        home_receipt, state_receipt = self._receipts()
        instance = self._instance(children, log)
        if home_receipt is None and state_receipt is None:
            if instance is not None:
                raise RuntimeError(f"{self.home} holds a Lima instance without this launcher's ownership receipt; "
                                   "it is left untouched")
            return None, None
        if home_receipt != state_receipt:
            raise RuntimeError(f"The VM ownership receipts in {self.home} and {self.policy.directory} disagree; "
                               "nothing was adopted or changed")
        receipt = home_receipt
        if (receipt["instance"] != INSTANCE or receipt["arch"] != self.arch
                or receipt["state"] != str(self.policy.directory)):
            raise RuntimeError("The VM ownership receipt belongs to another state directory or architecture")
        if receipt["image"] != self._image()[1]:
            raise RuntimeError("The VM ownership receipt has an unexpected pinned image identity")
        if (not isinstance(receipt["generation"], str) or len(receipt["generation"]) != 32
                or any(c not in "0123456789abcdef" for c in receipt["generation"])
                or type(receipt["created"]) is not bool):
            raise RuntimeError("Invalid VM ownership generation")
        if instance is None:
            if receipt["created"]:
                raise RuntimeError(f"The owned VM recorded in {self.policy.directory / STATE_RECEIPT} is missing; "
                                   "remove that receipt and " + str(self.home / HOME_RECEIPT) + " to create a new one")
            return None, receipt
        if (instance.get("dir") != str(self.home / INSTANCE) or instance.get("arch") != self.arch
                or instance.get("vmType") != "vz"):
            raise RuntimeError("Recorded VM identity no longer matches this launcher")
        images = _get(instance, "config", "images") or []
        if not any(item.get("digest") == receipt["image"]["digest"] for item in images):
            raise RuntimeError("The owned VM's image does not match its ownership receipt")
        return instance, receipt

    def _download_image(self, image, children):
        digest = image["digest"].removeprefix("sha256:")
        final = self.home / f".image-{digest[:16]}.img"
        partial = final.with_name(final.name + f".part-{secrets.token_hex(8)}")
        try:
            result = children.run([sys.executable, str(LAUNCHER / "vm/fetch_image.py"),
                                   image["location"], digest, str(partial), self.cacert or ""],
                                  timeout=1800, capture_output=True, text=True, start_new_session=True)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "Pinned VM image download failed")
            os.replace(partial, final)
        finally:
            partial.unlink(missing_ok=True)
        return final

    def _create(self, receipt, resources, children, log):
        template, image = self._image()
        if receipt is None:
            receipt = {"generation": secrets.token_hex(16), "instance": INSTANCE, "arch": self.arch,
                       "image": image, "state": str(self.policy.directory), "created": False}
            self._write_receipt(receipt)
        local = self._download_image(receipt["image"], children)
        try:
            config = {**template, "arch": self.arch, "cpus": resources["cpus"],
                      "memory": f"{resources['memory_gib']}GiB", "disk": f"{resources['disk_gib']}GiB",
                      "images": [{"location": str(local), "arch": self.arch, "digest": receipt["image"]["digest"]}]}
            path = self.home / ".ombp-template.yaml"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as output:
                json.dump(config, output)  # JSON is YAML.
            self._lima(["create", "--tty=false", f"--name={INSTANCE}", str(path)], children, 1800, log)
        finally:
            local.unlink(missing_ok=True)
        self._write_receipt({**receipt, "created": True})

    def _boot(self, children, log):
        if not self.limactl or not self.ssh or not self.template:
            raise ValueError("Start through the supplied Nix launcher for macOS isolated mode (Lima and OpenSSH)")
        resources, saved = self.resources()
        instance, receipt = self._owned_instance(children, log)
        if not saved:
            self.policy.save(RESOURCES, resources)
        if instance is None:
            with self.lock:
                self.vm_state = "creating"
            self._create(receipt, resources, children, log)
            instance, receipt = self._owned_instance(children, log)
        if instance.get("status") == "Running":
            verify_config(instance, self.arch, resources)
        else:
            if (instance.get("cpus"), instance.get("memory"), instance.get("disk")) != (
                    resources["cpus"], resources["memory_gib"] * GIB, resources["disk_gib"] * GIB):
                if instance.get("disk", 0) > resources["disk_gib"] * GIB:
                    raise ValueError(f"{self.policy.directory / RESOURCES}: the VM disk cannot shrink below "
                                     f"{instance['disk'] // GIB} GiB")
                self._lima(["edit", "--tty=false", INSTANCE, f"--cpus={resources['cpus']}",
                            f"--memory={resources['memory_gib']}", f"--disk={resources['disk_gib']}"],
                           children, 120, log)
                instance, receipt = self._owned_instance(children, log)
            verify_config(instance, self.arch, resources)
            with self.lock:
                self.vm_state = "starting"
            self._lima(["start", "--tty=false", "--timeout=15m", INSTANCE], children, 1200, log)
            instance, receipt = self._owned_instance(children, log)
            verify_config(instance, self.arch, resources)
        if instance.get("status") != "Running":
            raise RuntimeError(f"The Linux VM did not start (status {instance.get('status')!r}); see launch.log")
        with self.lock:
            self.vm_state = "running"

    def _ssh(self, *options, forwards=False):
        base = [self.ssh, "-F", str(self.home / INSTANCE / "ssh.config"), "-o", "ControlMaster=no",
                "-o", "ControlPath=none", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                "-o", "PermitLocalCommand=no", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=5",
                "-o", "ServerAliveCountMax=3", "-o", "LogLevel=ERROR", "-T"]
        if not forwards:
            base += ["-o", "ClearAllForwardings=yes"]
        return [sys.executable, str(LAUNCHER / "vm/owned_ssh.py"), str(os.getpid()),
                *base, *options, f"lima-{INSTANCE}"]

    def _provision(self, children, log):
        script = (LAUNCHER / "vm/provision.sh").read_bytes()
        provisioned = False

        def output(line):
            # Teed live to launch.log while the success sentinel is looked for.
            nonlocal provisioned
            log.write(line)
            provisioned = provisioned or b"ombp-provision: ok" in line
        code = children.run_lines([*self._ssh(), "sudo -n /bin/bash -s"], input=script, timeout=3600,
                                  on_line=output, stderr=log)
        if code or not provisioned:
            raise RuntimeError("Provisioning the Linux VM failed; see launch.log")

    def _deploy(self, children, log):
        """Build the guest supervisor from this controller's own launcher sources and lock, never the checkout."""
        digest, data = tree_digest(LAUNCHER, _excluded_launcher)
        receiver = ('set -eu; root="$HOME/.local/state/ombp-guest/launcher"; umask 077; mkdir -p "$root"; '
                    f'dest="$root/{digest}"; if [ -d "$dest" ]; then cat >/dev/null; exit 0; fi; '
                    'work=$(mktemp -d "$root/.incoming.XXXXXXXX"); cat > "$work.tar"; '
                    f'echo "{digest}  $work.tar" | sha256sum --check --strict --quiet; '
                    'tar -x --no-same-owner -f "$work.tar" -C "$work"; rm -f "$work.tar"; mv "$work" "$dest"')
        children.run([*self._ssh(), receiver], input=data, timeout=300, check=True, stdout=log, stderr=log)
        step(log, "Building guest runtime (first run downloads its Nix closure)")
        build = children.run(
            [*self._ssh(), f"{GUEST_NIX} --extra-experimental-features 'nix-command flakes' build "
                           f"\"path:$HOME/.local/state/ombp-guest/launcher/{digest}#guest-runtime\" --no-link "
                           "--print-out-paths --print-build-logs --no-write-lock-file"],
            timeout=7200, stdout=subprocess.PIPE, stderr=log, text=True)
        outputs = build.stdout.split()
        if build.returncode or len(outputs) != 1 or not outputs[0].startswith("/nix/store/"):
            raise RuntimeError("Building the guest runtime in the Linux VM failed; see launch.log")
        wrapper = outputs[0] + "/bin/ombp-guest"
        # This fixed bootstrap action is outside the application/control protocol and runs only in the
        # receipt-verified guest. The pinned static interpreter preserves the scanner's exact image pin.
        step(log, "Preparing scanner emulator")
        prepared = children.run([*self._ssh(), f"sudo -n {shlex.quote(wrapper)} provision-emulation"],
                                timeout=60, stdout=log, stderr=log)
        if prepared.returncode:
            raise RuntimeError("The Linux guest's pinned scanner emulator could not be prepared; see launch.log")
        return wrapper

    def _open_log(self):
        if self.log is None:
            self.log = open(self.policy.directory / "launch.log", "ab", buffering=0)
        return self.log

    def _connect(self, children):
        """A new control session with the deployed guest supervisor (which first retires any leftovers)."""
        return GuestSession([*self._ssh(), shlex.quote(self.wrapper)], self._on_event, self._open_log(),
                            self._session_lost, children=children)

    def prepare(self, children, log):
        """Boot, provision and connect the owned VM (idempotent) and refresh its program catalog."""
        with self.vm_lock:
            if self.closing:
                raise Cancelled("Launcher is closing")
            if self.vm_state == "failed":
                raise RuntimeError("VM retirement could not be confirmed; close the launcher and resolve the "
                                   "owned VM error in launch.log before another isolated launch")
            session = self.session
            if session is None or not session.alive:
                try:
                    step(log, "Booting Linux VM")
                    self._boot(children, log)
                except BaseException:
                    with self.lock:
                        if self.vm_state in ("creating", "starting"):
                            self.vm_state = ("created" if (self.policy.directory / STATE_RECEIPT).exists()
                                             else "absent")
                    raise
                step(log, "Provisioning Linux VM")
                self._provision(children, log)
                self.wrapper = self._deploy(children, log)
                children.check()
                step(log, "Connecting to guest supervisor")
                session = self._connect(children)
                with self.lock:
                    self.session = session
                    self.applied_policy_generation = 0
            else:
                step(log, "Checking prepared Linux VM")
                children.adopt(session.process, group=True)
                # A prepared session does not authorize silently changing a live VM's resources/configuration.
                instance, _ = self._owned_instance(children, log)
                if instance is None or instance.get("status") != "Running":
                    raise RuntimeError("The prepared Linux VM is no longer running")
                verify_config(instance, self.arch, self.resources()[0])
            step(log, "Reading Linux program catalog")
            catalog = session.request("catalog", timeout=120)
            programs = [{"name": str(item["name"]), "path": str(item["path"]), "system": str(item["system"])}
                        for item in catalog["programs"]]
            children.release(session.process)
            with self.lock:
                self.catalog_programs = programs
                self.catalog_ready = True
                self.catalog_generation += 1
            return session

    # Launch ----------------------------------------------------------------------------------------------------

    def launch(self, settings, log, children, advance, *, installation):
        """Prepare, snapshot, start and await the isolated OMBP; returns its workload once it is live.

        `installation` is the launch's captured {installed_mode, selected_packages}; the guest builds it.
        """
        if settings["gpu"] != "none":
            raise ValueError("GPU passthrough is not available in the macOS Linux VM; choose Software rendering")
        session = self.prepare(children, log)
        # Installed mode ignores saved inspection program grants (kept for inspection), so they cannot block it.
        for program in [] if installation["installed_mode"] else self.policy.snapshot()["programs"]:
            resolved = session.request("resolve_program", timeout=30, value=program)
            if resolved["path"] != program:
                raise ValueError(f"Selected program {program} is not a Linux executable in the VM; remove it")
            session.request("resolve_closure", timeout=120, executable=program)
            children.check()
        snapshot_id = secrets.token_hex(16)
        self._send_snapshot(settings["source"], snapshot_id, children, log)
        run = VmRun()
        with self.lock:
            self.run = run
        try:
            with run.retirement:
                if run.revoked:
                    raise RuntimeError("This isolated launch has already been retired")
                run.files = HostFiles(self.policy)
                transient = self.policy.transient_directory()
                run.broker = FileBrokerServer(run.files, transient / "broker.sock")
                from mac_network import HostNetwork, keyring_unlock
                run.network = HostNetwork(self.policy)
                run.network.start()
                status = session.request("status", timeout=10)
                run.forward = self._forwards(status["forwards"], run, children, transient)
                snapshot = self.policy.snapshot()
                if any(item["path"] == HOST_WORKSPACE for item in snapshot["folders"]):
                    prepare_workspace(Path(HOST_WORKSPACE))
                with self.lock:
                    generation, projection = self.policy_generation, self.projection
                self._send_policy(session, generation, projection)
                children.check()
                try:
                    receipt = session.request(
                        "start", timeout=ACK_DEADLINE, source_snapshot_id=snapshot_id, desktop=settings["desktop"],
                        gpu="none", agent=settings["agent"], keyring_unlock=keyring_unlock(self.policy),
                        proxy_ca=run.network.public_ca().decode("ascii"),
                        workspace={"host_workspace": HOST_WORKSPACE, "container_workspace": CONTAINER_WORKSPACE},
                        installation={"installed_mode": installation["installed_mode"],
                                      "selected_packages": list(installation["selected_packages"])},
                        # The Mac home as the guest sees it under /host, never the guest account's own home.
                        git_discovery_home="/host" + str(Path.home().resolve()))
                    if not isinstance(receipt, dict) or type(receipt.get("run")) is not int:
                        raise RuntimeError("The guest returned an invalid launch receipt")
                    run.guest_run = receipt["run"]
                finally:
                    run.admitted.set()
                advance("building")
            while True:
                try:
                    event = run.events.get(timeout=0.2)
                except queue.Empty:
                    children.check()
                    if run.workload.done.is_set():
                        raise RuntimeError(run.workload.error or "Isolated OMBP stopped before it was running")
                    continue
                if event.get("run") != run.guest_run:
                    continue
                if event["event"] == "requirements":
                    self._save_requirements(event["requirements"])
                    continue
                if event["event"] == "exited":
                    raise RuntimeError(event.get("error") or "Isolated OMBP stopped before it was running")
                if event["phase"] == "starting":
                    advance("starting")
                elif event["phase"] == "running":
                    return run.workload
        except BaseException:
            if isinstance(children, OwnedChildren) and children.cancelled:
                raise Cancelled("Launch cancelled") from None
            raise

    def _send_snapshot(self, source, snapshot_id, children, log):
        step(log, "Sending source snapshot")
        process = children.popen([*self._ssh(), f"{shlex.quote(self.wrapper)} receive-snapshot {snapshot_id}"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, start_new_session=True)
        try:
            write_tree(process.stdin, source, _excluded_source)
            process.stdin.close()
        except (BrokenPipeError, ValueError, OSError) as error:
            terminate(process, 5)
            children.check()
            if isinstance(error, ValueError):
                raise
            raise RuntimeError("The Linux runtime refused the source snapshot; see launch.log") from error
        output = process.stdout.read()
        process.wait()
        children.check()
        if process.returncode or output.strip() != b"ok":
            raise RuntimeError("The Linux runtime refused the source snapshot; see launch.log")

    def _forwards(self, paths, run, children, transient):
        """One owned SSH connection reverse-forwarding the gateway and broker sockets for this run only."""
        proxy, broker = paths["proxy"], paths["broker"]
        for path in (proxy, broker):
            if not isinstance(path, str) or not path.startswith("/") or "," in path or ":" in path:
                raise RuntimeError("The Linux runtime reported invalid forward paths")
        process = children.popen(
            [*self._ssh("-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=yes",
                        "-R", f"{proxy}:{run.network.socket_path}", "-R", f"{broker}:{transient / 'broker.sock'}",
                        forwards=True), f"{shlex.quote(self.wrapper)} await-forwards"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._open_log(), start_new_session=True)
        ready = queue.Queue(1)
        threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
        try:
            line = ready.get(timeout=20)
        except queue.Empty:
            line = b""
        if line.strip() != b"ready":
            terminate(process, 5)
            raise RuntimeError("Could not forward the website gateway and file broker into the Linux runtime")
        threading.Thread(target=self._watch_forward, args=(run, process), daemon=True).start()
        return process

    def _watch_forward(self, run, process):
        process.wait()
        if not run.revoked:
            self._retire_unconfirmed(run, "The Linux runtime's gateway connection was lost; isolated OMBP was stopped")

    # Guest events ----------------------------------------------------------------------------------------------

    def _on_event(self, event):
        kind = event.get("event")
        run = self.run
        if kind == "log":
            self._open_log().write(str(event.get("text", "")).encode())
        elif kind == "denial" and event.get("kind") == "program":
            self.policy.deny("program", str(event.get("target", ""))[:2048], str(event.get("reason", ""))[:300])
        elif kind in ("phase", "exited", "requirements") and run is not None and not run.revoked:
            # The reader may receive an event before the start reply. Queue it until the receipt is known;
            # an old run's final frame must never finish a newly admitted workload.
            if run.guest_run is None:
                run.events.put(event)
            elif event.get("run") == run.guest_run:
                if kind == "requirements":
                    self._save_requirements(event["requirements"])
                else:
                    if kind == "exited":
                        run.workload.finish(str(event.get("error") or ""))
                    run.events.put(event)
        elif kind == "display" and run is not None:
            self._display_events.put((run, event))

    def _display_events_run(self):
        # Preserve guest event order; a delayed ready must never resurrect a retired display.
        while (item := self._display_events.get()) is not None:
            run, event = item
            if not run.admitted.wait(ACK_DEADLINE) or event.get("run") != run.guest_run:
                continue
            if self.run is not run or run.revoked:
                continue
            try:
                self._display(event, run)
            except Exception as error:
                self._retire_unconfirmed(run, f"Isolated display forwarding failed: {error}")

    def _display(self, event, run):
        kind, generation, state = event.get("kind"), event.get("generation"), event.get("state")
        if kind not in ("ombp", "browser") or type(generation) is not int:
            return
        if state == "ready":
            port = event.get("vnc_port")
            if type(port) is not int or not 1 <= port <= 65535 or self.run is None:
                return
            socket_path = self.policy.transient_directory() / f"vnc-{kind}.sock"
            self._close_display(kind)
            socket_path.unlink(missing_ok=True)
            process = subprocess.Popen(
                [*self._ssh("-N", "-o", "ExitOnForwardFailure=yes", "-L", f"{socket_path}:127.0.0.1:{port}",
                            forwards=True)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self._open_log(),
                start_new_session=True)
            deadline = time.monotonic() + 10
            while not socket_path.is_socket():
                if process.poll() is not None or time.monotonic() >= deadline:
                    terminate(process, 5)
                    raise RuntimeError("The owned VNC forward did not become ready")
                time.sleep(0.05)
            viewer = self.viewer
            if viewer is None:
                from viewer import ViewerServer
                try:
                    viewer = ViewerServer(self.novnc).start()
                except BaseException:
                    terminate(process, 5)
                    raise
            with self.lock:
                retired = self.run is not run or run.revoked
                if not retired:
                    self.viewer = viewer
                    self.displays[kind] = (generation, process)
                    url = viewer.publish(kind, generation, str(socket_path))
            if retired:
                terminate(process, 5)
                if self.viewer is not viewer:
                    viewer.close()
                return
            from host_browser import open_url
            try:
                open_url(url)
            except (OSError, RuntimeError, ValueError) as error:
                # The viewer stays published; Open OMBP/Open browser in the control UI can still reach it.
                self._open_log().write(f"Could not open the {kind} viewer: {error}\n".encode())
        elif state in ("closed", "failed"):
            self._close_display(kind, generation)

    def _close_display(self, kind, generation=None):
        with self.lock:
            current = self.displays.get(kind)
            if current is None or (generation is not None and current[0] != generation):
                return
            del self.displays[kind]
            viewer = self.viewer
        if viewer is not None:
            viewer.retire(kind, current[0])
        terminate(current[1], 5)

    # Teardown --------------------------------------------------------------------------------------------------

    def _revoke(self, run):
        """Host authority ends at once: file handles, website gateway and forwards, whatever the guest does."""
        run.revoked = True
        run.admitted.set()
        if run.broker is not None:
            run.broker.close()
        if run.files is not None:
            run.files.close_all()
        if run.network is not None:
            run.network.stop()
        terminate(run.forward, 5)
        for kind in ("ombp", "browser"):
            self._close_display(kind)

    def _retire_unconfirmed(self, run, message):
        deadline = time.monotonic() + RETIRE_DEADLINE
        with run.retirement:
            if run.revoked:
                return
            self._revoke(run)
            session = self.session
            try:
                remaining = deadline - time.monotonic()
                if session is not None and remaining > 0:
                    session.request("stop", timeout=min(ACK_DEADLINE, remaining))
            except (OSError, RuntimeError, ValueError):
                pass
            try:
                if not self._await_guest_retired(session, run, deadline):
                    self._force_stop_vm()
            except Exception as error:
                message += f"; VM retirement failed: {error}"
            run.workload.finish(message)

    def _await_guest_retired(self, session, run, deadline=None):
        deadline = time.monotonic() + RETIRE_DEADLINE if deadline is None else deadline
        while time.monotonic() < deadline:
            if session is None or not session.alive:
                return False
            try:
                if session.request("status", timeout=max(0.1, deadline - time.monotonic()))["phase"] == "idle":
                    return True
            except (OSError, RuntimeError, ValueError):
                return False
            time.sleep(0.2)
        return False

    def _session_lost(self, session):
        with self.lock:
            if self.session is not session:
                return
            self.session = None
            self.catalog_ready = False
            self.catalog_generation += 1
            run = self.run
        if run is not None and not run.revoked and not self.closing:
            threading.Thread(target=self._recover_control, args=(run,), daemon=True).start()

    def _recover_control(self, run):
        # Do not reconnect/adopt while an old supervisor might still be retiring. With no acknowledgement
        # channel, stop the verified VM; prepare can establish a fresh session on the next operation.
        self._retire_unconfirmed(run, "Lost control of the Linux runtime; isolated OMBP was stopped")

    def _force_stop_vm(self):
        """After an unconfirmed retirement, force-stop only the verified VM and confirm it is no longer running."""
        self._stop_vm(force=True)

    def _stop_vm(self, force=False):
        children = OwnedChildren()
        log = self._open_log()
        try:
            instance, _ = self._owned_instance(children, log)
            if instance is not None and instance.get("status") != "Stopped":
                if not force:
                    try:
                        force = bool(self._lima(["stop", "--tty=false", INSTANCE], children, 10, log,
                                                check=False).returncode)
                    except subprocess.SubprocessError:
                        force = True
                if force:
                    self._lima(["stop", "--tty=false", "--force", INSTANCE], children, 30, log)
                instance, _ = self._owned_instance(children, log)
                if instance is not None and instance.get("status") != "Stopped":
                    raise RuntimeError("VM shutdown was not confirmed")
            with self.lock:
                self.vm_state = "created"
        except BaseException:
            with self.lock:
                self.vm_state = "failed"
            raise
        finally:
            children.retire()

    def cancel_preparation(self):
        """Cancellation before a guest run exists also retires SSH bootstrap/provisioning commands.

        SSH can lose its transport while a remote bootstrap child still runs. Before the supervisor is
        controlling builds, stopping this verified VM is the fail-closed retirement boundary.
        """
        if not (self.policy.directory / STATE_RECEIPT).exists():
            return
        with self.lock:
            session, self.session = self.session, None
            self.catalog_ready = False
            self.catalog_generation += 1
        if session is not None:
            session.close()
        self._force_stop_vm()

    def stop(self):
        """Retire the isolated workload: guest app/container, displays, build and broker; the VM keeps running."""
        with self.lock:
            run = self.run
        if run is None:
            return
        with run.retirement:
            session = self.session
            if not run.revoked:
                deadline = time.monotonic() + RETIRE_DEADLINE
                stopped = False
                try:
                    if session is not None and session.alive:
                        session.request("stop", timeout=ACK_DEADLINE)
                        stopped = self._await_guest_retired(session, run, deadline)
                except (OSError, RuntimeError, ValueError):
                    stopped = False
                self._revoke(run)
                if not stopped:
                    self._force_stop_vm()
            with self.lock:
                self.run = None

    def close(self):
        """Launcher exit: retire the workload, end the supervisor session and shut down the owned VM."""
        with self.lock:
            self.closing = True
        self.stop()
        self._push.set()
        self._policy_worker.join()
        with self.vm_lock:
            session, self.session = self.session, None
            if session is not None:
                session.close()
            if self.vm_state in ("running", "starting"):
                self._shutdown_vm()
        self._display_events.put(None)
        self._display_worker.join()
        if self.viewer is not None:
            self.viewer.close()
        if self.log is not None:
            self.log.close()
            self.log = None

    def _shutdown_vm(self):
        self._stop_vm()
