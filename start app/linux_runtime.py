"""Linux execution: one rootless container; filtered quality engine, no host session bus or host network.

Imported only by the Linux backend; FUSE, Wayland and Podman never load on other hosts.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import socket
import socketserver
import stat
import sys
import tempfile
import threading
import time
import uuid

from access_fs import AccessFS
from engine import EngineGateway, pinned_images, seed_client
from host_files import HostFiles
from network import NetworkGateway, read_public_ca
from policy import KEYRING_UNLOCK, new_keyring_unlock, read_keyring_unlock, read_private_json, valid_keyring_unlock
from installed import build_packages, install_profile
from omp_copy import copy_once, copy_status, read_copy_request
from requirements import (CONTAINER_WORKSPACE, DISPLAY_SOCKET, FOLDERS, HOST_WORKSPACE, bundles, prepare_workspace,
                          requirement_enabled)
from runtime import OwnedChildren, step, terminate

CONTAINER_RECORD = "container.json"
TRUST_CA = "/trust/ca.pem"
BROWSER_DISPLAY = "/browser-display"
PROXY_URL = "http://127.0.0.1:18080"
# The container has --network=none, so loopback names only reach processes inside the sandbox.
LOOPBACK = "localhost,.localhost,127.0.0.1,::1,[::1]"
# Guest-side SHA-256 verifier of the host-delivered unlock key: a second key can never silently rekey a home.
KEYRING_VERIFIER = "keyring-unlock.sha256.json"
PROXY_SOCKET = "proxy.sock"


def closure(program, run=subprocess.run):
    path = Path(program).resolve(strict=True)
    if not str(path).startswith("/nix/store/"):
        raise ValueError(f"Expected a Nix executable: {path}")
    root = "/" + "/".join(path.parts[1:4])
    result = run(["nix-store", "--query", "--requisites", root],
                 check=True, text=True, capture_output=True, timeout=120)
    return result.stdout.splitlines()


@dataclass(frozen=True)
class ProxyEndpoint:
    """Where this container's whitelist gateway socket and public CA live; the gateway's owner stays outside."""
    guest_socket_path: Path
    guest_public_ca_path: Path

    def verify(self, timeout=2):
        """Require an externally owned endpoint to be exactly the mountable socket and a live forward.

        A dead SSH reverse forward still accepts and then closes at once; a live gateway waits for the request.
        """
        path = Path(self.guest_socket_path)
        # session.py relays the fixed /network/proxy.sock; the whole parent directory is mounted.
        if path.name != PROXY_SOCKET or {entry.name for entry in path.parent.iterdir()} != {PROXY_SOCKET}:
            raise ValueError(f"Website gateway directory {path.parent} must contain only {PROXY_SOCKET}")
        metadata = path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("Website gateway endpoint must be a socket created by this user's SSH forward")
        certificate = read_public_ca(self.guest_public_ca_path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(timeout)
            try:
                probe.connect(str(path))
                probe.settimeout(0.5)
                closed = probe.recv(1) == b""
            except TimeoutError:
                closed = False
            except OSError as error:
                raise RuntimeError("Website gateway forward is not connected") from error
        if closed:
            raise RuntimeError("Website gateway forward closed; the host gateway is not reachable")
        return certificate


class _BrowserRequest(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.display.serve(self.request)


class BrowserDisplay:
    """A second kiosk desktop that runs only while some sandbox browser holds a request connection."""

    def __init__(self, directory, spawn):
        self.directory = directory
        self.spawn = spawn
        self.process = None
        self.clients = 0
        self.closed = False
        self.lock = threading.Lock()
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / "request.sock"
        path.unlink(missing_ok=True)
        self.server = socketserver.ThreadingUnixStreamServer(str(path), _BrowserRequest)
        self.server.daemon_threads = True
        self.server.display = self
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def serve(self, connection):
        with self.lock:
            self.clients += 1
            ready = not self.closed
            try:
                if ready and (self.process is None or self.process.poll() is not None):
                    self.process = self.spawn(self.directory, "wayland-browser")
            except (OSError, RuntimeError, ValueError):
                ready = False
        try:
            if ready:
                connection.sendall(b"ready\n")
                # Any bytes are ignored; EOF means the browser (holding this socket) has exited.
                while connection.recv(4096):
                    continue
        except OSError:
            pass
        finally:
            with self.lock:
                self.clients -= 1
                if not self.clients:
                    terminate(self.process, 5)
                    self.process = None

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        (self.directory / "request.sock").unlink(missing_ok=True)
        with self.lock:
            self.closed = True
            terminate(self.process, 5)
            self.process = None


class ContainerBackend:
    """Starts and retires OMBP's rootless container. Runtime owns the lifecycle; only its worker calls start/stop."""

    name = "linux-container"

    def __init__(self, policy, host_files=None, external_network=False, displays=None):
        """`external_network`: the website gateway and keyring key belong to a host outside this machine (Mac VM).

        Each start then requires that host's ProxyEndpoint and unlock key; there is no local gateway, CA or key.
        `displays`: None runs nested Weston inside the host's Wayland session (Linux). The Mac VM passes
        vm_display.HeadlessDisplays: a headless compositor always (Tauri needs one), shown over VNC only when the
        desktop setting asks, software rendering only.
        """
        self.policy = policy
        self.host_files = host_files
        self.external_network = external_network
        self.displays = displays
        self.show_desktop = False
        self.display_failure = ""
        self.files = None
        self.process = None
        self.container = None
        self.gateway = None
        self.proxy = None
        self.engine = None
        self.browser_trust = None
        self.browser_display = None
        self.fs_thread = None
        self.fs_error = None
        self.mount = policy.directory / "access"
        self.log = None
        self.desktop_process = None
        self.children = OwnedChildren()
        self.installed_profile = None
        manifest = policy.directory / "requirements.json"
        self.requirements = json.loads(manifest.read_text()) if manifest.exists() else [
            {"id": key, "label": label, "path": path, "kind": "folder"} for key, label, path in FOLDERS]
        record = policy.directory / CONTAINER_RECORD
        if record.exists():
            name = json.loads(record.read_text())
            if not isinstance(name, str) or not name.startswith("ombp-start-") or not name[11:].isalnum():
                raise ValueError("Invalid owned-container record")
            inspected = subprocess.run(["podman", "container", "inspect", name], capture_output=True, text=True, timeout=30)
            if inspected.returncode == 0:
                labels = json.loads(inspected.stdout)[0]["Config"]["Labels"]
                if labels.get("app") != "ombp-start":
                    raise RuntimeError("Recorded container no longer belongs to this launcher")
            self.container = name
        # Retire whatever an earlier launcher left: its container, FUSE mount and proxy socket.
        self.stop()
        socket = policy.directory / "network/socket/proxy.sock"
        if not external_network and socket.is_socket():
            socket.unlink()

    def requirements_status(self, installation=None):
        """Requirement rows; `installation` is the admitted launch's captured choice, else desired policy applies."""
        snapshot = self.policy.snapshot()
        installed = (installation or snapshot)["installed_mode"]
        labels = {key: (label, path) for key, label, path in FOLDERS}
        rows = []
        for item in self.requirements:
            key = "omp-copy" if item["id"] == "host-omp" else item["id"]
            row = {**item, "id": key}
            if key in labels:
                row.update(label=labels[key][0], path=labels[key][1])
            rows.append({**row, "enabled": requirement_enabled(row, installed, snapshot["disabled_requirements"])})
        return rows

    def start(self, executable, desktop, gpu, source, agent, log, children, *, installation, git_discovery_home,
              proxy=None, workspace=None, keyring_password=None):
        """Start the container and return its podman client process; every child is owned by `children`.

        `installation` is the launch's captured {installed_mode, selected_packages}; `git_discovery_home` is the
        user's home as mirrored under /host (repository-discovery ceiling, not a grant). Local mode runs its own
        website gateway. External mode takes this run's `proxy` endpoint and the host's `keyring_password`;
        `workspace` replaces the Linux {host_workspace, container_workspace} mapping.
        """
        if self.displays is not None and gpu != "none":
            raise ValueError("GPU passthrough is not available in the macOS Linux VM; choose Software rendering")
        if self.external_network != (proxy is not None) or self.external_network != (keyring_password is not None):
            raise ValueError("Isolated network endpoint and keyring key must both come from the host gateway owner"
                             if self.external_network else
                             "This backend owns its website gateway and keyring key")
        self.log = log
        self.children = children
        self.display_failure = ""
        self._container_start(executable, desktop, gpu, source, agent,
                              workspace or {"host_workspace": HOST_WORKSPACE, "container_workspace": CONTAINER_WORKSPACE},
                              installation, git_discovery_home, proxy, keyring_password)
        return self.process

    def exit_error(self, code):
        """Closing the nested desktop window (for example Super+Q) ends OMBP's display: a stop, not a crash."""
        if self.display_failure:
            return f"{self.display_failure}; see {self.policy.directory / 'launch.log'}"
        desktop = self.desktop_process
        if code and desktop is not None:
            try:
                if desktop.wait(timeout=2) == 0:
                    return ""
            except subprocess.TimeoutExpired:
                pass
            # A headless VM display reports why it failed (compositor or VNC server death).
            if getattr(desktop, "failure", ""):
                return f"{desktop.failure}; see {self.policy.directory / 'launch.log'}"
        return f"Process exited {code}; see {self.policy.directory / 'launch.log'}" if code else ""

    def _workspace_mount(self, snapshot, workspace):
        """(gateway source, container target) for a granted workspace, after checking its host directory.

        Grants name the canonical host path; the container keeps OMBP's fixed workspace path. With an external
        host the directory lives on that host, which prepared it; access still passes its revocable broker.
        """
        host_workspace = workspace["host_workspace"]
        if not any(item["path"] == host_workspace for item in snapshot["folders"]):
            return None
        if not self.external_network:
            prepare_workspace(Path(host_workspace))
        return self.mount / "host" / host_workspace.lstrip("/"), workspace["container_workspace"]

    def _installation_output(self, argv, cwd=None):
        """One owned installation step's stdout (stderr goes to launch.log); Stop ends it without waiting."""
        result = self.children.run(list(argv), timeout=None, cwd=cwd, stdout=subprocess.PIPE, stderr=self.log,
                                   text=True, start_new_session=True)
        if result.returncode:
            raise RuntimeError(f"Container installation step {Path(argv[0]).name} failed; "
                               f"see {self.policy.directory / 'launch.log'}")
        return result.stdout

    def _bundles(self, executable, gpu, source, agent, installation):
        """Program bundles; installed mode first realizes the selection and publishes its private generation."""
        resolve = lambda path: closure(path, self.children.run)
        if not installation["installed_mode"]:
            return bundles(executable, gpu, resolve)
        step(self.log, "Installing selected packages into container")
        agent_cli, selected = build_packages(installation["selected_packages"], agent, source,
                                             self._installation_output, self.children.check)
        base = bundles(executable, gpu, resolve, selected=selected, agent_cli=agent_cli)
        self.installed_profile = install_profile(self.policy.directory, base, self._installation_output,
                                                 self.children.check)
        return base

    def _container_start(self, executable, desktop, gpu, source, agent, workspace, installation, git_discovery_home,
                         proxy=None, keyring_password=None):
        info = json.loads(self.children.run(["podman", "info", "--format", "json"],
                                            check=True, text=True, capture_output=True, timeout=30).stdout)
        if not info["host"]["security"]["rootless"] or info["host"].get("serviceIsRemote"):
            raise ValueError("Only local rootless Podman is supported")
        python = os.environ.get("START_APP_PYTHON", sys.executable)
        dbus = os.environ.get("START_APP_DBUS", shutil.which("dbus-run-session"))
        keyring = os.environ.get("START_APP_KEYRING", shutil.which("gnome-keyring-daemon"))
        shell = os.environ.get("START_APP_SHELL")
        coreutils = os.environ.get("START_APP_COREUTILS")
        fonts = os.environ.get("START_APP_FONTCONFIG")
        if not all((dbus, keyring, shell, coreutils, fonts)):
            raise ValueError("Start through the supplied Nix environment for container runtime support")
        installed = installation["installed_mode"]
        base = self._bundles(executable, gpu, source, agent, installation)
        self.requirements = [
            {"id": key, "label": item["label"], "path": item["path"], "kind": "program",
             "programs": sorted({Path(program).name for program in item["programs"]})}
            for key, item in base.items()
        ] + [{"id": key, "label": label, "path": path, "kind": "folder"} for key, label, path in FOLDERS]
        if desktop or self.displays is not None:
            self.requirements.append({"id": "desktop-socket", "label": "Isolated desktop socket",
                                      "path": DISPLAY_SOCKET, "kind": "folder"})
        self.policy.save("requirements.json", self.requirements)
        mesa = os.environ.get("START_APP_MESA")
        snapshot = self.policy.snapshot()
        disabled = snapshot["disabled_requirements"]
        if "sandbox-home" in disabled:
            raise ValueError("Restore 'Private OMBP home' to use the private OMP copy")
        if self.displays is not None and "desktop-socket" in disabled:
            raise ValueError("OMBP needs its isolated desktop socket in the macOS Linux VM; restore "
                             "'Isolated desktop socket' under Required private folders")
        workspace_mount = self._workspace_mount(snapshot, workspace)
        password = self._keyring_password(keyring_password)
        if proxy is not None:
            # Externally owned: verify this run's forward is live before anything is mounted from it.
            if "network-socket" not in disabled:
                proxy.verify()
            elif "proxy-ca" not in disabled:
                read_public_ca(proxy.guest_public_ca_path)
        # Installed programs are private read-only copies; only host folders pass the revocable gateway.
        self._access_start({} if installed else base)
        if proxy is None:
            self.gateway = NetworkGateway(self.policy, self.policy.directory / "network")
            self.gateway.start()
            proxy = ProxyEndpoint(Path(self.gateway.socket_path), Path(self.gateway.ca_path))
        self.proxy = proxy
        root = self._rootfs(shell, coreutils)
        if not self.external_network:
            self._copy_omp()
        home = self.policy.directory / "home"
        home.mkdir(exist_ok=True, mode=0o700)
        browser = base.get("package-chromium" if installed else "tool-chrome")
        if browser and "sandbox-home" not in disabled and "proxy-ca" not in disabled:
            self._browser_trust_start(home)
        self.container = f"ombp-start-{uuid.uuid4().hex[:12]}"
        # Leave container root unmapped: crun then sets up FUSE mounts as their host owner.
        self.policy.save(CONTAINER_RECORD, self.container)
        args = ["podman", "run", "--rm", "--interactive", "--name", self.container, "--label", "app=ombp-start",
                "--http-proxy=false", "--hostname=ombp-sandbox",
                "--network=none", f"--uidmap={os.getuid()}:0:1", f"--gidmap={os.getgid()}:0:1",
                f"--user={os.getuid()}:{os.getgid()}",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only", "--read-only-tmpfs=false",
                # Podman's default seccomp profile blocks Chrome's user-namespace zygote sandbox.
                "--security-opt=seccomp=unconfined",
                "--pid=private", "--ipc=private", "--pids-limit=4096", "--init",
                "--workdir=/home/sandbox"]
        if "sandbox-tmp" not in disabled:
            args.append("--tmpfs=/tmp:rw,nosuid,nodev,notmpcopyup")
        if "sandbox-run" not in disabled:
            args.append("--tmpfs=/run:rw,nosuid,nodev,mode=1777,notmpcopyup")

        self._mount_resources(args, home, disabled)
        if workspace_mount:
            # A real mount keeps OMBP's canonical paths unchanged; access still passes the revocable gateway.
            self._mount(args, *workspace_mount, True)
        env = {"HOME": "/home/sandbox", "USER": "sandbox", "LOGNAME": "sandbox",
               "XDG_RUNTIME_DIR": "/run/ombp", "XDG_CONFIG_HOME": "/home/sandbox/.config",
               "PATH": ":".join(("/installed-programs" if installed else "/allowed-programs",
                                 str(Path(python).parent), str(Path(shell).parent),
                                 coreutils, str(Path(dbus).parent), str(Path(keyring).parent))),
               "HTTP_PROXY": PROXY_URL, "HTTPS_PROXY": PROXY_URL,
               "ALL_PROXY": PROXY_URL, "NO_PROXY": LOOPBACK,
               "http_proxy": PROXY_URL, "https_proxy": PROXY_URL,
               "all_proxy": PROXY_URL, "no_proxy": LOOPBACK, "NODE_USE_ENV_PROXY": "1",
               "SSL_CERT_FILE": TRUST_CA, "NODE_EXTRA_CA_CERTS": TRUST_CA,
               "REQUESTS_CA_BUNDLE": TRUST_CA, "CURL_CA_BUNDLE": TRUST_CA,
               "OMBP_GIT_DISCOVERY_HOME": git_discovery_home,
               "START_APP_KEYRING": keyring, "SHELL": shell, "FONTCONFIG_FILE": fonts,
               "GDK_BACKEND": "wayland", "NIXOS_OZONE_WL": "1"}
        env.update(self._program_environment(installed, agent, browser, base))
        if "sonar-engine" not in disabled:
            sonar_port = seed_client(home)
            self.engine = EngineGateway(self.policy, self.policy.directory / "engine",
                                        pinned_images(source), sonar_port, self.log).start()
            self._mount(args, self.engine.api_dir, "/engine")
            env["START_APP_SONAR_PORT"] = str(sonar_port)
        if (desktop or self.displays is not None) and "desktop-socket" not in disabled:
            self.show_desktop = desktop
            socket = self._desktop_start()
            self._mount(args, socket, DISPLAY_SOCKET)
            env["WAYLAND_DISPLAY"] = DISPLAY_SOCKET
            env["XDG_SESSION_TYPE"] = "wayland"
            # The OMBP compositor never depends on a browser; the browser display exists only for one.
            if browser:
                self.browser_display = BrowserDisplay(self.policy.directory / "browser-display", self._display)
                self._mount(args, self.browser_display.directory, BROWSER_DISPLAY)
        self._gpu_access(args, env, gpu, mesa)
        for key, value in env.items():
            args.extend(["--env", f"{key}={value}"])
        args.extend(["--rootfs", str(root), dbus, "--config-file=/etc/session.conf", "--",
                     python, "/launcher/session.py", executable])
        step(self.log, "Starting container")
        self.process = self.children.popen(args, stdin=subprocess.PIPE, stdout=self.log, stderr=self.log,
                                           start_new_session=True)
        with self.process.stdin as stream:
            stream.write((password + "\n").encode())
        if self.displays is not None and self.desktop_process is not None:
            # Running means a live OMBP with a mapped window, not merely a spawned container.
            step(self.log, "Waiting for OMBP window")
            self.desktop_process.wait_mapped(self.process)

    @staticmethod
    def _program_environment(installed, agent, browser, base):
        env = {"OMP_BIN": f"/installed-programs/{agent}" if installed else "/launcher/omp", "OMBP_AGENT": agent}
        if installed and agent == "omsp":
            env["OMSP_CONFIG_DIR"] = ".omp"
        if installed and "package-js-debug-adapter" in base:
            env["JS_DEBUG_DAP_SERVER"] = str(Path(base["package-js-debug-adapter"]["path"])
                                           / "share/ombp/dapDebugServer.js")
        if browser:
            commands = browser["programs"]
            env["START_APP_BROWSER"] = next((path for path in commands if Path(path).name == "google-chrome-stable"),
                                            commands[0])
        return env

    @staticmethod
    def _mount(args, source, target, writable=False):
        # Podman --mount is comma-delimited; rejecting commas avoids option injection.
        if "," in str(source) or ":" in str(source):
            raise ValueError("Mount paths cannot contain commas or colons")
        args.extend(["--volume", f"{source}:{target}:{'rw' if writable else 'ro'}"])

    def _mount_resources(self, args, home, disabled):
        if self.installed_profile:
            self._mount(args, self.installed_profile / "store", "/nix/store")
            self._mount(args, self.installed_profile / "programs", "/installed-programs")
        for key, source, target, writable in (
                ("nix-store", self.mount / "store", "/nix/store", False),
                ("sandbox-home", home, "/home/sandbox", True),
                ("launcher-files", Path(__file__).parent.resolve(), "/launcher", False),
                ("network-socket", self.proxy.guest_socket_path.parent, "/network", False),
                ("proxy-ca", self.proxy.guest_public_ca_path, TRUST_CA, False)):
            if key not in disabled and not (key == "nix-store" and self.installed_profile):
                self._mount(args, source, target, writable)
        if self.browser_trust:
            # Chrome uses NSS_InitReadWrite and silently drops local trust on a read-only database.
            self._mount(args, Path(self.browser_trust.name) / ".pki", "/home/sandbox/.pki", True)
        self._mount(args, self.mount / "host", "/host", True)
        if not self.installed_profile:
            self._mount(args, self.mount / "programs", "/allowed-programs")

    def _copy_omp(self):
        self.children.check()
        state = self.policy.directory
        pending = state / "omp-recopy.json"
        report = copy_status(state)
        request_id = read_copy_request(state)
        if report["copied"] and (request_id is None or report.get("request_id") == request_id):
            if request_id is not None:
                pending.unlink()
            return
        source = Path.home() / ".omp"
        resolved = source.resolve()
        if resolved.is_relative_to(state) or state.is_relative_to(resolved):
            raise ValueError("~/.omp overlaps launcher state; move launcher state outside ~/.omp")
        report = copy_once(source, state, replace=request_id is not None, request_id=request_id,
                           check=self.children.check, progress=lambda message: step(self.log, message))
        pending.unlink(missing_ok=True)
        step(self.log, f"Private OMP copy: {json.dumps(report, sort_keys=True)}")

    def _browser_trust_start(self, home):
        certutil = os.environ.get("START_APP_CERTUTIL")
        if not certutil:
            raise ValueError("Start through the supplied Nix environment for private browser CA trust")
        descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                os.mkdir(".pki", mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            target = os.open(".pki", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(target)
        finally:
            os.close(descriptor)
        # Never let host NSS load sandbox-authored PKCS#11 modules or database files.
        self.browser_trust = tempfile.TemporaryDirectory(prefix="browser-trust-", dir=self.policy.directory)
        scratch = Path(self.browser_trust.name)
        database = scratch / ".pki/nssdb"
        database.mkdir(parents=True, mode=0o700)
        environment = {"HOME": str(scratch), "PATH": os.defpath}
        for command in (
                ["-N", "--empty-password", "-d", f"sql:{database}"],
                ["-A", "-n", "OMBP sandbox proxy CA", "-t", "C,,",
                 "-i", str(self.proxy.guest_public_ca_path), "-d", f"sql:{database}"]):
            try:
                self.children.run([certutil, *command], env=environment, cwd=scratch,
                                  stdout=self.log, stderr=self.log, check=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as error:
                raise RuntimeError("Could not initialize private browser CA trust; see launch.log") from error
        # NSS persists configdir in its module configuration; relocate only our fresh trusted file.
        modules = database / "pkcs11.txt"
        modules.write_text(modules.read_text().replace(str(database), "/home/sandbox/.pki/nssdb"))

    def _private_home_used(self):
        home = self.policy.directory / "home"
        return home.is_symlink() or (home.exists() and (not home.is_dir() or any(home.iterdir())))

    def _keyring_password(self, delivered=None):
        if self.external_network:
            return self._delivered_keyring_password(delivered)
        path = self.policy.directory / KEYRING_UNLOCK
        if not path.exists() and not path.is_symlink():
            if self._private_home_used():
                raise ValueError("Existing private home has no keyring unlock key; restore its matching key or use a new state directory")
            self.policy.save(KEYRING_UNLOCK, new_keyring_unlock())
        return read_keyring_unlock(path)

    def _delivered_keyring_password(self, password):
        """The host-held key, accepted only if it is the one this private home was first unlocked with."""
        if not valid_keyring_unlock(password):
            raise ValueError("Invalid private keyring unlock key")
        digest = hashlib.sha256(password.encode()).hexdigest()
        path = self.policy.directory / KEYRING_VERIFIER
        if not path.exists() and not path.is_symlink():
            if self._private_home_used():
                raise ValueError("Existing private home has no keyring unlock key; restore its matching key or use a new state directory")
            self.policy.save(KEYRING_VERIFIER, digest)
        saved = read_private_json(path, "Private keyring key verifier")
        if not isinstance(saved, str) or not secrets.compare_digest(saved, digest):
            raise ValueError("The host keyring unlock key does not match this private home; restore the host's "
                             f"{KEYRING_UNLOCK} or use a new state directory")
        return password

    def _access_start(self, base):
        from fuse import FUSE
        self.mount.mkdir(exist_ok=True)
        self.fs_error = None
        files = self.host_files
        if files is None:
            # A host-file gateway this backend created is retired with its run; an injected one stays its owner's.
            files = self.files = HostFiles(self.policy)
        fs = AccessFS(self.policy, base, closure, files)

        def mount_fs():
            try:
                FUSE(fs, str(self.mount), foreground=True, nothreads=False, allow_other=False,
                     raw_fi=True, attr_timeout=0, entry_timeout=0, negative_timeout=0)
            except Exception as error:
                self.fs_error = error
        self.fs_thread = threading.Thread(target=mount_fs, daemon=True)
        self.fs_thread.start()
        deadline = time.monotonic() + 10
        while not os.path.ismount(self.mount):
            if self.fs_error:
                raise RuntimeError(f"FUSE mount failed: {self.fs_error}")
            if time.monotonic() >= deadline:
                raise RuntimeError("FUSE mount did not become ready; check /dev/fuse and fusermount")
            time.sleep(0.05)

    def _rootfs(self, shell, coreutils):
        root = self.policy.directory / "rootfs"
        for directory in ("etc", "nix/store", "host", "allowed-programs", "installed-programs", "launcher", "network",
                          "engine", "trust", "home/sandbox", "tmp", "run", "proc", "dev"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / "etc/passwd").write_text(f"sandbox:x:{os.getuid()}:{os.getgid()}:Sandbox:/home/sandbox:/bin/sh\n")
        (root / "etc/group").write_text(f"sandbox:x:{os.getgid()}:\n")
        (root / "etc/nsswitch.conf").write_text("hosts: files dns\n")
        machine_id = root / "etc/machine-id"
        if not re.fullmatch(r"[0-9a-f]{32}\n?", machine_id.read_text() if machine_id.is_file() else ""):
            # D-Bus/GLib tools and Chrome need one; random per state, never the host's.
            machine_id.write_text(secrets.token_hex(16) + "\n")
        (root / "etc/session.conf").write_text(
            '<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth>'
            '<policy context="default"><allow send_destination="*"/><allow receive_sender="*"/>'
            '<allow own="*"/></policy></busconfig>')
        for directory in ("bin", "usr/bin", "display", "browser-display", "var"):
            (root / directory).mkdir(exist_ok=True, parents=True)
        # Engine subprocesses discard TMPDIR; their default /var/tmp must reach private writable scratch.
        temporary = root / "var/tmp"
        if temporary.is_dir() and not temporary.is_symlink():
            temporary.rmdir()
        for target, source in (("bin/sh", shell), ("bin/bash", shell),
                               ("usr/bin/env", coreutils + "/env"), ("var/tmp", "../tmp")):
            link = root / target
            link.unlink(missing_ok=True)
            link.symlink_to(source)
        return root

    @staticmethod
    def _gpu_access(args, env, gpu, mesa):
        if gpu in ("none", "amd"):
            if not mesa:
                raise ValueError("Start through the supplied Nix environment for Mesa graphics support")
            # libglvnd cannot discover drivers in the private store through the host's /run/opengl-driver.
            # WebKit creates an EGL display when a page first uses WebGL, even with software rendering.
            env["__EGL_VENDOR_LIBRARY_FILENAMES"] = f"{mesa}/share/glvnd/egl_vendor.d/50_mesa.json"
            env["LIBGL_DRIVERS_PATH"] = f"{mesa}/lib/dri"
        if gpu == "none":
            env["LIBGL_ALWAYS_SOFTWARE"] = "1"
            env["GALLIUM_DRIVER"] = "llvmpipe"
        if gpu == "amd":
            devices = sorted(Path("/dev/dri").glob("renderD*"))
            if not devices:
                raise ValueError("No AMD render device available")
            for device in devices:
                args.extend(["--device", str(device)])
            if Path("/dev/kfd").exists():
                args.extend(["--device", "/dev/kfd"])
            args.extend(["--group-add=keep-groups"])
            # Mesa discovery is shared with software rendering above.
        elif gpu == "nvidia":
            args.extend(["--device=nvidia.com/gpu=all", "--group-add=keep-groups"])

    def _desktop_start(self):
        directory = self.policy.directory / "display"
        self.desktop_process = self._display(directory, "wayland-ombp")
        return directory / "wayland-ombp"

    def _display(self, directory, name):
        """A ready display serving `directory/name`: nested Weston on Linux, or the VM's headless compositor."""
        if self.displays is None:
            return self._weston(directory, name)
        return self.displays.start("ombp" if name == "wayland-ombp" else "browser", directory, name,
                                   self.show_desktop, self.children, self.log, self._display_ended)

    def _display_ended(self, display):
        """Closing OMBP's last window, or losing either display unexpectedly, ends the owned workload."""
        if display.failure:
            self.display_failure = display.failure
        process = self.process
        if (display is self.desktop_process or display.failure) and process is not None and process.poll() is None:
            process.terminate()

    def _weston(self, directory, name):
        """Start a nested kiosk desktop serving `directory/name`; return its process once the socket exists."""
        display = os.environ.get("WAYLAND_DISPLAY", "")
        host_runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/nonexistent"))
        host_socket = host_runtime / display
        weston = os.environ.get("START_APP_WESTON")
        if not weston or not display or not host_socket.is_socket():
            raise ValueError("Nested desktop requires the Nix launcher and a local Wayland session")
        directory.mkdir(mode=0o700, exist_ok=True)
        socket = directory / name
        socket.unlink(missing_ok=True)
        env = {key: os.environ[key] for key in ("PATH", "LANG", "LOCALE_ARCHIVE") if key in os.environ}
        env.update(HOME=str(directory), XDG_RUNTIME_DIR=str(directory), WAYLAND_DISPLAY=str(host_socket))
        if name == "wayland-browser":
            # OMBP stays borderless; the kiosk patch maximizes the browser and, independently, Zenity pickers.
            env["OMBP_KIOSK_MAXIMIZE"] = "1"
        process = self.children.popen(
            [sys.executable, str(Path(__file__).parent / "desktop.py"), str(os.getpid()), weston,
             "--backend=wayland", "--renderer=pixman", "--shell=kiosk-shell.so",
             f"--socket={name}", "--width=1440", "--height=900", "--idle-time=0", "--no-config"],
            env=env, stdout=self.log, stderr=self.log, start_new_session=True)
        deadline = time.monotonic() + 15
        while not socket.is_socket():
            if process.poll() is not None or time.monotonic() >= deadline:
                terminate(process, 5)
                raise RuntimeError("Nested desktop did not start; inspect launch.log")
            time.sleep(0.05)
        return process

    def stop(self):
        container = self.container
        if container:
            self._remove_container(container, 10)
        terminate(self.process, 10)
        if container:
            # podman run can create the container after the first remove; retire it after the client exits.
            self._remove_container(container, 0)
            self.container = None
            (self.policy.directory / CONTAINER_RECORD).unlink(missing_ok=True)
        self.process = None
        self.installed_profile = None
        terminate(self.desktop_process, 5)
        self.desktop_process = None
        if self.browser_display:
            self.browser_display.stop()
            self.browser_display = None
        if self.gateway:
            self.gateway.stop()
            self.gateway = None
        self.proxy = None
        if self.engine:
            self.engine.stop()
            self.engine = None
        if self.browser_trust:
            self.browser_trust.cleanup()
            self.browser_trust = None
        if os.path.ismount(self.mount):
            helper = next((p for p in ("/usr/bin/fusermount3", "/usr/bin/fusermount") if Path(p).exists()), "fusermount")
            subprocess.run([helper, "-u", str(self.mount)], check=True, timeout=10, capture_output=True)
        if self.fs_thread:
            self.fs_thread.join(timeout=3)
            self.fs_thread = None
        if self.files:
            self.files.close_all()
            self.files = None
        self.log = None

    @staticmethod
    def _remove_container(name, timeout):
        result = subprocess.run(["podman", "rm", "--force", "--ignore", f"--time={timeout}", name],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 20)
        if result.returncode:
            raise RuntimeError("Failed to stop container: " + result.stderr.decode(errors="replace"))
