"""Host-owned live permissions. Never mount this state into the sandbox."""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from catalog import DEFAULT_WEBSITES
from network import allowed_by_policy, auto_approved, covering_site
from packages import DEFAULT_PACKAGES, validate_packages
from requirements import HOST_WORKSPACE, prepare_workspace

DENIED_HISTORY = "denied.json"
LAST_LAUNCH = "last-launch.json"
AUTO_APPROVE = {"enabled": True, "sites": ["anthropic.com", "chatgpt.com", "google.com"]}
SITE_OPTIONS = {"dependencies": {}, "all_dependencies": [], "header_dependencies": [], "exact_hosts": []}
# Next-launch installation choices; older saved settings get these too, keeping every existing grant.
# They are launch inputs, not live permissions, and are never part of saved launch settings.
# "default" leaves the isolated display's keyboard as it is; other values name an XKB layout for the VM viewer.
KEYBOARD_LAYOUTS = ("default", "dk")
INSTALLATION_DEFAULTS = {"installed_mode": True, "selected_packages": DEFAULT_PACKAGES,
                         "keyboard_layout": "default", "hide_language_server_denials": True}
# Random per-state key unlocking the sandbox's private Secret Service keyring; host state only, never mounted.
KEYRING_UNLOCK = "keyring-unlock.json"
_KEYRING_UNLOCK_VALUE = re.compile(r"[A-Za-z0-9_-]{64}")


def new_keyring_unlock():
    return secrets.token_urlsafe(48)


def valid_keyring_unlock(value):
    return isinstance(value, str) and _KEYRING_UNLOCK_VALUE.fullmatch(value) is not None


def read_private_json(path, what):
    """A small JSON value from an owner-only, non-symlink regular file (opened without following links)."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077 or metadata.st_size > 256):
            raise ValueError(f"{what} must be a private, owner-only regular file")
        return json.loads(os.read(descriptor, 257))
    finally:
        os.close(descriptor)


def read_keyring_unlock(path):
    password = read_private_json(path, "Private keyring unlock key")
    if not valid_keyring_unlock(password):
        raise ValueError("Invalid private keyring unlock key")
    return password


def origin(value):
    parsed = urlsplit(value.strip())
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("Use an http:// or https:// base URL without credentials")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            raise ValueError("Private and local network addresses are not allowed")
    except ValueError as error:
        if ":" in host or host.replace(".", "").isdigit():
            raise ValueError("Invalid or private network address") from error
    if host == "localhost" or host.endswith(".localhost") or any(c.isspace() for c in host):
        raise ValueError("Local or invalid host name")
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port and port != {"http": 80, "https": 443}[parsed.scheme] else ""
    return f"{parsed.scheme}://{host}{suffix}"


def nix_program(value):
    """Syntactic check of a selected program: an absolute, normalized path inside a Nix store entry."""
    if not isinstance(value, str) or "\x00" in value or len(value) > 4096:
        raise ValueError("Program must be an executable name or path")
    parts = value.split("/")
    if (not value.startswith("/nix/store/") or len(parts) < 4 or any(part in ("", ".", "..") for part in parts[1:])
            or re.fullmatch(r"[0-9a-z]{32}-[^/]+", parts[3]) is None):
        raise ValueError("Programs must be installed Nix executables (use their bin paths)")
    return value


def resolve_host_program(value_path):
    """A new program grant on a Linux host: its installed Nix store executable here."""
    if not isinstance(value_path, str):
        raise ValueError("Program must be an executable name or path")
    if "/" not in value_path:
        installed = shutil.which(value_path)
        if installed is None:
            raise ValueError(f"Program is not installed on the host: {value_path}")
        value_path = installed
    path = Path(value_path).expanduser().resolve(strict=True)
    if not str(path).startswith("/nix/store/") or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("Programs must be installed Nix executables (use their bin paths)")
    return str(path)



class Policy:
    def __init__(self, directory, program_resolver=resolve_host_program):
        requested = Path(directory).expanduser().absolute()
        if requested.is_symlink():
            raise ValueError("State directory must not be a symlink")
        self.directory = requested.resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.stat().st_uid != os.getuid():
            raise ValueError("State directory must be owned by you")
        self.directory.chmod(0o700)
        # Also the hash identity of the app-owned VM and of this state's transient socket directory.
        self.state_id = hashlib.sha256(str(self.directory).encode()).hexdigest()[:12]
        # Nix shells and custom TMPDIRs may exceed Darwin's sun_path limit.
        socket_root = Path("/tmp") if sys.platform == "darwin" else Path(tempfile.gettempdir())
        self.transient = socket_root.resolve() / f"ombp-start-{os.getuid()}-{self.state_id}"
        self.private_paths = (str(self.directory), str(Path(__file__).parent.resolve()),
                              str(Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}").resolve()),
                              str((Path.home() / ".local/share/ombp-lima").resolve()), str(self.transient))
        self.lock = threading.RLock()
        # New program grants are resolved where programs run (the macOS VM replaces this host resolver).
        self.program_resolver = program_resolver
        self._listeners = []
        self.path = self.directory / "policy.json"
        self.data = {"folders": [], "programs": [], "websites": [], "credential_origins": [],
                     "internet": True, "allow_all_network": False, "disabled_requirements": [],
                     "folder_write_default": False, "auto_start": None, **copy.deepcopy(INSTALLATION_DEFAULTS),
                     **copy.deepcopy(SITE_OPTIONS), "auto_approve": copy.deepcopy(AUTO_APPROVE)}
        self.history = []
        self.history_error = ""
        self.history_generation = 0
        if self.path.exists():
            self.data = self._validated(json.loads(self.path.read_text()))
        if not (self.directory / "defaults.json").exists():
            defaults = self.snapshot()
            defaults["websites"] = sorted(set(defaults["websites"]) | set(DEFAULT_WEBSITES))
            if not any(item["path"] == HOST_WORKSPACE for item in defaults["folders"]):
                defaults["folders"].append({"path": HOST_WORKSPACE, "write": True})
            self.replace(defaults)
            self.save("defaults.json", 1)
        history_path = self.directory / DENIED_HISTORY
        if history_path.exists():
            self.history = json.loads(history_path.read_text())[-500:]
            self._prune_allowed()

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.data)

    def installation(self):
        """A fresh copy of the next isolated launch's installation choice; an admitted launch keeps its own."""
        with self.lock:
            return {"installed_mode": self.data["installed_mode"],
                    "selected_packages": list(self.data["selected_packages"]),
                    "keyboard_layout": self.data["keyboard_layout"]}

    def save(self, name, value):
        temporary = self.directory / f".{name}.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.directory / name)

    def transient_directory(self):
        """This state's short, owner-only directory for transient Unix sockets; protected, never granted.

        Darwin uses the canonical /tmp parent, not a potentially long build-specific TMPDIR.
        """
        try:
            self.transient.mkdir(mode=0o700)
        except FileExistsError:
            pass
        fd = os.open(self.transient, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(fd)
            if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ValueError(f"{self.transient} must be a private directory owned by you; remove it and retry")
        finally:
            os.close(fd)
        return self.transient

    def last_launch(self):
        """The settings of the latest launch that reached running, or None."""
        path = self.directory / LAST_LAUNCH
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text())
            if not isinstance(value, dict):
                raise ValueError("not an object")
            return self._auto_start(value)
        except ValueError as error:
            raise ValueError(f"Invalid saved launch settings in {path}; remove that file to continue") from error

    def record_launch(self, settings):
        """Remember a launch that reached running; enabled automatic start follows it.

        Automatic start is never switched from isolated to unrestricted this way: that needs its own confirmation.
        """
        if not isinstance(settings, dict):
            raise ValueError("Invalid launch settings")
        settings = self._auto_start(settings)
        with self.lock:
            self.save(LAST_LAUNCH, settings)
            current = self.data["auto_start"]
            if current is not None and current != settings and (
                    settings["mode"] != "normal" or current["mode"] == "normal"):
                data = copy.deepcopy(self.data)
                data["auto_start"] = settings
                self.replace(data)

    def _folder(self, item):
        if not isinstance(item, dict) or set(item) != {"path", "write"} or not isinstance(item["write"], bool):
            raise ValueError("Folder needs path and boolean write permission")
        path = Path(item["path"]).expanduser()
        if not path.is_absolute() or (path.exists() and not path.is_dir()) or path.resolve() != path:
            raise ValueError("Folder must be an absolute directory path without symlinks")
        if path == Path("/") or any(path.is_relative_to(p) for p in ("/proc", "/sys", "/dev", "/run", "/nix")):
            raise ValueError("System trees cannot be shared as folders")
        if any(path.is_relative_to(p) for p in self.private_paths):
            raise ValueError("Launcher state, code and runtime sockets cannot be shared")
        if str(path) == HOST_WORKSPACE:
            prepare_workspace(path)
        return {"path": str(path), "write": item["write"]}

    def _program(self, value, known):
        """A selected program: unchanged ones are checked only syntactically, new ones through the resolver.

        `known` is None while loading saved permissions: nothing is resolved then (on macOS that would need the VM).
        """
        if known is None or value in known:
            return nix_program(value)
        return nix_program(self.program_resolver(value))

    def _validated(self, value, known=None):
        if not isinstance(value, dict):
            raise ValueError("Invalid permission fields")
        value = {"disabled_requirements": [], "allow_all_network": False, **copy.deepcopy(SITE_OPTIONS),
                 "auto_approve": copy.deepcopy(AUTO_APPROVE), "folder_write_default": False, "auto_start": None,
                 **copy.deepcopy(INSTALLATION_DEFAULTS), **value}
        if set(value) != set(self.data):
            raise ValueError("Invalid permission fields")
        if not all(isinstance(value[key], bool) for key in (
                "internet", "allow_all_network", "folder_write_default", "installed_mode",
                "hide_language_server_denials")):
            raise ValueError("Switches must be booleans")
        if value["keyboard_layout"] not in KEYBOARD_LAYOUTS:
            raise ValueError("Unknown keyboard layout")
        if any(not isinstance(value[key], list) for key in ("folders", "programs", "websites", "credential_origins")):
            raise ValueError("Permission lists are required")
        folders = [self._folder(item) for item in value["folders"]]
        programs = {self._program(path, known) for path in value["programs"]}
        if len({Path(path).name for path in programs}) != len(programs):
            raise ValueError("Selected programs must have distinct executable names")
        websites = sorted({origin(url) for url in value["websites"]})
        credentials = sorted({origin(url) for url in value["credential_origins"]})
        if not set(credentials) <= set(websites):
            raise ValueError("Credential origins must also be allowed websites")
        if any(not site.startswith("https://") for site in credentials):
            raise ValueError("Host Authorization injection requires HTTPS")
        disabled = value["disabled_requirements"]
        if not isinstance(disabled, list) or any(
                not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,79}", key) for key in disabled):
            raise ValueError("Invalid disabled runtime requirements")
        return {"folders": folders, "programs": sorted(programs),
                "websites": websites, "credential_origins": credentials, "internet": value["internet"],
                "allow_all_network": value["allow_all_network"], "folder_write_default": value["folder_write_default"],
                "auto_start": self._auto_start(value["auto_start"]),
                "installed_mode": value["installed_mode"],
                "selected_packages": validate_packages(value["selected_packages"]),
                "keyboard_layout": value["keyboard_layout"],
                "hide_language_server_denials": value["hide_language_server_denials"],
                "disabled_requirements": sorted(set(disabled)), **self._site_options(value, websites),
                "auto_approve": self._auto_approve(value["auto_approve"])}

    @staticmethod
    def _auto_start(value):
        """None, or the launch settings to start with whenever the launcher starts."""
        if value is None:
            return None
        if isinstance(value, dict):
            value = {"agent": "omp", **value}  # Settings saved before the agent choice existed.
        if (not isinstance(value, dict) or set(value) != {"source", "mode", "desktop", "gpu", "agent"}
                or not isinstance(value["source"], str) or not value["source"].strip()
                or value["mode"] not in ("container", "normal") or not isinstance(value["desktop"], bool)
                or value["gpu"] not in ("none", "amd", "nvidia") or value["agent"] not in ("omp", "omsp")):
            raise ValueError("Invalid automatic start settings")
        # Same resolution as Runtime.start, so ~ and relative checkouts keep working at the next launch.
        return {**value, "source": str(Path(value["source"]).expanduser().resolve())}

    @staticmethod
    def _site_options(value, websites):
        lists = ("all_dependencies", "header_dependencies", "exact_hosts")
        dependencies = value["dependencies"]
        if (not isinstance(dependencies, dict) or any(not isinstance(origins, list) for origins in dependencies.values())
                or any(not isinstance(value[key], list) for key in lists)):
            raise ValueError("Invalid website options")
        options = {key: sorted({origin(site) for site in value[key]}) for key in lists}
        options["dependencies"] = {origin(site): sorted({origin(url) for url in origins})
                                   for site, origins in dependencies.items() if origins}
        if not set(options["dependencies"]).union(*(options[key] for key in lists)) <= set(websites):
            raise ValueError("Website options need their site to be allowed")
        return options

    @staticmethod
    def _auto_text(value):
        """A host fragment; full URLs from older settings keep only their host."""
        if not isinstance(value, str):
            raise ValueError("Auto-approve entries must be text")
        text = value.strip().lower()
        if "://" in text:
            text = urlsplit(text).hostname or ""
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", text):
            raise ValueError("Auto-approve entries are host text such as chatgpt.com or openai")
        return text

    @classmethod
    def _auto_approve(cls, value):
        if (not isinstance(value, dict) or set(value) != {"enabled", "sites"} or not isinstance(value["enabled"], bool)
                or not isinstance(value["sites"], list)):
            raise ValueError("Invalid auto-approve settings")
        return {"enabled": value["enabled"], "sites": sorted({cls._auto_text(site) for site in value["sites"]})}

    def replace(self, value):
        with self.lock:
            known = set(self.data["programs"])
        data = self._validated(value, known)
        with self.lock:
            self.save("policy.json", data)
            self.data = data
            self._prune_allowed()
            for listener in self._listeners:
                listener()

    def add_listener(self, listener):
        """Call `listener()` (quickly, without blocking) after every accepted permission change."""
        with self.lock:
            self._listeners.append(listener)

    def remember_website(self, origin_value):
        """List an auto-approved origin as an ordinary allowed website (subdomains on), once."""
        with self.lock:
            # Recheck under the lock: the user may have just turned auto-approve or internet off.
            if (not self.data["internet"] or covering_site(origin_value, self.data) is not None
                    or not auto_approved(origin_value, self.data)):
                return
            data = copy.deepcopy(self.data)
            data["websites"].append(origin_value)
            self.replace(data)

    def _prune_allowed(self):
        """Websites the current permissions allow are no longer "denied"; new denials still appear."""
        with self.lock:
            if not self.data["internet"]:
                return  # Offline, every website is still blocked.
            history = [row for row in self.history
                       if row["kind"] != "website" or not allowed_by_policy(self.data, row["target"])]
            if history == self.history:
                return
            self.history = history
            try:
                self.save(DENIED_HISTORY, history)
            except OSError as error:
                self.history_error = str(error)
            else:
                self.history_error = ""

    def deny(self, kind, target, reason, site=None):
        if kind not in ("folder", "program", "website"):
            return
        with self.lock:
            for row in self.history:
                if row["kind"] == kind and row["target"] == target and row.get("site") == site:
                    row.update(time=time.time(), count=row["count"] + 1, reason=str(reason)[:300])
                    break
            else:
                self.history.append({"kind": kind, "target": str(target)[:2048], "site": site,
                                     "reason": str(reason)[:300], "time": time.time(), "count": 1})
            self.history.sort(key=lambda row: row["time"])
            self.history = self.history[-500:]
            try:
                self.save(DENIED_HISTORY, self.history)
            except OSError as error:
                self.history_error = str(error)
            else:
                self.history_error = ""

    def events(self):
        with self.lock:
            return copy.deepcopy(list(reversed(self.history)))

    def clear_history(self):
        with self.lock:
            self.save(DENIED_HISTORY, [])
            self.history = []
            self.history_error = ""
            self.history_generation += 1

    def forget(self, items):
        """Drop history rows the user just approved; new attempts can appear again."""
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ValueError("Invalid history items")
        keys = {(item.get("kind"), item.get("target"), item.get("site")) for item in items}
        with self.lock:
            history = [row for row in self.history if (row["kind"], row["target"], row.get("site")) not in keys]
            self.save(DENIED_HISTORY, history)
            self.history = history
            self.history_error = ""
            self.history_generation += 1
