import contextlib
import errno
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
import unittest

if not sys.platform.startswith("linux"):
    # The Linux backend runs natively on Linux and inside the macOS runtime VM, never on the Mac host.
    raise unittest.SkipTest("Linux container backend")

from access_fs import AccessFS
from host_files import HostFiles
from linux_runtime import KEYRING_UNLOCK, KEYRING_VERIFIER, BrowserDisplay, ContainerBackend, ProxyEndpoint
from policy import Policy, new_keyring_unlock
from runtime import OwnedChildren


INSPECTION = {"installed_mode": False, "selected_packages": []}


def _until(condition, timeout=5):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError("Condition not reached in time")
        time.sleep(0.01)


class ContainerBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backend = ContainerBackend(Policy(self.root / "state"))
        self.addCleanup(self.backend.stop)

    def test_installed_mounts_keep_host_gateway_without_exposing_host_store(self):
        self.backend.proxy = ProxyEndpoint(self.root / "network/proxy.sock", self.root / "network/ca.pem")
        profile = self.root / "private-install"
        self.backend.installed_profile = profile
        args = []
        with patch.object(self.backend, "_host_omp", return_value=None):
            self.backend._mount_resources(args, self.root / "home", ["nix-store"])
        mounts = [args[i + 1] for i, value in enumerate(args) if value == "--volume"]
        self.assertIn(f"{profile}/store:/nix/store:ro", mounts)
        self.assertIn(f"{profile}/programs:/installed-programs:ro", mounts)
        self.assertIn(f"{self.backend.mount}/host:/host:rw", mounts)
        self.assertNotIn(f"{self.backend.mount}/store:/nix/store:ro", mounts)
        self.assertFalse(any(value.startswith("/nix/store:") for value in mounts))
        self.assertFalse(any(":/allowed-programs:" in value for value in mounts))
        self.backend.installed_profile = None
        args = []
        with patch.object(self.backend, "_host_omp", return_value=None):
            self.backend._mount_resources(args, self.root / "home", [])
        mounts = [args[i + 1] for i, value in enumerate(args) if value == "--volume"]
        self.assertIn(f"{self.backend.mount}/store:/nix/store:ro", mounts)
        self.assertIn(f"{self.backend.mount}/programs:/allowed-programs:ro", mounts)
        self.assertIn(f"{self.backend.mount}/host:/host:rw", mounts)

    def test_rootfs_preparation_does_not_delete_existing_temporary_data(self):
        temporary = self.backend.policy.directory / "rootfs/var/tmp"
        temporary.mkdir(parents=True)
        saved = temporary / "saved"
        saved.write_text("keep this data")
        with self.assertRaises(OSError):
            self.backend._rootfs("/bin/sh", "/bin")
        self.assertEqual(saved.read_text(), "keep this data")

    def test_closing_desktop_window_is_a_stop_but_app_crash_is_reported(self):
        def child(code, delay=0):
            return subprocess.Popen([sys.executable, "-c", f"import sys, time; time.sleep({delay}); sys.exit({code})"])

        # (desktop exit code or None while still running, expected error prefix; "" means no error)
        for desktop_code, expected in ((0, ""), (None, "Process exited 1"), (1, "Process exited 1")):
            with self.subTest(desktop_code=desktop_code):
                app = child(1)
                self.backend.process = app
                self.backend.desktop_process = child(0, 30) if desktop_code is None else child(desktop_code)
                error = self.backend.exit_error(app.wait())
                if expected:
                    self.assertTrue(error.startswith(expected), error)
                else:
                    self.assertEqual(error, "")
                self.backend.stop()
                self.assertIsNone(self.backend.process)
                self.assertIsNone(self.backend.desktop_process)

    def test_host_omp_bind_never_exposes_launcher_state(self):
        home = self.root / "home"
        (home / ".omp").mkdir(parents=True)
        alias = self.root / "alias"
        alias.symlink_to(home / ".omp", target_is_directory=True)
        with patch.dict(os.environ, {"HOME": str(home)}):
            self.assertEqual(self.backend._host_omp([]), (home / ".omp").resolve())
            self.assertIsNone(self.backend._host_omp(["host-omp"]))
            for state in (home / ".omp" / "ombp-start", alias / "state"):
                with self.subTest(state=state):
                    backend = ContainerBackend(Policy(state))
                    with self.assertRaisesRegex(ValueError, "overlaps protected launcher path"):
                        backend._host_omp([])

    def test_workspace_grant_uses_canonical_host_path_and_fixed_container_path(self):
        system_alias = self.root / "tmp-alias"
        system_alias.symlink_to(self.root, target_is_directory=True)
        host = str(system_alias.resolve() / "omp-manager")
        workspace = {"host_workspace": host, "container_workspace": "/tmp/omp-manager"}
        # A grant naming the alias or the container path is not the canonical host grant.
        for folders in ([], [{"path": str(system_alias / "omp-manager"), "write": True}],
                        [{"path": "/tmp/omp-manager", "write": True}] if host != "/tmp/omp-manager" else []):
            with self.subTest(folders=folders):
                self.assertIsNone(self.backend._workspace_mount({"folders": folders}, workspace))
        mount = self.backend._workspace_mount({"folders": [{"path": host, "write": True}]}, workspace)
        self.assertEqual(mount, (self.backend.mount / "host" / host.lstrip("/"), "/tmp/omp-manager"))
        self.assertEqual(stat.S_IMODE(Path(host).stat().st_mode), 0o700)
        args = []
        self.backend._mount(args, *mount, True)
        self.assertEqual(args, ["--volume", f"{self.backend.mount}/host{host}:/tmp/omp-manager:rw"])

    def test_symlinked_workspace_is_refused_before_mounting(self):
        target = self.root / "elsewhere"
        target.mkdir()
        host = self.root / "omp-manager"
        host.symlink_to(target, target_is_directory=True)
        workspace = {"host_workspace": str(host), "container_workspace": "/tmp/omp-manager"}
        with self.assertRaises(OSError):
            self.backend._workspace_mount({"folders": [{"path": str(host), "write": True}]}, workspace)
        self.assertEqual(list(target.iterdir()), [])


class PrivateKeyringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = Policy(self.root / "state")
        self.backend = ContainerBackend(self.policy)
        self.addCleanup(self.backend.stop)
        self.key = self.policy.directory / KEYRING_UNLOCK

    def filesystem(self, policy):
        filesystem = AccessFS(policy, {}, lambda _: [], HostFiles(policy))
        self.addCleanup(filesystem.destroy, "/")
        return filesystem

    def test_unlock_key_is_stable_private_and_separate_from_container_home(self):
        first = self.backend._keyring_password()
        home = self.policy.directory / "home"
        home.mkdir()
        (home / "saved-data").write_text("persistent private data")
        # Boolean comparisons keep generated unlock keys out of assertion output.
        self.assertTrue(secrets.compare_digest(first, ContainerBackend(self.policy)._keyring_password()),
                        "Private keyring key rotated")
        other = ContainerBackend(Policy(self.root / "other-state"))
        self.assertFalse(secrets.compare_digest(first, other._keyring_password()), "Different states share an unlock key")
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        self.assertFalse(self.key.is_relative_to(home))

    def test_broad_host_grant_cannot_read_unlock_key(self):
        self.backend._keyring_password()
        value = self.policy.snapshot()
        value["folders"] = [{"path": str(self.root), "write": True}]
        self.policy.replace(value)
        filesystem = self.filesystem(self.policy)
        with self.assertRaises(OSError) as denied:
            filesystem.open("/host" + str(self.key), os.O_RDONLY)
        self.assertEqual(denied.exception.errno, errno.EACCES)

    def test_symlinked_state_parent_cannot_expose_unlock_key(self):
        real = self.root / "real"
        real.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)
        policy = Policy(alias / "state")
        backend = ContainerBackend(policy)
        backend._keyring_password()
        (real / "shared").write_bytes(b"allowed data")
        value = policy.snapshot()
        value["folders"] = [{"path": str(real), "write": True}]
        policy.replace(value)
        filesystem = self.filesystem(policy)
        handle = filesystem.open("/host" + str(real / "shared"), os.O_RDONLY)
        try:
            self.assertEqual(filesystem.read("", 32, 0, handle), b"allowed data")
        finally:
            filesystem.release("", handle)
        with self.assertRaises(OSError) as denied:
            filesystem.open("/host" + str(real / "state" / KEYRING_UNLOCK), os.O_RDONLY)
        self.assertEqual(denied.exception.errno, errno.EACCES)

    def test_existing_private_home_is_never_rekeyed_without_its_key(self):
        home = self.policy.directory / "home"
        home.mkdir()
        saved = home / "encrypted-keyring"
        saved.write_bytes(b"existing encrypted data")
        with self.assertRaises(ValueError):
            self.backend._keyring_password()
        self.assertEqual(saved.read_bytes(), b"existing encrypted data")
        self.assertFalse(self.key.exists())

    def test_symlink_and_public_unlock_keys_are_rejected(self):
        outside = self.root / "outside-key"
        outside.write_text(json.dumps("f" * 64))
        outside.chmod(0o600)
        self.key.symlink_to(outside)
        with self.assertRaises((OSError, ValueError)):
            self.backend._keyring_password()
        self.key.unlink()
        self.key.write_text(json.dumps("f" * 64))
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            self.backend._keyring_password()
        self.key.chmod(0o600)
        self.assertEqual(self.backend._keyring_password(), "f" * 64)

    def test_malformed_unlock_key_is_not_replaced(self):
        self.key.write_text(json.dumps("invalid"))
        self.key.chmod(0o600)
        with self.assertRaises(ValueError):
            self.backend._keyring_password()
        self.assertEqual(json.loads(self.key.read_text()), "invalid")


class PrivateBrowserTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = Policy(self.root / "state")
        self.backend = ContainerBackend(self.policy)
        self.addCleanup(self.backend.stop)
        self.home = self.policy.directory / "home"
        self.home.mkdir()
        self.ca = self.policy.directory / "proxy-ca.pem"
        self.ca.write_text("first launcher CA")
        self.backend.proxy = ProxyEndpoint(self.root / "proxy.sock", self.ca)
        environment = patch.dict(os.environ, {"START_APP_CERTUTIL": "/nix/store/test-nss/bin/certutil",
                                             "LD_PRELOAD": "/untrusted.so"})
        environment.start()
        self.addCleanup(environment.stop)

    def certutil(self, command, **kwargs):
        database = Path(command[command.index("-d") + 1].removeprefix("sql:"))
        self.assertTrue(database.is_relative_to(self.policy.directory))
        self.assertFalse(database.is_relative_to(self.home))
        self.assertEqual(kwargs["env"], {"HOME": str(database.parent.parent), "PATH": os.defpath})
        self.assertEqual(Path(kwargs["cwd"]), database.parent.parent)
        self.assertTrue(kwargs["check"])
        if "-N" in command:
            self.assertIn("--empty-password", command)
            (database / "cert9.db").write_bytes(b"")
            (database / "key4.db").write_bytes(b"fresh key database")
            (database / "pkcs11.txt").write_text(f"parameters=configdir='sql:{database}'\n")
        else:
            self.assertEqual(command[1:6], ["-A", "-n", "OMBP sandbox proxy CA", "-t", "C,,"])
            self.assertEqual(command[command.index("-i") + 1], str(self.ca))
            (database / "cert9.db").write_bytes(self.ca.read_bytes())

    def commands(self, **kwargs):
        # certutil runs as an owned child of the launch, so Stop can reach it.
        return patch.object(self.backend.children, "run", **kwargs)

    def test_only_fresh_protected_database_is_opened_and_mounted_for_chrome(self):
        stored = self.home / ".pki/nssdb"
        stored.mkdir(parents=True)
        outside = self.root / "untrusted-module"
        outside.write_text("sandbox-authored module configuration")
        for name in ("cert9.db", "key4.db", "pkcs11.txt"):
            (stored / name).symlink_to(outside)
        with self.commands(side_effect=self.certutil) as commands:
            self.backend._browser_trust_start(self.home)
        self.assertEqual(commands.call_count, 2)
        private = Path(self.backend.browser_trust.name) / ".pki"
        self.assertEqual((private / "nssdb/cert9.db").read_bytes(), self.ca.read_bytes())
        self.assertEqual((private / "nssdb/pkcs11.txt").read_text(),
                         "parameters=configdir='sql:/home/sandbox/.pki/nssdb'\n")
        self.assertEqual(outside.read_text(), "sandbox-authored module configuration")
        self.assertTrue(all((stored / name).is_symlink() for name in ("cert9.db", "key4.db", "pkcs11.txt")))
        args = []
        self.backend._mount_resources(args, self.home, ["host-omp", "tool-chrome"])
        self.assertIn(f"{private}:/home/sandbox/.pki:rw", args)
        self.assertIn(f"{self.root}:/network:ro", args)
        self.assertIn(f"{self.ca}:/trust/ca.pem:ro", args)
        self.assertNotIn("/nix/store/test-nss/bin/certutil", args)

    def test_restart_regenerates_trust_without_stale_ca_or_changing_saved_database(self):
        stored = self.home / ".pki/nssdb"
        stored.mkdir(parents=True)
        (stored / "cert9.db").write_bytes(b"user's saved NSS database")
        with self.commands(side_effect=self.certutil):
            self.backend._browser_trust_start(self.home)
            first = Path(self.backend.browser_trust.name)
            proxy = self.backend.proxy
            self.backend.stop()
            self.assertFalse(first.exists())
            self.assertIsNone(self.backend.proxy)
            self.backend.proxy = proxy
            self.ca.write_text("rotated launcher CA")
            self.backend._browser_trust_start(self.home)
        database = Path(self.backend.browser_trust.name) / ".pki/nssdb"
        self.assertEqual((database / "cert9.db").read_bytes(), b"rotated launcher CA")
        self.assertEqual((stored / "cert9.db").read_bytes(), b"user's saved NSS database")

    def test_symlinked_mount_target_is_rejected_before_host_certutil_runs(self):
        for destination in (self.root, self.root / "missing"):
            with self.subTest(destination=destination):
                (self.home / ".pki").symlink_to(destination, target_is_directory=True)
                with self.commands() as commands:
                    with self.assertRaises(OSError):
                        self.backend._browser_trust_start(self.home)
                commands.assert_not_called()
                self.assertIsNone(self.backend.browser_trust)
                (self.home / ".pki").unlink()

    def test_symlinked_home_is_rejected_before_host_certutil_runs(self):
        alias = self.policy.directory / "home-alias"
        alias.symlink_to(self.home, target_is_directory=True)
        with self.commands() as commands:
            with self.assertRaises(OSError):
                self.backend._browser_trust_start(alias)
        commands.assert_not_called()
        self.assertFalse((self.home / ".pki").exists())

    def test_cleanup_never_reopens_or_follows_sandbox_mutated_database(self):
        outside = self.root / "outside"
        outside.mkdir()
        marker = outside / "keep"
        marker.write_text("host data")
        with self.commands(side_effect=self.certutil) as commands:
            self.backend._browser_trust_start(self.home)
            scratch = Path(self.backend.browser_trust.name)
            database = scratch / ".pki/nssdb"
            (database / "pkcs11.txt").write_text("library=/untrusted-host-module.so")
            (database / "cert9.db").unlink()
            (database / "cert9.db").symlink_to(marker)
            (database / "outside").symlink_to(outside, target_is_directory=True)
            self.backend.stop()
        self.assertEqual(commands.call_count, 2)
        self.assertFalse(scratch.exists())
        self.assertEqual(marker.read_text(), "host data")

    def test_certutil_failure_fails_closed_and_stop_cleans_scratch(self):
        with self.commands(side_effect=subprocess.CalledProcessError(1, "certutil")):
            with self.assertRaisesRegex(RuntimeError, "private browser CA trust"):
                self.backend._browser_trust_start(self.home)
        scratch = Path(self.backend.browser_trust.name)
        self.backend.stop()
        self.assertFalse(scratch.exists())
        self.assertIsNone(self.backend.browser_trust)

    def test_cancelled_launch_cannot_start_certutil(self):
        self.backend.children.cancel()
        with patch("runtime.subprocess.Popen") as spawn, self.assertRaisesRegex(RuntimeError, "Launch cancelled"):
            self.backend._browser_trust_start(self.home)
        spawn.assert_not_called()


CERTIFICATE = b"-----BEGIN CERTIFICATE-----\nMIIBfixtureONLY+/=\n-----END CERTIFICATE-----\n"


class ExternalNetworkTests(unittest.TestCase):
    """Mac VM guest mode: the website gateway, its CA and the keyring key all belong to the host."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = Policy(self.root / "state")
        self.backend = ContainerBackend(self.policy, external_network=True)
        self.addCleanup(self.backend.stop)
        self.network = self.root / "guest-network"
        self.network.mkdir(mode=0o700)
        self.ca = self.root / "ca.pem"
        self.ca.write_bytes(CERTIFICATE)
        self.endpoint = ProxyEndpoint(self.network / "proxy.sock", self.ca)

    def forward(self, live):
        """A stand-in for the SSH reverse forward: a live one holds connections, a dead one closes them.

        Returns a callable that stops listening, as a vanished sshd forward does.
        """
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.endpoint.guest_socket_path))
        listener.listen()
        held = []

        def accept():
            while True:
                try:
                    connection, _ = listener.accept()
                except OSError:
                    return
                if live:
                    held.append(connection)
                else:
                    connection.close()
        thread = threading.Thread(target=accept, daemon=True)
        thread.start()

        def stop():
            # On Linux close() alone leaves a listener blocked in accept() serving; shutdown() retires it.
            with contextlib.suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
            thread.join(5)
        self.addCleanup(lambda: [connection.close() for connection in held])
        self.addCleanup(stop)
        return stop

    def test_start_requires_this_runs_host_endpoint_and_key(self):
        children = OwnedChildren()
        key = new_keyring_unlock()
        with patch.object(children, "run") as run, patch.object(children, "popen") as popen:
            for proxy, password in ((None, None), (self.endpoint, None), (None, key)):
                with self.subTest(proxy=proxy, password=password is not None):
                    with self.assertRaisesRegex(ValueError, "host gateway owner"):
                        self.backend.start("/nix/store/x-omp/bin/omp", False, "none", self.root, "omp",
                                           None, children, installation=INSPECTION, git_discovery_home="/host/home/u",
                                           proxy=proxy, keyring_password=password)
            local = ContainerBackend(Policy(self.root / "local-state"))
            self.addCleanup(local.stop)
            with self.assertRaisesRegex(ValueError, "owns its website gateway"):
                local.start("/nix/store/x-omp/bin/omp", False, "none", self.root, "omp", None, children,
                            installation=INSPECTION, git_discovery_home="/host/home/u", proxy=self.endpoint)
        run.assert_not_called()
        popen.assert_not_called()
        self.assertIsNone(self.backend.gateway)

    def test_only_a_live_forward_alone_in_its_mounted_directory_is_accepted(self):
        stop = self.forward(live=True)
        self.assertEqual(self.endpoint.verify(), CERTIFICATE)
        (self.network / "broker.sock").write_text("")
        with self.assertRaisesRegex(ValueError, "must contain only proxy.sock"):
            self.endpoint.verify()
        (self.network / "broker.sock").unlink()
        with self.assertRaisesRegex(ValueError, "must contain only proxy.sock"):
            ProxyEndpoint(self.network / "other.sock", self.ca).verify()
        stop()
        with self.assertRaisesRegex(RuntimeError, "not connected"):
            self.endpoint.verify()
        self.endpoint.guest_socket_path.unlink()
        self.forward(live=False)
        with self.assertRaisesRegex(RuntimeError, "forward closed"):
            self.endpoint.verify()

    def test_ca_must_be_a_certificate_without_key_material(self):
        self.forward(live=True)
        self.ca.write_bytes(CERTIFICATE + b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")
        with self.assertRaisesRegex(ValueError, "only PEM certificates"):
            self.endpoint.verify()
        self.ca.unlink()
        target = self.root / "elsewhere.pem"
        target.write_bytes(CERTIFICATE)
        self.ca.symlink_to(target)
        with self.assertRaises(OSError):
            self.endpoint.verify()

    def test_mounts_and_fresh_browser_trust_consume_the_host_endpoint(self):
        home = self.policy.directory / "home"
        home.mkdir()
        self.backend.proxy = self.endpoint
        commands = []

        def certutil(command, **kwargs):
            commands.append(command)
            database = Path(command[command.index("-d") + 1].removeprefix("sql:"))
            (database / "pkcs11.txt").write_text(f"configdir='sql:{database}'\n")
        with (patch.dict(os.environ, {"START_APP_CERTUTIL": "/nix/store/test-nss/bin/certutil"}),
              patch.object(self.backend.children, "run", side_effect=certutil)):
            self.backend._browser_trust_start(home)
        self.assertEqual(commands[1][commands[1].index("-i") + 1], str(self.ca))
        fake_home = self.root / "user"
        (fake_home / ".omp").mkdir(parents=True)
        args = []
        with patch.object(Path, "home", return_value=fake_home):
            self.backend._mount_resources(args, home, [])
        self.assertIn(f"{self.network}:/network:ro", args)
        self.assertIn(f"{self.ca}:/trust/ca.pem:ro", args)
        self.assertFalse(any(":/home/sandbox/.omp:" in value for value in args))
        self.assertFalse((self.policy.directory / "network").exists(), "Guest created a local gateway")
        self.backend.stop()
        self.assertIsNone(self.backend.proxy)
        self.assertIsNone(self.backend.browser_trust)

    def test_host_workspace_is_not_prepared_inside_the_guest(self):
        host = "/private/tmp/omp-manager-fixture-" + secrets.token_hex(4)
        workspace = {"host_workspace": host, "container_workspace": "/tmp/omp-manager"}
        self.assertEqual(self.backend._workspace_mount({"folders": [{"path": host, "write": True}]}, workspace),
                         (self.backend.mount / "host" / host.lstrip("/"), "/tmp/omp-manager"))
        self.assertFalse(Path(host).exists())
        self.assertIsNone(self.backend._workspace_mount({"folders": []}, workspace))

    def test_delivered_key_is_pinned_to_its_private_home_and_never_stored(self):
        first = new_keyring_unlock()
        # Boolean comparisons keep unlock keys out of assertion output.
        self.assertTrue(secrets.compare_digest(self.backend._keyring_password(first), first))
        verifier = self.policy.directory / KEYRING_VERIFIER
        self.assertEqual(stat.S_IMODE(verifier.stat().st_mode), 0o600)
        self.assertNotIn(first, verifier.read_text())
        self.assertFalse((self.policy.directory / KEYRING_UNLOCK).exists())
        home = self.policy.directory / "home"
        home.mkdir()
        (home / "saved-data").write_text("persistent private data")
        self.assertTrue(secrets.compare_digest(
            ContainerBackend(self.policy, external_network=True)._keyring_password(first), first))
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.backend._keyring_password(new_keyring_unlock())
        with self.assertRaisesRegex(ValueError, "Invalid"):
            self.backend._keyring_password("short")
        verifier.unlink()
        with self.assertRaisesRegex(ValueError, "no keyring unlock key"):
            self.backend._keyring_password(first)
        self.assertFalse(verifier.exists())


class FakeWeston:
    def __init__(self):
        self.code = None

    def poll(self):
        return self.code

    def terminate(self):
        self.code = -15

    def wait(self, timeout=None):
        return self.code


class BrowserDisplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.started = []
        self.display = BrowserDisplay(Path(self.temp.name) / "browser-display", self.spawn)
        self.addCleanup(self.display.stop)

    def spawn(self, directory, name):
        self.assertEqual((directory, name), (self.display.directory, "wayland-browser"))
        self.started.append(FakeWeston())
        return self.started[-1]

    def connect(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.settimeout(5)
        client.connect(str(self.display.directory / "request.sock"))
        self.assertEqual(client.recv(16), b"ready\n")
        return client

    def test_window_runs_once_while_any_browser_holds_its_connection(self):
        first, second = self.connect(), self.connect()
        self.assertEqual(len(self.started), 1)
        first.close()
        _until(lambda: self.display.clients == 1)
        self.assertIsNone(self.started[0].code)
        second.close()
        _until(lambda: self.display.process is None)
        self.assertEqual(self.started[0].code, -15)
        self.connect()
        self.assertEqual(len(self.started), 2)

    def test_stop_retires_window_and_request_socket(self):
        self.connect()
        self.display.stop()
        self.assertEqual(self.started[0].code, -15)
        self.assertFalse((self.display.directory / "request.sock").exists())


if __name__ == "__main__":
    unittest.main()
