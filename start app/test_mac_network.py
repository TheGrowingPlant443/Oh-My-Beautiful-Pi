import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest

from mac_network import HostNetwork, keyring_unlock
from policy import KEYRING_UNLOCK, Policy


class HostNetworkTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.policy = Policy(self.root / "state")
        self.addCleanup(shutil.rmtree, self.policy.transient, True)

    def test_real_gateway_exposes_only_short_socket_and_public_certificate(self):
        network = HostNetwork(self.policy).start()
        self.addCleanup(network.stop)
        self.assertEqual(network.socket_path.parent, self.policy.transient_directory())
        self.assertLessEqual(len(os.fsencode(network.socket_path)), 103)
        self.assertTrue(network.socket_path.is_socket())
        self.assertEqual(stat.S_IMODE(network.socket_path.stat().st_mode), 0o600)
        certificate = network.public_ca()
        self.assertTrue(certificate.startswith(b"-----BEGIN CERTIFICATE-----"))
        self.assertNotIn(b"PRIVATE KEY", certificate)
        # The CA key stays in owner-only launcher state, away from anything forwarded into the VM.
        keys = [path for path in (self.policy.directory / "network").rglob("*")
                if path.is_file() and b"PRIVATE KEY" in path.read_bytes()]
        self.assertTrue(keys)
        for path in keys:
            self.assertFalse(path.is_relative_to(self.policy.transient))
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(list(self.policy.transient.iterdir()), [network.socket_path])
        # The socket is the host Policy's gateway: an ungranted destination is refused.
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(str(network.socket_path))
            client.sendall(b"GET http://denied.invalid/ HTTP/1.1\r\nHost: denied.invalid\r\n\r\n")
            self.assertTrue(client.recv(64).startswith(b"HTTP/1.1 403"))
        self.assertEqual(self.policy.history[-1]["target"], "http://denied.invalid")
        with self.assertRaisesRegex(RuntimeError, "already running"):
            network.start()
        network.stop()
        self.assertFalse(network.socket_path.exists())
        with self.assertRaisesRegex(RuntimeError, "not running"):
            network.public_ca()
        # A later run generation gets a fresh gateway on the same short path.
        network.start()
        self.assertTrue(network.socket_path.is_socket())

    def test_stale_socket_of_an_earlier_controller_is_replaced(self):
        stale = self.policy.transient_directory() / "proxy.sock"
        listener = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        listener.bind(str(stale))
        listener.close()
        network = HostNetwork(self.policy)
        self.assertFalse(stale.exists())
        network.start()
        self.addCleanup(network.stop)
        self.assertTrue(network.socket_path.is_socket())

    def test_overlong_socket_path_is_refused(self):
        policy = SimpleNamespace(transient_directory=lambda: Path("/" + "x" * 100))
        with self.assertRaisesRegex(ValueError, "Unix socket limit"):
            HostNetwork(policy)


class KeyringUnlockTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.policy = Policy(self.root / "state")
        self.key = self.policy.directory / KEYRING_UNLOCK

    def test_one_stable_owner_only_key_per_host_state(self):
        first = keyring_unlock(self.policy)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        # Boolean comparisons keep generated unlock keys out of assertion output.
        self.assertTrue(secrets.compare_digest(first, keyring_unlock(Policy(self.root / "state"))))
        self.assertFalse(secrets.compare_digest(first, keyring_unlock(Policy(self.root / "other"))))

    def test_unsafe_or_malformed_key_is_refused_not_replaced(self):
        self.key.write_text(json.dumps("f" * 64))
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            keyring_unlock(self.policy)
        self.key.chmod(0o600)
        self.assertEqual(keyring_unlock(self.policy), "f" * 64)
        self.key.write_text(json.dumps("invalid"))
        with self.assertRaises(ValueError):
            keyring_unlock(self.policy)
        self.assertEqual(json.loads(self.key.read_text()), "invalid")
        self.key.unlink()
        self.key.symlink_to(self.root / "elsewhere")
        with self.assertRaises(OSError):
            keyring_unlock(self.policy)
        self.assertFalse((self.root / "elsewhere").exists())


if __name__ == "__main__":
    unittest.main()
