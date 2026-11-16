"""Host side of a Mac isolated run's network boundary: the real website gateway and the keyring unlock key.

The Linux VM receives only the gateway's Unix socket (reverse-forwarded by the controller's own SSH session),
its public CA certificate and, over the management channel, the keyring unlock key. The CA private key, the
Mac login Keychain (read by the gateway for credential injection) and the control token never leave the Mac.
"""
import os

from network import NetworkGateway, read_public_ca
from policy import KEYRING_UNLOCK, new_keyring_unlock, read_keyring_unlock

# sockaddr_un.sun_path on macOS holds 104 bytes including the terminating NUL.
_SOCKET_PATH_LIMIT = 103


class HostNetwork:
    """The host-owned website gateway of one isolated run generation; construct one per controller."""

    def __init__(self, policy):
        self.policy = policy
        # The short owner-only transient directory: Application Support paths can exceed the socket limit.
        self.socket_path = policy.transient_directory() / "proxy.sock"
        if len(os.fsencode(self.socket_path)) > _SOCKET_PATH_LIMIT:
            raise ValueError(f"Website gateway socket path {self.socket_path} exceeds the macOS Unix socket "
                             "limit; set a shorter TMPDIR")
        self.gateway = None
        # Left by an earlier controller of this state, which no longer serves it.
        if self.socket_path.is_socket():
            self.socket_path.unlink()

    def start(self):
        """Start the gateway with the host Policy; its CA and key stay in owner-only host launcher state."""
        if self.gateway is not None:
            raise RuntimeError("Website gateway is already running")
        gateway = NetworkGateway(self.policy, self.policy.directory / "network", self.socket_path)
        gateway.start()
        self.gateway = gateway
        return self

    def public_ca(self):
        """PEM certificate bytes for the guest's trust store; never the CA key."""
        if self.gateway is None:
            raise RuntimeError("Website gateway is not running")
        return read_public_ca(self.gateway.ca_path)

    def stop(self):
        """Retire this run's gateway; its forwarded socket disappears with it, so the guest loses network."""
        if self.gateway is not None:
            self.gateway.stop()
            self.gateway = None


def keyring_unlock(policy):
    """This state's sandbox keyring unlock key, kept in owner-only host launcher state.

    It is created once; the VM keeps only a verifier and refuses any other key for an existing private home.
    """
    path = policy.directory / KEYRING_UNLOCK
    if not path.exists() and not path.is_symlink():
        policy.save(KEYRING_UNLOCK, new_keyring_unlock())
    return read_keyring_unlock(path)
