"""Pinned static x86-64 user emulation, registered only in the launcher's owned ARM Linux guest.

The official pinned SonarScanner CLI image is linux/amd64 only. This preserves that exact image/filter:
no alternate image, privileged installer container, Mac Rosetta installation or host binfmt registration.
"""
import json
import os
from pathlib import Path
import platform
import stat
import struct
import subprocess

NAME = "ombp-x86_64"
DIRECTORY = Path("/proc/sys/fs/binfmt_misc")
RECEIPT = Path("/var/lib/ombp/binfmt.json")
MAGIC = bytes.fromhex("7f454c4602010100000000000000000002003e00")
MASK = bytes.fromhex("ffffffffffffff000000000000000000feffffff")


def static_interpreter(path):
    """An immutable Nix-store, native aarch64 ELF64 executable with no dynamic interpreter."""
    path = Path(path).resolve(strict=True)
    if not str(path).startswith("/nix/store/"):
        raise ValueError("The emulation interpreter must come from the pinned Nix runtime")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or not info.st_mode & 0o111
                or info.st_mode & 0o022):
            raise ValueError("The emulation interpreter must be an immutable executable")
        header = os.read(fd, 64)
        if (len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01"
                or struct.unpack_from("<H", header, 18)[0] != 183):
            raise ValueError("The emulation interpreter must be a native aarch64 ELF64 executable")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if size < 56 or count == 0 or count > 256 or size * count > 65536 or offset + size * count > info.st_size:
            raise ValueError("Invalid emulation interpreter program headers")
        os.lseek(fd, offset, os.SEEK_SET)
        headers = os.read(fd, size * count)
        if len(headers) != size * count or any(struct.unpack_from("<I", headers, i * size)[0] == 3
                                             for i in range(count)):
            raise ValueError("The emulation interpreter must be static (no PT_INTERP)")
    finally:
        os.close(fd)
    return str(path)


def registration(interpreter):
    def escaped(value):
        return "".join(f"\\x{byte:02x}" for byte in value)
    # F pins the static interpreter across container mount namespaces. No C flag: never preserve setuid credentials.
    return f":{NAME}:M:0:{escaped(MAGIC)}:{escaped(MASK)}:{interpreter}:F"


def provision():
    if os.geteuid() != 0 or platform.system() != "Linux":
        raise RuntimeError("Emulation provisioning runs as root only inside the owned Linux guest")
    marker = Path("/var/lib/ombp/provisioned.json")
    metadata = marker.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError("The owned guest provisioning receipt is missing or unsafe")
    facts = json.loads(marker.read_text())
    if facts.get("system") == "x86_64-linux" and platform.machine() == "x86_64":
        return  # The pinned scanner already runs natively on Intel guests.
    if facts.get("system") != "aarch64-linux" or platform.machine() != "aarch64":
        raise RuntimeError("The owned guest provisioning receipt has the wrong architecture")
    value = os.environ.get("START_APP_QEMU_X86_64")
    if not value:
        raise RuntimeError("The ARM guest runtime needs its pinned static qemu-x86_64 for the locked scanner image")
    interpreter = static_interpreter(value)
    probe = subprocess.run([interpreter, "--version"], capture_output=True, timeout=10)
    if probe.returncode or not probe.stdout.startswith(b"qemu-x86_64 version "):
        raise RuntimeError("The pinned guest x86-64 interpreter cannot execute; refusing to register it")
    if not os.path.ismount(DIRECTORY):
        subprocess.run(["/usr/bin/mount", "-t", "binfmt_misc", "binfmt_misc", str(DIRECTORY)],
                       check=True, timeout=10)
    entry = DIRECTORY / NAME
    if entry.exists():
        if not RECEIPT.exists() or RECEIPT.is_symlink():
            raise RuntimeError("An unowned binfmt registration already uses the launcher's name; left untouched")
        old = json.loads(RECEIPT.read_text())
        content = entry.read_text().splitlines()
        if (f"interpreter {old.get('interpreter')}" not in content or "flags: F" not in content
                or f"magic {MAGIC.hex()}" not in content or f"mask {MASK.hex()}" not in content):
            raise RuntimeError("The owned guest's binfmt registration no longer matches its receipt")
        if old.get("interpreter") == interpreter and "enabled" in content:
            return
        entry.write_text("-1")
    (DIRECTORY / "register").write_text(registration(interpreter))
    content = entry.read_text().splitlines()
    if f"interpreter {interpreter}" not in content or "flags: F" not in content or "enabled" not in content:
        raise RuntimeError("The guest kernel did not enable the owned static x86-64 interpreter")
    temporary = RECEIPT.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump({"interpreter": interpreter, "name": NAME, "flags": "F"}, output)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, RECEIPT)
