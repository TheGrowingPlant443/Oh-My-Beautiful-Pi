"""Owned child for a digest-pinned VM image download: cancelling it interrupts blocked network IO too."""
import hashlib
import os
import ssl
import sys
import urllib.request


def fetch(url, digest, path, cacert=None):
    if not url.startswith("https://") or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("An HTTPS image URL and SHA-256 digest are required")
    context = ssl.create_default_context(cafile=cacert or None)
    hasher = hashlib.sha256()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output, urllib.request.urlopen(url, context=context, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise ValueError("The image redirected outside HTTPS")
        while chunk := response.read(1 << 20):
            hasher.update(chunk)
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if hasher.hexdigest() != digest:
        raise ValueError("The VM image's SHA-256 digest does not match the mandatory pin")


if __name__ == "__main__":
    try:
        fetch(*sys.argv[1:])
    except Exception as error:
        print(f"Pinned VM image download failed: {error}. Obtain the same digest from Ubuntu's HTTPS archive "
              "or update the verified image pin in vm/lima-template.nix; no unchecked image is used.", file=sys.stderr)
        sys.exit(1)
