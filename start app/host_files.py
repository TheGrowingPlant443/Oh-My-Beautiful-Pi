"""Live, fail-closed host-folder access shared by the Linux FUSE gateway and the Mac broker.

HostFiles is the only implementation of folder permissions: grant selection,
protected launcher paths, descriptor-relative traversal, registered-handle
revalidation, denial deduplication and rename bookkeeping. It addresses real
host paths ("targets") and raises ordinary OSError. AccessFS presents it as
the FUSE `/host` view on Linux; file_broker serves it to the Mac's Linux VM.

Host symlinks, multiply-linked regular files, special files and nested
cross-device mounts are never opened. Platform descriptor primitives differ:

- LinuxPrimitives pins the inspected inode with O_PATH and reopens exactly that
  inode through /proc/self/fd, so a device swapped in after inspection is never
  opened.
- DarwinPrimitives has no O_PATH. It inspects the leaf without following links,
  opens it relative to the pinned parent with O_NOFOLLOW|O_NONBLOCK and without
  truncation, then immediately requires the same device/inode before any IO or
  truncation. LIMIT: if an independent host process replaces the inspected
  entry with a device node between that inspection and the open, the open
  itself can reach the device driver (its open side effect) before the identity
  check rejects and closes it. No data is read, written or truncated through it,
  and the sandbox itself cannot create links or device nodes. The two backends
  are therefore not syscall-equivalent.
"""

import errno
import functools
import os
import posixpath
import stat
import sys
import threading
import json
import unicodedata
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass


SYSTEM = ("/proc", "/sys", "/dev", "/run", "/nix")
# Lookups of files that never exist, not user actions; Python's startup probes beside its executable included.
# A leading "-" is a login shell's argv[0] (bash looks up "-bash"), never a program name.
PROBES = {".DS_Store", ".directory", ".hidden", "desktop.ini", "autorun.inf", "pyvenv.cfg"}
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
OS_PERMISSION_REASON = ("macOS denied this access (Privacy & Security setting for the launcher, "
                        "or a file protection flag)")


def within(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def absolute(path):
    return (isinstance(path, str) and path.startswith("/") and "\0" not in path
            and path == posixpath.normpath(path) and not path.startswith("//"))


def error(code, message=None):
    return OSError(code, message or os.strerror(code))


class OSPermissionError(PermissionError):
    """The operating system's own access control (macOS TCC/file flags) refused the call."""


def attributes(st, writable=False):
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)
            or stat.S_ISLNK(st.st_mode)):
        raise error(errno.EACCES)
    attrs = {key: getattr(st, key) for key in (
        "st_mode", "st_nlink", "st_size", "st_atime", "st_mtime", "st_ctime",
        "st_uid", "st_gid", "st_ino")}
    attrs["st_mode"] &= ~0o6000  # Never advertise host set-id privileges.
    if not writable:
        attrs["st_mode"] &= ~0o222
    return attrs


def virtual_attributes():
    return {"st_mode": stat.S_IFDIR | 0o555, "st_nlink": 2,
            "st_uid": os.getuid(), "st_gid": os.getgid(), "st_size": 0}


VIRTUAL_STATFS = {"f_bsize": 4096, "f_frsize": 4096, "f_blocks": 0, "f_bfree": 0,
                  "f_bavail": 0, "f_files": 0, "f_ffree": 0, "f_namemax": 255}
STATFS_KEYS = ("f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail",
               "f_files", "f_ffree", "f_favail", "f_flag", "f_namemax")


class DenialLog:
    """Deduplicated, bounded denial reporting; cleared with the policy's history."""

    def __init__(self, policy, limit=256):
        self.policy = policy
        self.limit = limit
        self._lock = threading.Lock()
        self._seen = OrderedDict()
        self._generation = getattr(policy, "history_generation", 0)

    def __len__(self):
        return len(self._seen)

    def record(self, kind, target, reason):
        name = posixpath.basename(target)
        if name in PROBES or name.endswith("._pth") or (kind == "program" and name.startswith("-")):
            return
        key = kind, target, reason
        with self._lock:
            generation = getattr(self.policy, "history_generation", 0)
            if generation != self._generation:
                self._seen.clear()
                self._generation = generation
            if key in self._seen:
                return
            self._seen[key] = None
            if len(self._seen) > self.limit:
                self._seen.popitem(last=False)
        self.policy.deny(kind, target, reason)


class Pin:
    """An inspected host object. `st` is its inspected status; `fd` and `name` are primitive-specific."""

    __slots__ = ("st", "fd", "name")

    def __init__(self, st, fd, name=None):
        self.st, self.fd, self.name = st, fd, name

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class _Primitives:
    @staticmethod
    def protected_within(path, root):
        return within(path, root)

    def directory(self, path):
        """Traversal descriptor for an absolute path, never following a link."""
        fd = self.open_root()
        try:
            for part in path.strip("/").split("/") if path != "/" else ():
                child = self.child_directory(fd, part)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def scandir(fd):
        return os.scandir(fd)


class LinuxPrimitives(_Primitives):
    """O_PATH pins the checked inode; the trusted /proc link reopens exactly it."""

    name = "linux"

    def __init__(self):
        if not hasattr(os, "O_PATH") or not os.path.isdir("/proc/self/fd"):
            raise error(errno.ENOTSUP, "Linux O_PATH descriptors are unavailable")
        self.path_flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC

    def open_root(self):
        return os.open("/", self.path_flags | os.O_DIRECTORY)

    def child_directory(self, fd, name):
        return os.open(name, self.path_flags | os.O_DIRECTORY, dir_fd=fd)

    def pin(self, parent, name):
        fd = os.open(name, self.path_flags, dir_fd=parent)
        try:
            return Pin(os.fstat(fd), fd)
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def pin_root(fd):
        try:
            return Pin(os.fstat(fd), fd)
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def reopen(pin, flags):
        safe_flags = flags & ~(os.O_TRUNC | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW)
        # This trusted proc link names the pinned, checked inode.
        return os.open(f"/proc/self/fd/{pin.fd}", safe_flags | os.O_CLOEXEC | os.O_NONBLOCK)

    @staticmethod
    def chmod(pin, mode):
        os.chmod(f"/proc/self/fd/{pin.fd}", mode)

    @staticmethod
    def utime(pin, times):
        os.utime(f"/proc/self/fd/{pin.fd}", times)


def _darwin_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except PermissionError as failure:
        if failure.errno == errno.EPERM:
            raise OSPermissionError(errno.EPERM, failure.strerror, failure.filename) from None
        raise


class DarwinPrimitives(_Primitives):
    """Descriptor-relative no-follow opens with post-open identity checks (see module LIMIT).

    Uses only POSIX *at calls plus O_SEARCH/O_EXEC when the platform has them,
    so the same implementation is also exercised on Linux test hosts.
    """

    name = "darwin"

    def __init__(self):
        self.search = getattr(os, "O_SEARCH", None)
        self.execute = getattr(os, "O_EXEC", None)
        self.directory_flags = ((os.O_RDONLY if self.search is None else self.search)
                                | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    @staticmethod
    def _case_sensitive(fd):
        """Ask this volume, not the OS name: APFS can be case-sensitive.

        fgetattrlist ABI/constants are from Darwin sys/attr.h. This is only
        needed for reserved private paths which do not exist yet; existing
        objects are compared by inode/device, including Unicode aliases.
        """
        if sys.platform != "darwin":
            return True
        import ctypes
        import struct

        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.fgetattrlist
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                             ctypes.c_size_t, ctypes.c_ulong)
        function.restype = ctypes.c_int
        # ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES, with ATTR_BIT_MAP_COUNT = 5.
        requested = ctypes.create_string_buffer(struct.pack("=HHIIIII", 5, 0, 0,
                                                            0x80020000, 0, 0, 0))
        result = ctypes.create_string_buffer(36)  # length, capabilities[4], valid[4]
        if function(fd, requested, result, len(result), 0) != 0:
            raise error(ctypes.get_errno())
        values = struct.unpack("=9I", result.raw)
        if values[0] != 36 or not values[5] & 0x100:  # VOL_CAP_FMT_CASE_SENSITIVE
            raise error(errno.ENOTSUP, "Filesystem does not report name-comparison semantics")
        return bool(values[1] & 0x100)

    def _identity_chain(self, path):
        """No-follow identities of every existing prefix and any missing suffix."""
        parts = tuple(path.strip("/").split("/")) if path != "/" else ()
        fd = self.open_root()
        try:
            st = os.fstat(fd)
            identities = [(st.st_dev, st.st_ino)]
            for index, name in enumerate(parts):
                try:
                    st = _darwin_call(os.stat, name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    return parts, identities, True, self._case_sensitive(fd)
                identities.append((st.st_dev, st.st_ino))
                if index == len(parts) - 1 or not stat.S_ISDIR(st.st_mode):
                    # A non-directory prefix cannot be traversed by HostFiles.
                    return parts, identities, False, True
                child = self.child_directory(fd, name)
                now = os.fstat(child)
                if (now.st_dev, now.st_ino) != identities[-1]:
                    os.close(child)
                    raise error(errno.EACCES, "Host directory changed during authorization")
                os.close(fd)
                fd = child
            return parts, identities, False, True
        finally:
            os.close(fd)

    def protected_within(self, path, root):
        if within(path, root):
            return True
        # Identity, rather than lowercasing, handles actual filesystem aliases
        # and leaves distinct names on case-sensitive volumes distinct.
        root_parts, root_ids, missing, sensitive = self._identity_chain(root)
        path_parts, path_ids, _, _ = self._identity_chain(path)
        if not missing:
            return len(root_ids) == len(root_parts) + 1 and root_ids[-1] in path_ids
        base = root_ids[-1]
        if base not in path_ids:
            return False
        suffix = root_parts[len(root_ids) - 1:]
        candidate = path_parts[path_ids.index(base):]
        # Reserve absent private names too, using only this volume's casing
        # rules. Darwin Unicode-equivalent spellings are conservatively
        # reserved even before either spelling exists.
        def key(name):
            normalized = unicodedata.normalize("NFD", name)
            return normalized if sensitive else normalized.casefold()
        return len(candidate) >= len(suffix) and all(
            key(actual) == key(reserved) for actual, reserved in zip(candidate, suffix))

    def open_root(self):
        return _darwin_call(os.open, "/", self.directory_flags)

    def child_directory(self, fd, name):
        return _darwin_call(os.open, name, self.directory_flags, dir_fd=fd)

    @staticmethod
    def pin(parent, name):
        st = _darwin_call(os.stat, name, dir_fd=parent, follow_symlinks=False)
        return Pin(st, os.dup(parent), name)

    @staticmethod
    def pin_root(fd):
        try:
            return Pin(os.fstat(fd), fd, ".")
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def reopen(pin, flags):
        # Never truncate or create here: truncation happens only after identity is proven.
        safe_flags = flags & ~(os.O_TRUNC | os.O_CREAT | os.O_EXCL)
        fd = _darwin_call(os.open, pin.name, safe_flags | os.O_NOFOLLOW | os.O_NONBLOCK
                          | os.O_CLOEXEC, dir_fd=pin.fd)
        try:
            st = os.fstat(fd)
            if ((st.st_dev, st.st_ino) != (pin.st.st_dev, pin.st.st_ino)
                    or stat.S_IFMT(st.st_mode) != stat.S_IFMT(pin.st.st_mode)):
                raise error(errno.EACCES, "Host path changed while it was opened")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _metadata(self, pin, apply):
        if pin.name == ".":
            apply(pin.fd)  # The grant root's own traversal descriptor.
            return
        if stat.S_ISDIR(pin.st.st_mode):
            candidates = [os.O_RDONLY | os.O_DIRECTORY]
            if self.search is not None:
                candidates.insert(0, self.search | os.O_DIRECTORY)
        else:
            candidates = [os.O_RDONLY, os.O_WRONLY]
            if self.execute is not None:
                candidates.append(self.execute)
        for flags in candidates:
            try:
                fd = self.reopen(pin, flags)
            except PermissionError as failure:
                if failure.errno == errno.EACCES:
                    continue
                raise
            try:
                apply(fd)
                return
            finally:
                os.close(fd)
        # Pathname metadata calls cannot be bound to the checked inode; refuse instead.
        raise error(errno.ENOTSUP, "Metadata of an object that cannot be opened is unsupported on macOS")

    def chmod(self, pin, mode):
        self._metadata(pin, lambda fd: os.chmod(fd, mode))

    def utime(self, pin, times):
        self._metadata(pin, lambda fd: os.utime(fd, times))

    @staticmethod
    def scandir(fd):
        return _darwin_call(os.scandir, fd)


def platform_primitives():
    if sys.platform.startswith("linux"):
        return LinuxPrimitives()
    if sys.platform == "darwin":
        return DarwinPrimitives()
    raise error(errno.ENOTSUP, f"Host file access is unsupported on {sys.platform}")


@dataclass(frozen=True)
class _Entry:
    kind: str
    target: str = ""
    anchor: str = "/"
    writable: bool = False


@dataclass
class _Handle:
    fd: int
    path: str
    append: bool = False


def _reports_os_permission(method):
    @functools.wraps(method)
    def wrapper(self, subject, *args, **kwargs):
        try:
            return method(self, subject, *args, **kwargs)
        except OSPermissionError as failure:
            path = subject if isinstance(subject, str) else self.handle_path(subject)
            if path:
                self._deny("folder", path, OS_PERMISSION_REASON)
            raise PermissionError(failure.errno, failure.strerror) from None
    return wrapper


def open_flags(read, write, append=False, truncate=False):
    if read and write:
        flags = os.O_RDWR
    elif write:
        flags = os.O_WRONLY
    elif read:
        flags = os.O_RDONLY
    else:
        raise error(errno.EINVAL)
    return flags | (os.O_APPEND if append else 0) | (os.O_TRUNC if truncate else 0)


class HostFiles:
    """policy supplies snapshot(), deny(), optional private_paths and history_generation.

    Every operation, including IO on an already-open handle, reauthorizes the
    handle's current path, inode/link identity and the current policy.
    """

    def __init__(self, policy, primitives=None):
        self.policy = policy
        self.primitives = platform_primitives() if primitives is None else primitives
        self._handles = {}
        self._next_handle = 1
        self._lock = threading.RLock()
        self._denials = DenialLog(policy)

    def _deny(self, kind, target, reason):
        self._denials.record(kind, target, reason)

    def handle_path(self, handle):
        with self._lock:
            item = self._handles.get(handle)
            return item.path if item is not None else None

    def _blocked(self, path):
        return any(self.primitives.protected_within(path, root) for root in (
            *SYSTEM, *getattr(self.policy, "private_paths", ())))

    def _grants(self, snapshot):
        return [(item["path"], bool(item.get("write")))
                for item in snapshot.get("folders", ())
                if isinstance(item, dict) and absolute(item.get("path"))
                and not self._blocked(item["path"])]

    def _entry(self, target, write=False, snapshot=None, file=False):
        if not absolute(target):
            raise error(errno.EINVAL)
        snapshot = self.policy.snapshot() if snapshot is None else snapshot
        grants = self._grants(snapshot)
        if not self._blocked(target):
            matches = [(root, writable) for root, writable in grants
                       if within(target, root) and (writable or not write)]
            if matches:
                root, writable = max(matches, key=lambda item: len(item[0]))
                return _Entry("host", target, root, writable)
            if not write and (target == "/" or any(
                    within(root, target) for root, _ in grants)):
                return _Entry("virtual")
        self._deny("folder", posixpath.dirname(target) if file else target,
                   "Folder is not granted for " + ("writing" if write else "reading"))
        raise error(errno.EACCES)

    @contextmanager
    def _parent(self, entry):
        parent, name = posixpath.split(entry.target)
        fd = self.primitives.directory(entry.anchor)
        try:
            device = os.fstat(fd).st_dev
            relative = posixpath.relpath(parent, entry.anchor)
            # The grant root itself is never a mutable directory entry.
            if relative == ".." or relative.startswith("../"):
                raise error(errno.EACCES)
            for part in relative.split("/") if relative != "." else ():
                child = self.primitives.child_directory(fd, part)
                if os.fstat(child).st_dev != device:
                    os.close(child)
                    raise error(errno.EXDEV)
                os.close(fd)
                fd = child
            yield fd, name, device
        finally:
            os.close(fd)

    @staticmethod
    def _safe_host(st, device):
        if st.st_dev != device:
            raise error(errno.EXDEV)
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            raise error(errno.EACCES)
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            raise error(errno.EACCES)

    def _pin(self, entry):
        """Inspect a host entry without opening its data; the caller closes the pin."""
        if entry.target == entry.anchor:
            return self.primitives.pin_root(self.primitives.directory(entry.anchor))
        with self._parent(entry) as (parent, name, device):
            # Pin the inode before opening it: a replaced device must never open.
            pin = self.primitives.pin(parent, name)
            try:
                self._safe_host(pin.st, device)
                return pin
            except BaseException:
                pin.close()
                raise

    def _host_open(self, entry, flags, mode=0o666):
        if entry.target == entry.anchor:
            pin = self.primitives.pin_root(self.primitives.directory(entry.anchor))
            try:
                return self.primitives.reopen(pin, flags)
            finally:
                pin.close()
        with self._parent(entry) as (parent, name, device):
            try:
                pin = self.primitives.pin(parent, name)
            except FileNotFoundError:
                if not flags & os.O_CREAT:
                    raise
                fd = os.open(name, flags | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, mode, dir_fd=parent)
            else:
                try:
                    self._safe_host(pin.st, device)
                    if flags & os.O_CREAT and flags & os.O_EXCL:
                        raise error(errno.EEXIST)
                    fd = self.primitives.reopen(pin, flags)
                finally:
                    pin.close()
            try:
                self._safe_host(os.fstat(fd), device)
                if flags & os.O_TRUNC:
                    os.ftruncate(fd, 0)
                return fd
            except BaseException:
                os.close(fd)
                raise

    @_reports_os_permission
    def getattr(self, target):
        entry = self._entry(target)
        if entry.kind == "virtual":
            return virtual_attributes()
        pin = self._pin(entry)
        try:
            return attributes(pin.st, entry.writable)
        finally:
            pin.close()

    @_reports_os_permission
    def open_directory(self, target):
        """A bounded incremental listing; its owner must close it."""
        return _DirectoryCursor(self, target)

    @_reports_os_permission
    def readdir(self, target):
        """Local FUSE compatibility; only the local caller materializes its list."""
        cursor = self.open_directory(target)
        try:
            visible = []
            while True:
                names, done = cursor.page(4096, 512 << 10)
                visible.extend(names)
                if done:
                    return sorted(visible)
        finally:
            cursor.close()

    def _register(self, target, fd, append):
        with self._lock:
            handle = self._next_handle
            self._next_handle += 1
            self._handles[handle] = _Handle(fd, target, append)
            return handle

    @_reports_os_permission
    def open(self, target, *, read=True, write=False, append=False, truncate=False):
        flags = open_flags(read, write, append, truncate)
        with self._lock:
            entry = self._entry(target, write=bool(write or append or truncate), file=True)
            if entry.kind != "host":
                raise error(errno.EISDIR)
            try:
                fd = self._host_open(entry, flags)
            except OSPermissionError:
                raise
            except OSError:
                self._deny("folder", posixpath.dirname(entry.target),
                           "Host path is unsafe or unavailable")
                raise
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise error(errno.EISDIR)
                return self._register(target, fd, append)
            except BaseException:
                os.close(fd)
                raise

    @_reports_os_permission
    def create(self, target, mode, *, read=True, write=True, append=False, exclusive=True):
        flags = open_flags(read, write, append) | os.O_CREAT | (os.O_EXCL if exclusive else 0)
        with self._lock:
            self._entry(posixpath.dirname(target), write=True)
            entry = self._entry(target, write=True, file=True)
            fd = self._host_open(entry, flags, mode & 0o777)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise error(errno.EISDIR)
                return self._register(target, fd, append)
            except BaseException:
                os.close(fd)
                raise

    @contextmanager
    def _handle(self, handle, write=False):
        fd = None
        try:
            with self._lock:
                item = self._handles.get(handle)
                if item is None:
                    raise error(errno.EBADF)
                fd, path, append = os.dup(item.fd), item.path, item.append
                entry = self._entry(path, write=write, file=True)
                if entry.kind != "host":
                    raise error(errno.EACCES)
                current = self._pin(entry)
                try:
                    actual, now = os.fstat(fd), current.st
                    if (actual.st_dev, actual.st_ino) != (now.st_dev, now.st_ino):
                        raise error(errno.EACCES)
                    self._safe_host(actual, now.st_dev)
                finally:
                    current.close()
            yield fd, append
        finally:
            if fd is not None:
                os.close(fd)

    @_reports_os_permission
    def read(self, handle, size, offset):
        with self._handle(handle) as (fd, _):
            return os.pread(fd, size, offset)

    @_reports_os_permission
    def write(self, handle, data, offset):
        with self._handle(handle, write=True) as (fd, append):
            # Append descriptors always write at the current end, ignoring caller offsets.
            return os.write(fd, data) if append else os.pwrite(fd, data, offset)

    @_reports_os_permission
    def truncate(self, target, length, handle=None):
        if handle is not None:
            with self._handle(handle, write=True) as (fd, _):
                os.ftruncate(fd, length)
            return
        fd = self._host_open(self._entry(target, write=True, file=True), os.O_WRONLY)
        try:
            os.ftruncate(fd, length)
        finally:
            os.close(fd)

    def flush(self, handle):
        with self._lock:
            if handle not in self._handles:
                raise error(errno.EBADF)

    @_reports_os_permission
    def fsync(self, handle, datasync=False):
        with self._handle(handle) as (fd, _):
            (getattr(os, "fdatasync", os.fsync) if datasync else os.fsync)(fd)

    def close(self, handle):
        """Release is always permitted, including after revocation."""
        with self._lock:
            item = self._handles.pop(handle, None)
        if item is None:
            raise error(errno.EBADF)
        os.close(item.fd)

    def close_all(self):
        with self._lock:
            handles, self._handles = self._handles, {}
        for item in handles.values():
            os.close(item.fd)

    def _mutable_parent(self, target):
        self._entry(posixpath.dirname(target), write=True)
        entry = self._entry(target, write=True)
        if entry.kind != "host":
            raise error(errno.EROFS)
        if any(self.primitives.protected_within(private, entry.target)
               for private in getattr(self.policy, "private_paths", ())):
            raise error(errno.EACCES)
        return entry

    @_reports_os_permission
    def mkdir(self, target, mode):
        entry = self._mutable_parent(target)
        with self._parent(entry) as (parent, name, _):
            os.mkdir(name, mode & 0o777, dir_fd=parent)

    def _remove(self, target, directory):
        entry = self._mutable_parent(target)
        checked = self._pin(entry)
        try:
            with self._parent(entry) as (parent, name, _):
                (os.rmdir if directory else os.unlink)(name, dir_fd=parent)
        finally:
            checked.close()

    @_reports_os_permission
    def unlink(self, target):
        self._remove(target, False)

    @_reports_os_permission
    def rmdir(self, target):
        self._remove(target, True)

    @_reports_os_permission
    def rename(self, old, new):
        with self._lock:
            source, destination = self._mutable_parent(old), self._mutable_parent(new)
            checked = self._pin(source)
            try:
                try:
                    existing = self._pin(destination)
                except FileNotFoundError:
                    pass
                else:
                    existing.close()
                with self._parent(source) as (src, src_name, _):
                    with self._parent(destination) as (dst, dst_name, _):
                        os.rename(src_name, dst_name, src_dir_fd=src, dst_dir_fd=dst)
                for item in self._handles.values():
                    if within(item.path, old):
                        item.path = new + item.path[len(old):]
            finally:
                checked.close()

    @_reports_os_permission
    def chmod(self, target, mode):
        pin = self._pin(self._entry(target, write=True))
        try:
            self.primitives.chmod(pin, mode & 0o777)
        finally:
            pin.close()

    @_reports_os_permission
    def utimens(self, target, times=None):
        pin = self._pin(self._entry(target, write=True))
        try:
            self.primitives.utime(pin, times)
        finally:
            pin.close()

    @_reports_os_permission
    def access(self, target, *, read=False, write=False, execute=False):
        entry = self._entry(target, write=write)
        attrs = self.getattr(target)
        if execute and not attrs["st_mode"] & 0o111:
            raise error(errno.EACCES)
        if entry.kind == "virtual" and write:
            raise error(errno.EROFS)

    @_reports_os_permission
    def statfs(self, target):
        entry = self._entry(target)
        if entry.kind == "virtual":
            return dict(VIRTUAL_STATFS)
        fd = self._host_open(entry, os.O_RDONLY)
        try:
            st = os.fstatvfs(fd)
            return {key: getattr(st, key) for key in STATFS_KEYS}
        finally:
            os.close(fd)


class _DirectoryCursor:
    """An owned directory iterator, not a snapshot of its unbounded contents.

    Every page has bounded filesystem work, including invisible children.
    At most one name is carried between pages. A folder/private-path policy
    change invalidates the cursor, including real-to-virtual transitions.
    """

    def __init__(self, files, target):
        self._files, self._target = files, target
        self._lock = threading.RLock()
        self._fd, self._iterator, self._pending = None, None, None
        self._closed = False
        self._seen = set()  # Virtual names only: bounded by the policy's grants.
        snapshot = files.policy.snapshot()
        self._folders = snapshot.get("folders", ())
        self._private = tuple(getattr(files.policy, "private_paths", ()))
        self._entry = files._entry(target, snapshot=snapshot)
        try:
            if self._entry.kind == "virtual":
                self._iterator = (
                    posixpath.relpath(root, target).split("/")[0]
                    for root, _ in files._grants(snapshot)
                    if within(root, target) and root != target)
            else:
                self._fd = files._host_open(self._entry, DIRECTORY)
                st = os.fstat(self._fd)
                self._identity = st.st_dev, st.st_ino
                self._iterator = files.primitives.scandir(self._fd)
        except BaseException:
            self.close()
            raise

    def _authorize(self):
        snapshot = self._files.policy.snapshot()
        if (snapshot.get("folders", ()) != self._folders
                or tuple(getattr(self._files.policy, "private_paths", ())) != self._private):
            raise error(errno.EACCES, "Folder authority changed during directory enumeration")
        entry = self._files._entry(self._target, snapshot=snapshot)
        if entry != self._entry:
            raise error(errno.EACCES)
        if self._fd is not None:
            pin = self._files._pin(entry)
            try:
                if (pin.st.st_dev, pin.st.st_ino) != self._identity:
                    raise error(errno.EACCES, "Directory changed during enumeration")
            finally:
                pin.close()

    def page(self, max_names, max_bytes):
        with self._lock:
            if self._closed:
                raise error(errno.EBADF)
            try:
                if (type(max_names) is not int or max_names <= 0
                        or type(max_bytes) is not int or max_bytes <= 0):
                    raise error(errno.EINVAL)
                self._authorize()
                names, size, done = [], 0, False
                for _ in range(max_names):
                    if self._pending is not None:
                        name, self._pending = self._pending, None
                    else:
                        try:
                            item = next(self._iterator)
                        except StopIteration:
                            done = True
                            break
                        name = item.name if self._fd is not None else item
                        if self._fd is None:
                            if name in self._seen:
                                continue
                            self._seen.add(name)
                    child = posixpath.join(self._target, name)
                    if self._files._blocked(child):
                        continue
                    try:
                        self._files.getattr(child)
                    except OSError:
                        continue
                    cost = len(json.dumps(name, ensure_ascii=True)) + 1
                    if cost > max_bytes:
                        raise error(errno.EOVERFLOW, "Directory name exceeds page capacity")
                    if size + cost > max_bytes:
                        self._pending = name
                        break
                    names.append(name)
                    size += cost
                # Don't return a partially built page authorized before revocation.
                self._authorize()
                if done:
                    self.close()
                return names, done
            except BaseException:
                self.close()
                raise

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                if self._iterator is not None:
                    self._iterator.close()
            finally:
                if self._fd is not None:
                    os.close(self._fd)
                    self._fd = None
                self._iterator = self._pending = None
                self._seen.clear()
