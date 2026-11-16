"""Live, fail-closed host-folder and Nix-store views for a rootless container.

Mount with raw_fi=True and zero attribute/entry/negative cache timeouts. Host
files use direct IO; immutable store files retain executable mmap support.
`/host` is served by an injected host-files implementation (host_files.HostFiles
on Linux, file_broker.RemoteHostFiles in the Mac VM), which owns every folder
permission decision. Nix symlinks may only resolve within the currently
approved closure roots.
"""

import errno
import os
import posixpath
import stat
import threading
from collections import Counter
from dataclasses import dataclass

from fuse import FuseOSError, Operations

from host_files import DenialLog, absolute as _absolute, attributes, virtual_attributes, within as _within


STORE = "/nix/store"
_STORE_VIEW = "/store"
_HOST_VIEW = "/host"
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_PATH = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC


def _store_root(path):
    if path.startswith(STORE + "/"):
        return STORE + "/" + path[len(STORE) + 1:].split("/", 1)[0]


def _host_target(path):
    if _absolute(path) and _within(path, _HOST_VIEW):
        return path[len(_HOST_VIEW):] or "/"
    return None


@dataclass(frozen=True)
class _Entry:
    kind: str
    target: str = ""


@dataclass
class _Handle:
    fd: int = None
    path: str = ""
    host: object = None
    sync: int = 0  # 0, or 1 for O_DSYNC / 2 for O_SYNC host handles


class AccessFS(Operations):
    """policy supplies snapshot() and deny() for programs and store roots.

    closure_resolver(program) returns absolute /nix/store/<root> closure roots.
    It must fail rather than return an incomplete closure. Results are cached;
    a fresh policy snapshot determines which cached closures remain accessible.
    host_files implements the host_files.HostFiles interface for `/host`.
    """

    def __init__(self, policy, base_store_roots, closure_resolver, host_files):
        self.policy = policy
        self.host_files = host_files
        self._requirements = base_store_roots
        self._base_roots = {key: frozenset(self._root(root) for root in item["roots"])
                            for key, item in base_store_roots.items()}
        self._resolve_closure = closure_resolver
        self._closures = {}
        self._roots_key = None
        self._approved_roots = frozenset()
        self._handles = {}
        self._next_handle = 1
        self._lock = threading.RLock()
        self._denials = DenialLog(policy)

    @staticmethod
    def _root(path):
        if not _absolute(path) or posixpath.dirname(path) != STORE:
            raise ValueError("Expected an absolute Nix store root")
        return path

    @staticmethod
    def _host(call, *args, **kwargs):
        """Host-files errors are ordinary OSError; present them as FUSE errors."""
        try:
            return call(*args, **kwargs)
        except FuseOSError:
            raise
        except OSError as failure:
            raise FuseOSError(failure.errno or errno.EIO) from None

    def _deny(self, kind, target, reason):
        self._denials.record(kind, target, reason)

    def _blocked_roots(self, snapshot):
        return {self._root(root) for key in snapshot.get("disabled_requirements", ())
                for root in self._requirements.get(key, {}).get("primary_roots", ())}

    def _programs(self, snapshot):
        blocked = self._blocked_roots(snapshot)
        disabled = snapshot.get("disabled_requirements", ())
        programs = {}
        for key, item in self._requirements.items():
            if key not in disabled:
                for path in item["programs"]:
                    if not any(_within(path, root) for root in blocked):
                        programs.setdefault(posixpath.basename(path), path)
        paths = [path for path in snapshot.get("programs", ())
                 if _absolute(path) and _within(path, STORE) and path != STORE
                 and not any(_within(path, root) for root in blocked)]
        counts = Counter(posixpath.basename(path) for path in set(paths))
        for path in paths:
            name = posixpath.basename(path)
            if counts[name] == 1:
                programs[name] = path
            else:
                programs.pop(name, None)
        return programs

    def _roots(self, snapshot):
        key = (tuple(snapshot.get("programs", ())),
               tuple(snapshot.get("disabled_requirements", ())))
        with self._lock:
            if key == self._roots_key:
                return self._approved_roots
            disabled = snapshot.get("disabled_requirements", ())
            roots = set()
            for requirement, paths in self._base_roots.items():
                if requirement not in disabled:
                    roots.update(paths)
            complete = True
            for program in set(snapshot.get("programs", ())) & set(self._programs(snapshot).values()):
                try:
                    if program not in self._closures:
                        self._closures[program] = frozenset(
                            self._root(root) for root in self._resolve_closure(program))
                    roots.update(self._closures[program])
                except (OSError, ValueError, RuntimeError):
                    complete = False
                    self._deny("program", program, "Cannot resolve approved Nix closure")
            roots = frozenset(roots - self._blocked_roots(snapshot))
            # Failed closures stay retryable; only complete policy results are cached.
            if complete:
                self._roots_key, self._approved_roots = key, roots
            return roots

    def _entry(self, path, write=False, snapshot=None):
        """Entries outside `/host`; host paths are authorized by host_files."""
        if not _absolute(path):
            raise FuseOSError(errno.EINVAL)
        snapshot = self.policy.snapshot() if snapshot is None else snapshot
        if path in ("/", _STORE_VIEW, "/programs"):
            if write:
                raise FuseOSError(errno.EROFS)
            return _Entry("virtual")
        if path.startswith("/programs/"):
            name = path[len("/programs/"):]
            program = self._programs(snapshot).get(name)
            if program is None:
                self._deny("program", name, "Program is not selected")
                raise FuseOSError(errno.ENOENT)
            if write:
                raise FuseOSError(errno.EROFS)
            self._store_resolve(program, self._roots(snapshot))
            return _Entry("program", program)
        if path.startswith(_STORE_VIEW + "/"):
            return self._store_entry(STORE + path[len(_STORE_VIEW):], write, snapshot)
        raise FuseOSError(errno.ENOENT)

    def _read_only(self, path):
        """Mutations outside `/host` fail with the view's own error."""
        self._entry(path, write=True)
        raise FuseOSError(errno.EROFS)

    def _store_entry(self, target, write, snapshot):
        root = _store_root(target)
        if root not in self._roots(snapshot):
            # Node searches parent directories for optional package metadata; absence is not a denied grant.
            try:
                os.lstat(root)
            except FileNotFoundError:
                raise FuseOSError(errno.ENOENT) from None
            if "/bin/" in target and self._unapproved_executable(target):
                self._deny("program", target, "Nix executable is not approved")
            raise FuseOSError(errno.EACCES)
        if write:
            raise FuseOSError(errno.EROFS)
        return _Entry("store", target)

    def _unapproved_executable(self, target):
        root = _store_root(target)
        try:
            target = self._store_resolve(target, {root})
            parent = self._directory(posixpath.dirname(target))
            try:
                st = os.stat(posixpath.basename(target), dir_fd=parent,
                             follow_symlinks=False)
                return stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111)
            finally:
                os.close(parent)
        except OSError:
            return False

    @staticmethod
    def _directory(path):
        fd = os.open("/", _PATH | os.O_DIRECTORY)
        try:
            for part in path.strip("/").split("/") if path != "/" else ():
                child = os.open(part, _PATH | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _checked_store_link(fd, final, follow_final, links):
        mode = os.fstat(fd).st_mode
        if stat.S_ISLNK(mode) and (not final or follow_final):
            if links >= 40:
                raise FuseOSError(errno.ELOOP)
            return os.readlink("", dir_fd=fd)
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)
                or (final and stat.S_ISLNK(mode))):
            raise FuseOSError(errno.EACCES)
        if not final and not stat.S_ISDIR(mode):
            raise FuseOSError(errno.ENOTDIR)
        return None

    def _store_resolve(self, target, roots, follow_final=True):
        links = 0
        while True:
            if _store_root(target) not in roots:
                raise FuseOSError(errno.EACCES)
            parts = target[len(STORE) + 1:].split("/")
            fd = self._directory(STORE)
            resolved = STORE
            try:
                for index, name in enumerate(parts):
                    child = os.open(name, _PATH, dir_fd=fd)
                    try:
                        final = index == len(parts) - 1
                        link = self._checked_store_link(child, final, follow_final, links)
                        if link is not None:
                            links += 1
                            target = posixpath.normpath(posixpath.join(
                                resolved, link, *parts[index + 1:]))
                            break
                        resolved += "/" + name
                        if final:
                            return resolved
                        os.close(fd)
                        fd, child = child, None
                    finally:
                        if child is not None:
                            os.close(child)
            finally:
                os.close(fd)

    def _open_entry(self, entry, flags):
        if entry.kind in ("store", "program"):
            target = self._store_resolve(entry.target, self._roots(self.policy.snapshot()))
            parent = self._directory(posixpath.dirname(target))
            try:
                pinned = os.open(posixpath.basename(target), _PATH, dir_fd=parent)
                try:
                    mode = os.fstat(pinned).st_mode
                    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                        raise FuseOSError(errno.EACCES)
                    if flags == _PATH:
                        fd, pinned = pinned, None
                        return fd
                    return os.open(f"/proc/self/fd/{pinned}",
                                   (flags & ~os.O_NOFOLLOW) | os.O_CLOEXEC
                                   | os.O_NONBLOCK)
                finally:
                    if pinned is not None:
                        os.close(pinned)
            finally:
                os.close(parent)
        raise FuseOSError(errno.EISDIR)

    def getattr(self, path, fh=None):
        target = _host_target(path)
        if target is not None:
            return self._host(self.host_files.getattr, target)
        entry = self._entry(path)
        if entry.kind == "virtual":
            return virtual_attributes()
        if entry.kind == "program":
            return {"st_mode": stat.S_IFLNK | 0o777, "st_nlink": 1,
                    "st_uid": os.getuid(), "st_gid": os.getgid(),
                    "st_size": len(entry.target)}
        roots = self._roots(self.policy.snapshot())
        target = self._store_resolve(entry.target, roots, follow_final=False)
        self._store_resolve(entry.target, roots)
        parent = self._directory(posixpath.dirname(target))
        try:
            return attributes(os.stat(posixpath.basename(target),
                                      dir_fd=parent, follow_symlinks=False))
        finally:
            os.close(parent)

    def readdir(self, path, fh):
        target = _host_target(path)
        if target is not None:
            return [".", "..", *self._host(self.host_files.readdir, target)]
        snapshot = self.policy.snapshot()
        entry = self._entry(path, snapshot=snapshot)
        if path == "/":
            names = {"host", "store", "programs"}
        elif path == _STORE_VIEW:
            names = {posixpath.basename(root) for root in self._roots(snapshot)}
        elif path == "/programs":
            names = set(self._programs(snapshot))
        else:
            fd = self._open_entry(entry, _DIRECTORY)
            try:
                names = set(os.listdir(fd))
            finally:
                os.close(fd)
        visible = []
        for name in sorted(names):
            try:
                self.getattr(path.rstrip("/") + "/" + name)
            except OSError:
                continue
            visible.append(name)
        return [".", "..", *visible]

    def readlink(self, path):
        if _host_target(path) is not None:
            raise FuseOSError(errno.EACCES)
        entry = self._entry(path)
        if entry.kind == "program":
            return entry.target
        if entry.kind != "store":
            raise FuseOSError(errno.EACCES)
        target = self._store_resolve(entry.target, self._roots(self.policy.snapshot()),
                                     follow_final=False)
        parent = self._directory(posixpath.dirname(target))
        try:
            if not stat.S_ISLNK(os.stat(posixpath.basename(target), dir_fd=parent,
                                       follow_symlinks=False).st_mode):
                raise FuseOSError(errno.EINVAL)
        finally:
            os.close(parent)
        return self._store_resolve(entry.target, self._roots(self.policy.snapshot()))

    def _register(self, path, record, fi):
        with self._lock:
            handle = self._next_handle
            self._next_handle += 1
            if fi is not None:
                fi.fh = handle
                host = record.host is not None
                fi.direct_io = int(host)
                # Store files are immutable; every open is still authorized, only their page cache survives.
                fi.keep_cache = int(not host)
            self._handles[handle] = record
        return handle if fi is None else 0

    @staticmethod
    def _sync_mode(flags):
        if flags & os.O_SYNC == os.O_SYNC:
            return 2
        return 1 if flags & os.O_DSYNC else 0

    def _register_host(self, path, handle, flags, fi):
        try:
            return self._register(path, _Handle(path=path, host=handle,
                                                sync=self._sync_mode(flags)), fi)
        except BaseException:
            self.host_files.close(handle)
            raise

    def open(self, path, flags):
        fi = None if isinstance(flags, int) else flags
        flags = flags if fi is None else fi.flags
        target = _host_target(path)
        if target is not None:
            access = flags & os.O_ACCMODE
            handle = self._host(
                self.host_files.open, target,
                read=access in (os.O_RDONLY, os.O_RDWR),
                write=access in (os.O_WRONLY, os.O_RDWR),
                append=bool(flags & os.O_APPEND), truncate=bool(flags & os.O_TRUNC))
            return self._register_host(path, handle, flags, fi)
        write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC | os.O_APPEND))
        with self._lock:
            entry = self._entry(path, write=write)
            fd = self._open_entry(entry, flags)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise FuseOSError(errno.EISDIR)
                return self._register(path, _Handle(fd, path), fi)
            except BaseException:
                os.close(fd)
                raise

    def create(self, path, mode, fi=None):
        target = _host_target(path)
        if target is None:
            self._entry(posixpath.dirname(path), write=True)
            self._read_only(path)
        flags = os.O_RDWR if fi is None else fi.flags
        access = flags & os.O_ACCMODE
        handle = self._host(
            self.host_files.create, target, mode & 0o777,
            read=access in (os.O_RDONLY, os.O_RDWR),
            write=access in (os.O_WRONLY, os.O_RDWR),
            append=bool(flags & os.O_APPEND), exclusive=True)
        return self._register_host(path, handle, flags, fi)

    def _lookup(self, fh):
        fh = fh if isinstance(fh, int) else fh.fh
        with self._lock:
            record = self._handles.get(fh)
        if record is None:
            raise FuseOSError(errno.EBADF)
        return record

    def _store_handle(self, record, write=False):
        """A duplicate of a store handle's descriptor, revalidated against current roots."""
        fd = os.dup(record.fd)
        try:
            entry = self._entry(record.path, write=write)
            current = self._open_entry(entry, _PATH)
            try:
                actual, now = os.fstat(fd), os.fstat(current)
                if (actual.st_dev, actual.st_ino) != (now.st_dev, now.st_ino):
                    raise FuseOSError(errno.EACCES)
            finally:
                os.close(current)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _store_write(self, record):
        """Store handles are immutable: report the view's own error for any mutation."""
        os.close(self._store_handle(record, write=True))
        raise FuseOSError(errno.EROFS)

    def write(self, path, data, offset, fh):
        record = self._lookup(fh)
        if record.host is None:
            self._store_write(record)
        written = self._host(self.host_files.write, record.host, data, offset)
        if record.sync:
            self._host(self.host_files.fsync, record.host, record.sync == 1)
        return written

    def truncate(self, path, length, fh=None):
        if fh is not None:
            record = self._lookup(fh)
            if record.host is None:
                self._store_write(record)
            self._host(self.host_files.truncate, None, length, record.host)
            return 0
        target = _host_target(path)
        if target is None:
            self._read_only(path)
        self._host(self.host_files.truncate, target, length)
        return 0

    def read(self, path, size, offset, fh):
        record = self._lookup(fh)
        if record.host is not None:
            return self._host(self.host_files.read, record.host, size, offset)
        fd = self._store_handle(record)
        try:
            return os.pread(fd, size, offset)
        finally:
            os.close(fd)

    def flush(self, path, fh):
        record = self._lookup(fh)
        if record.host is not None:
            self._host(self.host_files.flush, record.host)
        return 0

    def fsync(self, path, datasync, fh):
        record = self._lookup(fh)
        if record.host is not None:
            self._host(self.host_files.fsync, record.host, bool(datasync))
            return 0
        fd = self._store_handle(record)
        try:
            (os.fdatasync if datasync else os.fsync)(fd)
        finally:
            os.close(fd)
        return 0

    def release(self, path, fh):
        fh = fh if isinstance(fh, int) else fh.fh
        with self._lock:
            record = self._handles.pop(fh, None)
        if record is None:
            return 0
        if record.host is not None:
            try:
                self.host_files.close(record.host)
            except OSError:
                pass  # The handle is already gone (closed transport or unknown).
        else:
            os.close(record.fd)
        return 0

    def _host_mutation(self, path):
        target = _host_target(path)
        if target is None:
            self._entry(posixpath.dirname(path), write=True)
            self._read_only(path)
        return target

    def mkdir(self, path, mode):
        self._host(self.host_files.mkdir, self._host_mutation(path), mode & 0o777)
        return 0

    def unlink(self, path):
        self._host(self.host_files.unlink, self._host_mutation(path))
        return 0

    def rmdir(self, path):
        self._host(self.host_files.rmdir, self._host_mutation(path))
        return 0

    def rename(self, old, new):
        source, destination = _host_target(old), _host_target(new)
        for path, target in ((old, source), (new, destination)):
            if target is None:
                self._host_mutation(path)
        self._host(self.host_files.rename, source, destination)
        return 0

    def chmod(self, path, mode):
        target = _host_target(path)
        if target is None:
            self._read_only(path)
        self._host(self.host_files.chmod, target, mode & 0o777)
        return 0

    def utimens(self, path, times=None):
        target = _host_target(path)
        if target is None:
            self._read_only(path)
        self._host(self.host_files.utimens, target, times)
        return 0

    def access(self, path, mode):
        target = _host_target(path)
        if target is not None:
            self._host(self.host_files.access, target, read=bool(mode & os.R_OK),
                       write=bool(mode & os.W_OK), execute=bool(mode & os.X_OK))
            return 0
        entry = self._entry(path, write=bool(mode & os.W_OK))
        attrs = self.getattr(path)
        if mode & os.X_OK and not attrs["st_mode"] & 0o111:
            raise FuseOSError(errno.EACCES)
        if entry.kind == "virtual" and mode & os.W_OK:
            raise FuseOSError(errno.EROFS)
        return 0

    def statfs(self, path):
        target = _host_target(path)
        if target is not None:
            return self._host(self.host_files.statfs, target)
        entry = self._entry(path)
        if entry.kind == "virtual":
            return {"f_bsize": 4096, "f_frsize": 4096, "f_blocks": 0,
                    "f_bfree": 0, "f_bavail": 0, "f_files": 0, "f_ffree": 0,
                    "f_namemax": 255}
        fd = self._open_entry(entry, os.O_RDONLY)
        try:
            st = os.fstatvfs(fd)
            return {key: getattr(st, key) for key in (
                "f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail",
                "f_files", "f_ffree", "f_favail", "f_flag", "f_namemax")}
        finally:
            os.close(fd)

    def symlink(self, target, source):
        raise FuseOSError(errno.EPERM)

    def link(self, target, source):
        raise FuseOSError(errno.EPERM)

    def mknod(self, path, mode, dev):
        raise FuseOSError(errno.EPERM)

    def chown(self, path, uid, gid):
        raise FuseOSError(errno.EPERM)

    def destroy(self, path):
        """Close every handle this view opened; host_files' own lifetime belongs to its owner."""
        with self._lock:
            handles, self._handles = self._handles, {}
        for record in handles.values():
            if record.host is not None:
                try:
                    self.host_files.close(record.host)
                except OSError:
                    pass
            else:
                os.close(record.fd)
