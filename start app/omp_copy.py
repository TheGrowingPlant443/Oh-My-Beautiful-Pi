"""One-time, private ~/.omp copies; no host mounts, Git operations or name filters.

The wire format is a tar containing tree/ and a final, non-secret report.json.
Only regular files, directories and literal symlinks are transported. Source
owners, absolute source paths and xattrs are never added to archive metadata.

SQLite connections, even mode=ro connections, may write a host WAL index. To
avoid that, a separate process takes SQLite's POSIX shared database lock and
shared WAL writer/checkpoint/recovery locks, captures pinned read-only fds, and
revalidates the sidecars. SQLite then recovers that *private* capture and uses
its online backup API. The helper process matters: POSIX locks are process-wide
and must not alias an application's own SQLite connection. No source fd is ever
opened writable. This supports SQLite's normal Unix locking VFS, not custom
VFSes or filesystems that do not implement POSIX advisory locks.

Publication is a recoverable transaction outside home/.omp. A durable intent
and inode identities precede renames; recovery finishes the same staged copy
before consulting the receipt. Cancellation is honored until this short commit
section. Existing .omp.previous is never discarded without replace=True and a
new durable request_id; replaying the last request returns its receipt unchanged.
"""

import codecs
from contextlib import closing, contextmanager
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import posixpath
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_RECEIPT = "omp-copy.json"
_INTENT = ".omp-copy-pending.json"
_REQUEST = "omp-recopy.json"
_SQLITE = b"SQLite format 3\x00"
_COUNTS = ("files", "directories", "symlinks", "bytes", "special_files",
           "external_links", "sqlite_databases")
_CHUNK = 1024 * 1024
_SQLITE_LOCK_TIMEOUT = 15.0
_SQLITE_PROGRESS_INTERVAL = 2.0


def _stat(parent, name):
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _identity(value):
    return [value.st_dev, value.st_ino] if value is not None else None


def _same(parent, name, expected):
    return _identity(_stat(parent, name)) == expected


@contextmanager
def _directory(path, create=False):
    """Pin every ancestor; neither a root nor an ancestor may be a symlink."""
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, _DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _regular(parent, name, expected=None):
    fd = os.open(name, _READ, dir_fd=parent)
    value = os.fstat(fd)
    if not stat.S_ISREG(value.st_mode) or (expected is not None and
                                          _identity(value) != _identity(expected)):
        os.close(fd)
        raise RuntimeError("Source entry changed while copying")
    return fd


def _json_read(parent, name):
    value = _stat(parent, name)
    if value is None:
        return None
    fd = _regular(parent, name, value)
    with os.fdopen(fd, "rb") as stream:
        payload = stream.read(65537)
    if len(payload) > 65536:
        raise ValueError("Copy metadata is too large")
    return json.loads(payload)


def _json_write(parent, name, value):
    fd = os.open(name, _CREATE, 0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(value, sort_keys=True).encode())
        stream.flush()
        os.fsync(stream.fileno())


def _request_id(value):
    if (not isinstance(value, str) or len(value) != 32 or
            any(character not in "0123456789abcdef" for character in value)):
        raise ValueError("Private copy request_id must be 32 lowercase hexadecimal characters")
    return value


def _validate_request(replace, request_id):
    if replace:
        _request_id(request_id)
    elif request_id is not None:
        raise ValueError("Private copy request_id requires replace=True")


def read_copy_request(state: Path) -> str | None:
    """Read an explicit recopy request without following symlinks or creating state."""
    try:
        with _directory(state) as root:
            if _stat(root, _REQUEST) is None:
                return None
            value = _json_read(root, _REQUEST)
    except FileNotFoundError:
        return None
    if (not isinstance(value, dict) or set(value) != {"replace_previous", "request_id"} or
            value["replace_previous"] is not True):
        raise ValueError("Invalid private copy request; expected replace_previous and request_id")
    return _request_id(value["request_id"])


def _report(value, copied=False):
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ValueError("Unsupported private copy report")
    if type(value.get("source_missing")) is not bool:
        raise ValueError("Invalid private copy report")
    for key in _COUNTS:
        if type(value.get(key)) is not int or value[key] < 0:
            raise ValueError("Invalid private copy counts")
    report = {"version": 1, "source_missing": value["source_missing"],
              **{key: value[key] for key in _COUNTS}, **({"copied": True} if copied else {})}
    # Only local transaction metadata can carry authorization, never a tar report.
    if copied and "request_id" in value:
        report["request_id"] = _request_id(value["request_id"])
    return report


def _remove(parent, name):
    value = _stat(parent, name)
    if value is None:
        return
    if not stat.S_ISDIR(value.st_mode):
        os.unlink(name, dir_fd=parent)
        return
    fd = os.open(name, _DIRECTORY, dir_fd=parent)
    try:
        os.fchmod(fd, 0o700)
        for child in os.listdir(fd):
            _remove(fd, child)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent)


@contextmanager
def _locked(state, check):
    with _directory(state, create=True) as root:
        lock = os.open("omp-copy.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                       os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=root)
        try:
            if not stat.S_ISREG(os.fstat(lock).st_mode):
                raise ValueError("Copy lock is not a regular file")
            while True:
                check()
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.05)
            _recover(root)
            yield root
        finally:
            os.close(lock)


@contextmanager
def _stage(root):
    name = ".omp-copy-stage-" + uuid.uuid4().hex
    os.mkdir(name, 0o700, dir_fd=root)
    fd = os.open(name, _DIRECTORY, dir_fd=root)
    try:
        yield name, fd
    finally:
        os.close(fd)
        # An interrupted commit owns its stage until recovery finishes it.
        pending = _json_read(root, _INTENT)
        if pending is None or pending.get("stage") != name:
            _remove(root, name)


def _home(root):
    try:
        os.mkdir("home", 0o700, dir_fd=root)
    except FileExistsError:
        pass
    return os.open("home", _DIRECTORY, dir_fd=root)


def _recover(root):
    pending = _json_read(root, _INTENT)
    if pending is None:
        return
    name = pending.get("stage", "")
    if not isinstance(name, str) or not name.startswith(".omp-copy-stage-") or "/" in name:
        raise ValueError("Invalid private copy transaction")
    report = _report(pending["report"], copied=True)
    _validate_request(pending["replace"], report.get("request_id"))
    stage = os.open(name, _DIRECTORY, dir_fd=root)
    home = _home(root)
    try:
        new = pending["new"]
        old = pending["old"]
        previous = pending["previous"]
        if not _same(home, ".omp", new):
            if not _same(stage, "tree", new):
                raise RuntimeError("Private copy staging was changed; refusing publication")
            if previous is not None:
                if _same(home, ".omp.previous", previous):
                    if not pending["replace"]:
                        raise RuntimeError("Replacing .omp.previous requires explicit consent")
                    os.rename(".omp.previous", "discarded", src_dir_fd=home, dst_dir_fd=stage)
                elif not _same(stage, "discarded", previous):
                    raise RuntimeError("Private copy backup changed during publication")
            if old is not None and _same(home, ".omp", old):
                if _stat(home, ".omp.previous") is not None:
                    raise RuntimeError("Refusing to overwrite an unexpected .omp.previous")
                os.rename(".omp", ".omp.previous", src_dir_fd=home, dst_dir_fd=home)
            elif not _same(home, ".omp", None) or (old is not None and
                                                  not _same(home, ".omp.previous", old)):
                raise RuntimeError("Private .omp changed during publication")
            os.rename("tree", ".omp", src_dir_fd=stage, dst_dir_fd=home)
        os.fsync(home)
        if _stat(stage, "receipt") is None:
            _json_write(stage, "receipt", report)
        os.replace("receipt", _RECEIPT, src_dir_fd=stage, dst_dir_fd=root)
        os.fsync(root)
        os.unlink(_INTENT, dir_fd=root)
        os.fsync(root)
    finally:
        os.close(home)
        os.close(stage)
    _remove(root, name)


def copy_status(state: Path) -> dict:
    """Return the durable receipt; recover an interrupted publication first."""
    with _locked(state, lambda: None) as root:
        value = _json_read(root, _RECEIPT)
        return _report(value, copied=True) if value is not None else {"copied": False}


def _tar_info(name, value, kind):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = stat.S_IMODE(value.st_mode)
    info.mtime = value.st_mtime
    # TarInfo defaults uid/gid to zero and owner names to empty strings.
    return info


class _CheckedReader:
    def __init__(self, stream, check):
        self.stream, self.check = stream, check

    def read(self, size=-1):
        self.check()
        return self.stream.read(min(size, _CHUNK) if size >= 0 else _CHUNK)


def _external_links(links, names=None):
    count = 0
    for name in links if names is None else names:
        current = posixpath.join(posixpath.dirname(name), links[name])
        seen = set()
        while True:
            if current.startswith("/"):
                count += 1
                break
            parts = current.split("/")
            resolved = []
            changed = False
            for index, part in enumerate(parts):
                if part in ("", "."):
                    continue
                if part == "..":
                    if not resolved:
                        count += 1
                        changed = None
                        break
                    resolved.pop()
                    continue
                resolved.append(part)
                prefix = "/".join(resolved)
                if prefix in links:
                    if prefix in seen:
                        changed = None  # Internal cycles do not read anything outside.
                        break
                    seen.add(prefix)
                    current = posixpath.join(posixpath.dirname(prefix), links[prefix],
                                             *parts[index + 1:])
                    changed = True
                    break
            if changed is not True:
                break
    return count


def _git_file(stream, parent_parts, name):
    if name != ".git":
        return
    stream.seek(0)
    first = stream.readline(65537)
    stream.seek(0)
    if first.startswith(b"gitdir:"):
        target = os.fsdecode(first[7:].strip())
        resolved = posixpath.normpath(posixpath.join(*parent_parts, target)
                                      if parent_parts else target)
        if target.startswith("/") or resolved == ".." or resolved.startswith("../"):
            raise ValueError("Cannot copy a linked-worktree .git file with an external gitdir; "
                             "use a self-contained checkout (no Git fetch is performed)")
        return target


def _git_alternates(stream, path):
    if path != ".git/objects/info/alternates" and not path.endswith("/.git/objects/info/alternates"):
        return []
    references = []
    objects = posixpath.dirname(posixpath.dirname(path))
    for index, line in enumerate(stream):
        target = line.rstrip(b"\n")
        if target.startswith(b'"'):
            if not target.endswith(b'"'):
                raise ValueError("Malformed Git object alternates; use a self-contained checkout")
            target = codecs.escape_decode(target[1:-1])[0]
        if target:
            references.append((posixpath.join(objects, ".omp-alternate-" + str(index)),
                               os.fsdecode(target), "Git object alternates"))
    stream.seek(0)
    return references


def _sqlite_capture(parent, name, fd, destination, check, progress, relative):
    command = [sys.executable, str(Path(__file__).resolve()), "--sqlite-snapshot",
               str(parent), name, str(fd), str(destination), str(_SQLITE_LOCK_TIMEOUT)]
    child = subprocess.Popen(command, pass_fds=(parent, fd), stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    next_progress = started + _SQLITE_PROGRESS_INTERVAL
    try:
        while True:
            check()
            try:
                _, error = child.communicate(timeout=0.05)
                break
            except subprocess.TimeoutExpired as pending:
                now = time.monotonic()
                status = (pending.output or b"").splitlines()
                if now >= next_progress and status and status[-1].startswith(b"waiting:"):
                    progress(f"{status[-1].decode('ascii')} ({now - started:.1f}s elapsed); "
                             "close the application using this database if it remains busy")
                    next_progress = now + _SQLITE_PROGRESS_INTERVAL
        if child.returncode:
            raise RuntimeError(f"Cannot capture SQLite database {relative!r} safely: " +
                               error.decode("utf-8", "replace").strip())
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stderr.close()
        child.stdout.close()


def _scratch_base(source):
    # TMPDIR is user-controlled and may point into the source (or sandbox home).
    # Fixed system locations keep scratch out of both; resolve their OS aliases
    # before testing ancestry, notably Darwin's /tmp -> /private/tmp.
    source = Path(os.path.abspath(source))
    for candidate in (Path("/tmp").resolve(), Path("/var/tmp").resolve()):
        if candidate != source and source not in candidate.parents and candidate.is_dir():
            return candidate
    raise ValueError("No private SQLite staging location exists outside the source")


@contextmanager
def _sqlite_backup(parent, name, fd, check, host_source, relative, progress):
    """Yield a private online backup; the source is accessed only by read-only fds."""
    progress(f"Capturing SQLite database {relative!r}")
    with tempfile.TemporaryDirectory(prefix="omp-sqlite-", dir=_scratch_base(host_source)) as directory:
        private = Path(directory)
        _sqlite_capture(parent, name, fd, private, check,
                        lambda message: progress(f"SQLite {relative!r}: {message}"), relative)
        with closing(sqlite3.connect(private / "db")) as source:
            target_fd = os.open(private / "backup", _CREATE, 0o600)
            os.close(target_fd)
            with closing(sqlite3.connect(private / "backup")) as target:
                source.backup(target, pages=256, progress=lambda *args: check(), sleep=0.05)
        with (private / "backup").open("rb") as stream:
            yield stream


def write_snapshot(stream, source: Path, check=lambda: None, *, progress=lambda message: None) -> dict:
    """Write a complete private tar. Symlinks are copied literally, never followed."""
    check()
    try:
        descriptor = stream.fileno()
    except (AttributeError, io.UnsupportedOperation):
        pass
    else:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.fchmod(descriptor, 0o600)
    report = {"version": 1, "source_missing": False, **dict.fromkeys(_COUNTS, 0)}
    links = {}
    git_references = []
    with tarfile.open(fileobj=stream, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        def visit(parent, relative, value):
            check()
            archive.addfile(_tar_info("tree" + ("/" + relative if relative else ""),
                                      value, tarfile.DIRTYPE))
            report["directories"] += 1
            names = sorted(os.listdir(parent))
            databases = set()
            # Recognize databases before deciding which sidecars are transient.
            for name in names:
                check()
                # A base name sorts before its suffixes. Live sidecars may vanish
                # during checkpoint/last-close; only the locked capture reads them.
                if any(name.endswith(suffix) and name[:-len(suffix)] in databases
                       for suffix in ("-wal", "-shm", "-journal")):
                    continue
                entry = _stat(parent, name)
                if entry is None:
                    raise RuntimeError(
                        f"Source entry {posixpath.join(relative, name)!r} disappeared while copying; "
                        "close applications changing ~/.omp, then retry Start. No files were skipped.")
                if stat.S_ISREG(entry.st_mode):
                    fd = _regular(parent, name, entry)
                    try:
                        if os.read(fd, 16) == _SQLITE:
                            databases.add(name)
                    finally:
                        os.close(fd)
            transient = {name + suffix for name in databases for suffix in ("-wal", "-shm", "-journal")}
            for name in names:
                check()
                if name in transient:
                    continue
                entry = _stat(parent, name)
                if entry is None:
                    raise RuntimeError(
                        f"Source entry {posixpath.join(relative, name)!r} disappeared while copying; "
                        "close applications changing ~/.omp, then retry Start. No files were skipped.")
                path = posixpath.join(relative, name)
                wire = "tree/" + path
                if stat.S_ISDIR(entry.st_mode):
                    child = os.open(name, _DIRECTORY, dir_fd=parent)
                    try:
                        if _identity(os.fstat(child)) != _identity(entry):
                            raise RuntimeError("Source directory changed while copying")
                        visit(child, path, entry)
                    finally:
                        os.close(child)
                elif stat.S_ISLNK(entry.st_mode):
                    target = os.readlink(name, dir_fd=parent)
                    if not _same(parent, name, _identity(entry)):
                        raise RuntimeError("Source symlink changed while copying")
                    info = _tar_info(wire, entry, tarfile.SYMTYPE)
                    info.linkname = target
                    archive.addfile(info)
                    links[path] = target
                    report["symlinks"] += 1
                elif stat.S_ISREG(entry.st_mode):
                    fd = _regular(parent, name, entry)
                    with os.fdopen(fd, "rb") as original:
                        if (os.pread(fd, 16, 0) == _SQLITE) != (name in databases):
                            raise RuntimeError("Source database type changed while copying")
                        gitdir = _git_file(original, relative.split("/") if relative else [], name)
                        if gitdir is not None:
                            git_references.append((path, gitdir, "linked-worktree .git file"))
                        git_references.extend(_git_alternates(original, path))
                        info = _tar_info(wire, entry, tarfile.REGTYPE)
                        if name in databases:
                            with _sqlite_backup(parent, name, fd, check, source, path, progress) as backup:
                                info.size = os.fstat(backup.fileno()).st_size
                                archive.addfile(info, _CheckedReader(backup, check))
                            report["sqlite_databases"] += 1
                        else:
                            info.size = os.fstat(fd).st_size
                            archive.addfile(info, _CheckedReader(original, check))
                        report["files"] += 1
                        report["bytes"] += info.size
                else:
                    report["special_files"] += 1
        try:
            with _directory(source) as root:
                visit(root, "", os.fstat(root))
        except FileNotFoundError:
            # Missing roots are a real, empty first copy; missing descendants fail.
            if report["directories"]:
                raise RuntimeError(
                    "Source entry disappeared while copying; close applications changing ~/.omp, "
                    "then retry Start. No files were skipped.") from None
            report["source_missing"] = True
            info = tarfile.TarInfo("tree")
            info.type, info.mode = tarfile.DIRTYPE, 0o700
            archive.addfile(info)
            report["directories"] = 1
        for path, target, kind in git_references:
            if _external_links({**links, path: target}, [path]):
                raise ValueError("Cannot copy " + kind + " with an external gitdir/object path; "
                                 "use a self-contained checkout (no Git fetch is performed)")
        if any(posixpath.basename(name) == ".git" and _external_links(links, [name])
               for name in links):
            raise ValueError("Cannot copy an external .git symlink; use a self-contained checkout")
        report["external_links"] = _external_links(links)
        payload = json.dumps(report, sort_keys=True).encode()
        info = tarfile.TarInfo("report.json")
        info.mode, info.size = 0o600, len(payload)
        archive.addfile(info, io.BytesIO(payload))
        check()
    return report


def _member_parts(member):
    name = member.name
    if "\x00" in name or name.startswith("/"):
        raise ValueError("Unsafe private copy archive path")
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("Unsafe private copy archive path")
    if parts[0] != "tree":
        raise ValueError("Unexpected private copy archive member")
    return parts


@contextmanager
def _parents(root, parts):
    fd = os.dup(root)
    try:
        for part in parts:
            child = os.open(part, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _unpack(stream, stage, check):
    directories = []
    seen = set()
    report = None
    with tarfile.open(fileobj=_CheckedReader(stream, check), mode="r|") as archive:
        for member in archive:
            check()
            if report is not None:
                raise ValueError("Members follow the private copy report")
            if member.name == "report.json":
                if not member.isreg() or member.size > 65536:
                    raise ValueError("Invalid private copy report member")
                with archive.extractfile(member) as data:
                    report = _report(json.loads(data.read()))
                continue
            parts = _member_parts(member)
            if parts == ["tree"] and not member.isdir():
                raise ValueError("Private copy root must be a directory")
            key = tuple(parts)
            if key in seen:
                raise ValueError("Duplicate private copy archive path")
            seen.add(key)
            if member.mode < 0 or member.mode > 0o7777:
                raise ValueError("Invalid private copy permissions")
            with _parents(stage, parts[:-1]) as parent:
                name = parts[-1]
                if member.isdir():
                    os.mkdir(name, 0o700, dir_fd=parent)
                    directories.append((parts, member.mode, member.mtime))
                elif member.issym():
                    if "\x00" in member.linkname:
                        raise ValueError("Invalid private copy symlink")
                    os.symlink(member.linkname, name, dir_fd=parent)
                elif member.isreg():
                    fd = os.open(name, _CREATE, 0o600, dir_fd=parent)
                    with os.fdopen(fd, "wb") as output, archive.extractfile(member) as data:
                        while True:
                            check()
                            chunk = data.read(_CHUNK)
                            if not chunk:
                                break
                            output.write(chunk)
                        output.flush()
                        os.fchmod(output.fileno(), member.mode)
                        os.utime(output.fileno(), (member.mtime, member.mtime))
                        os.fsync(output.fileno())
                else:
                    raise ValueError("Unsupported private copy archive member type")
    if report is None or ("tree",) not in seen:
        raise ValueError("Incomplete private copy archive")
    for parts, mode, mtime in reversed(directories):
        with _parents(stage, parts) as directory:
            os.fchmod(directory, mode)
            os.utime(directory, (mtime, mtime))
            os.fsync(directory)
    return report


def _install(stream, root, replace, check, request_id):
    with _stage(root) as (name, stage):
        report = _report(_unpack(stream, stage, check), copied=True)
        if request_id is not None:
            report["request_id"] = request_id
        home = _home(root)
        try:
            old = _identity(_stat(home, ".omp"))
            previous = _identity(_stat(home, ".omp.previous")) if old is not None else None
            if previous is not None and not replace:
                raise FileExistsError(".omp.previous already exists; Copy again must explicitly "
                                      "authorize replacing that backup")
            _json_write(stage, "receipt", report)
            os.fsync(stage)
            check()
            _json_write(root, _INTENT, {"stage": name, "new": _identity(_stat(stage, "tree")),
                                      "old": old, "previous": previous,
                                      "replace": bool(replace), "report": report})
            os.fsync(root)
        finally:
            os.close(home)
        # No cancellation between durable intent and receipt publication.
        _recover(root)
        return report


def install_snapshot(stream, state: Path, replace=False, check=lambda: None, *,
                     request_id=None) -> dict:
    """Install once; each explicit recopy needs a durable, replay-safe request ID."""
    _validate_request(replace, request_id)
    with _locked(state, check) as root:
        receipt = _json_read(root, _RECEIPT)
        if receipt is not None:
            receipt = _report(receipt, copied=True)
            if not replace or receipt.get("request_id") == request_id:
                return receipt
        return _install(stream, root, replace, check, request_id)


def _overlap(source, state):
    source = Path(os.path.abspath(source))
    state = Path(os.path.abspath(state))
    if source == state or source in state.parents or state in source.parents:
        raise ValueError("The host .omp source and private launcher state must not overlap")


def copy_once(source: Path, state: Path, replace=False, check=lambda: None, *,
              request_id=None, progress=lambda message: None) -> dict:
    """Copy once or apply a new recopy ID; replay never reads the source again."""
    _validate_request(replace, request_id)
    _overlap(source, state)
    with _locked(state, check) as root:
        receipt = _json_read(root, _RECEIPT)
        if receipt is not None:
            receipt = _report(receipt, copied=True)
            if not replace or receipt.get("request_id") == request_id:
                return receipt
        with _stage(root) as (_, stage):
            fd = os.open("snapshot.tar", os.O_RDWR | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=stage)
            with os.fdopen(fd, "w+b") as stream:
                write_snapshot(stream, source, check, progress=progress)
                stream.seek(0)
                return _install(stream, root, replace, check, request_id)


def _sidecar(parent, name):
    try:
        fd = _regular(parent, name)
    except FileNotFoundError:
        return None, None
    return fd, _identity(os.fstat(fd))


def _copy_fd(source, destination):
    os.lseek(source, 0, os.SEEK_SET)
    fd = os.open(destination, _CREATE, 0o600)
    with os.fdopen(fd, "wb") as output:
        while True:
            data = os.read(source, _CHUNK)
            if not data:
                break
            output.write(data)


class _SQLiteBusy(Exception):
    pass


def _sqlite_lock(fd, start, length, label, locked):
    # EACCES means contention only for F_SETLK, not open/read/write failures.
    try:
        fcntl.lockf(fd, fcntl.LOCK_SH | fcntl.LOCK_NB, length, start)
    except OSError as failure:
        if failure.errno in (errno.EAGAIN, errno.EACCES):
            raise _SQLiteBusy(label) from None
        raise
    locked.append((fd, start, length))


def _sqlite_worker(parent, name, database, destination, lock_timeout=_SQLITE_LOCK_TIMEOUT):
    """Pin/lock/capture using SQLite's standard Unix VFS locking protocol."""
    destination = Path(destination)
    deadline = time.monotonic() + lock_timeout
    status = None
    while True:
        sidecars = {}
        locked = []
        retry = False
        try:
            for suffix in ("-shm", "-wal", "-journal"):
                sidecars[suffix] = _sidecar(parent, name + suffix)
            # PENDING/SHARED freeze the database, including rollback-journal
            # spills. Do not impersonate a RESERVED writer: other readers use
            # that lock to distinguish a hot journal requiring recovery.
            for start, length, label in ((0x40000000, 1, "database pending lock"),
                                         (0x40000002, 510, "database shared lock")):
                _sqlite_lock(database, start, length, label, locked)
            shm = sidecars["-shm"][0]
            if shm is not None:
                # Unix WAL_WRITE/CKPT/RECOVER are bytes 120..122 (not read marks).
                _sqlite_lock(shm, 120, 3, "WAL writer/checkpoint/recovery locks", locked)
            if not _same(parent, name, _identity(os.fstat(database))):
                raise RuntimeError("SQLite source changed during capture")
            if any(not _same(parent, name + suffix, identity)
                   for suffix, (_, identity) in sidecars.items()):
                retry = True
            else:
                if status != "capturing":
                    print("capturing", flush=True)
                    status = "capturing"
                _copy_fd(database, destination / "db")
                for suffix in ("-wal", "-journal"):
                    fd = sidecars[suffix][0]
                    if fd is not None:
                        _copy_fd(fd, destination / ("db" + suffix))
                if any(not _same(parent, name + suffix, identity)
                       for suffix, (_, identity) in sidecars.items()):
                    retry = True
                else:
                    return
        except _SQLiteBusy as failure:
            retry = True
            message = "waiting: " + str(failure)
            if status != message:
                print(message, flush=True)
                status = message
        finally:
            for fd, start, length in reversed(locked):
                fcntl.lockf(fd, fcntl.LOCK_UN, length, start)
            for fd, _ in sidecars.values():
                if fd is not None:
                    os.close(fd)
        if retry:
            for child in destination.iterdir():
                child.unlink()
            if time.monotonic() >= deadline:
                reason = status if status and status.startswith("waiting:") else "sidecars keep changing"
                raise RuntimeError(
                    f"{reason} after {lock_timeout:g}s. Close the application using this database "
                    "(including a browser holding an exclusive profile lock), then retry Start; "
                    "the database was not skipped and the private copy was not published.")
            time.sleep(0.01)


if __name__ == "__main__":
    if len(sys.argv) != 7 or sys.argv[1] != "--sqlite-snapshot":
        raise SystemExit("This module is imported by the launcher, not run directly")
    try:
        _sqlite_worker(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5], float(sys.argv[6]))
    except Exception as failure:
        raise SystemExit(str(failure)) from None
