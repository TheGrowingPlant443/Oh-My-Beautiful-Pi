"""Host-folder contract for HostFiles on Linux and Darwin descriptor primitives.

No mount, root privileges or Nix installation. HostContract is reused by
test_file_broker.py to run the same contract through a real framed socket.
"""

import copy
import errno
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
from contextlib import contextmanager
import unittest
from unittest.mock import patch

from host_files import (OS_PERMISSION_REASON, DarwinPrimitives, DenialLog, HostFiles, LinuxPrimitives,
                        OSPermissionError)


class Policy:
    def __init__(self, folders=(), programs=(), private_paths=()):
        self.data = {"folders": list(folders), "programs": list(programs),
                     "websites": [], "internet": False}
        self.private_paths = tuple(str(path) for path in private_paths)
        self.denied = []

    def snapshot(self):
        return copy.deepcopy(self.data)

    def deny(self, kind, target, reason):
        self.denied.append((kind, target, reason))


class ObservedRLock:
    """Announce contenders without replacing the lock or filesystem operations."""

    def __init__(self, contender, attempted):
        self.lock = threading.RLock()
        self.contender = contender
        self.attempted = attempted

    def __enter__(self):
        if threading.current_thread().name == self.contender:
            self.attempted.set()
        self.lock.acquire()
        return self

    def __exit__(self, *exc):
        self.lock.release()


def _foreign_device(real, inode):
    def call(*args, **kwargs):
        value = real(*args, **kwargs)
        if value.st_ino == inode:
            fields = list(value)
            fields[2] += 1
            return os.stat_result(fields)
        return value
    return call


class HostContract:
    """Consumer-visible host-folder behaviour; make_host returns (interface, local HostFiles)."""

    def make_host(self, policy):
        raise NotImplementedError

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name))
        self.allowed = self.root / "allowed"
        self.allowed.mkdir()
        self.secret = self.root / "secret"
        self.secret.mkdir()
        (self.secret / "credential").write_bytes(b"outside-secret")
        self.policy = Policy([{"path": str(self.allowed), "write": True}])
        self.fs, self.local = self.make_host(self.policy)
        self.addCleanup(self.local.close_all)
        linux = isinstance(self.local.primitives, LinuxPrimitives)
        # Linux O_PATH reaches objects that cannot be opened; Darwin must open them first.
        self.pathless_metadata = linux
        self.search_traversal = linux or self.local.primitives.search is not None
        # Linux reopens the pinned inode; Darwin refuses a raced path instead.
        self.pinned_reopen = linux

    def read(self, path):
        handle = self.fs.open(str(path))
        try:
            return self.fs.read(handle, 65536, 0)
        finally:
            self.fs.close(handle)

    def assertDenied(self, callback, *args, **kwargs):
        with self.assertRaises(OSError):
            callback(*args, **kwargs)

    def assertErrno(self, code, callback, *args, **kwargs):
        with self.assertRaises(OSError) as failure:
            callback(*args, **kwargs)
        self.assertEqual(failure.exception.errno, code)

    def test_virtual_ancestors_list_only_granted_descendants(self):
        self.assertEqual(self.fs.readdir(str(self.root)), ["allowed"])
        self.assertTrue(stat.S_ISDIR(self.fs.getattr(str(self.root))["st_mode"]))
        self.assertDenied(self.fs.readdir, str(self.secret))
        self.assertDenied(self.fs.getattr, str(self.secret / "credential"))
        self.assertEqual(self.fs.readdir("/"), [self.root.parts[1]])

    def test_grant_and_revoke_are_live_for_existing_handles(self):
        file = self.allowed / "data"
        file.write_bytes(b"allowed")
        handle = self.fs.open(str(file), read=True, write=True)
        self.assertEqual(self.fs.read(handle, 20, 0), b"allowed")
        self.policy.data["folders"] = []
        self.assertDenied(self.fs.read, handle, 20, 0)
        self.assertDenied(self.fs.write, handle, b"X", 0)
        self.assertDenied(self.fs.truncate, str(file), 0, handle)
        self.assertDenied(self.fs.fsync, handle, False)
        self.fs.flush(handle)
        self.policy.data["folders"] = [{"path": str(self.allowed), "write": False}]
        self.assertEqual(self.fs.read(handle, 20, 0), b"allowed")
        self.assertDenied(self.fs.write, handle, b"X", 0)
        self.assertDenied(self.fs.truncate, str(file), 0, handle)
        self.policy.data["folders"] = []
        self.fs.close(handle)  # Release stays permitted after revocation.
        self.assertErrno(errno.EBADF, self.fs.close, handle)
        self.assertEqual(file.read_bytes(), b"allowed")

    def test_normal_writable_directory_and_file_operations(self):
        directory = self.allowed / "directory"
        self.fs.mkdir(str(directory), 0o755)
        path, renamed = directory / "file", directory / "renamed"
        handle = self.fs.create(str(path), 0o640)
        self.assertEqual(self.fs.write(handle, b"abcdef", 0), 6)
        self.fs.rename(str(path), str(renamed))
        self.assertEqual(self.fs.read(handle, 3, 1), b"bcd")
        self.fs.truncate(str(renamed), 3, handle)
        self.fs.fsync(handle, False)
        self.fs.fsync(handle, True)
        self.fs.flush(handle)
        self.fs.close(handle)
        self.fs.chmod(str(renamed), 0o600)
        self.assertEqual(stat.S_IMODE(renamed.stat().st_mode), 0o600)
        self.fs.utimens(str(renamed), (1000, 2000))
        self.assertEqual(renamed.stat().st_mtime_ns, 2000_000_000_000)
        self.assertEqual(self.read(renamed), b"abc")
        attrs = self.fs.getattr(str(renamed))
        self.assertEqual((attrs["st_size"], attrs["st_uid"]), (3, os.getuid()))
        self.assertTrue(stat.S_ISREG(attrs["st_mode"]))
        self.assertGreater(self.fs.statfs(str(directory))["f_blocks"], 0)
        self.fs.access(str(renamed), read=True, write=True)
        self.assertErrno(errno.EACCES, self.fs.access, str(renamed), execute=True)
        self.fs.truncate(str(renamed), 1)
        self.assertEqual(renamed.read_bytes(), b"a")
        self.fs.unlink(str(renamed))
        self.fs.rmdir(str(directory))
        self.assertFalse(directory.exists())

    def test_existing_file_can_be_opened_by_nonexclusive_create(self):
        file = self.allowed / "data"
        file.write_bytes(b"kept")
        self.assertErrno(errno.EEXIST, self.fs.create, str(file), 0o600)
        handle = self.fs.create(str(file), 0o600, exclusive=False)
        try:
            self.assertEqual(self.fs.read(handle, 10, 0), b"kept")
        finally:
            self.fs.close(handle)

    def test_append_writes_ignore_caller_offsets(self):
        file = self.allowed / "log"
        file.write_bytes(b"start")
        handle = self.fs.open(str(file), read=False, write=True, append=True)
        self.assertEqual(self.fs.write(handle, b"-one", 0), 4)
        self.assertEqual(self.fs.write(handle, b"-two", 1), 4)
        self.fs.close(handle)
        self.assertEqual(file.read_bytes(), b"start-one-two")

    def test_open_requires_an_access_mode_and_regular_file(self):
        file = self.allowed / "data"
        file.write_bytes(b"data")
        self.assertErrno(errno.EINVAL, self.fs.open, str(file), read=False, write=False)
        self.assertErrno(errno.EISDIR, self.fs.open, str(self.allowed))
        self.assertErrno(errno.EISDIR, self.fs.open, str(self.root))

    def test_readonly_blocks_every_mutation(self):
        file = self.allowed / "file"
        file.write_bytes(b"unchanged")
        path = str(file)
        handle = self.fs.open(path, read=True, write=True)
        self.policy.data["folders"][0]["write"] = False
        for callback, args, kwargs in (
            (self.fs.open, (path,), {"read": False, "write": True, "truncate": True}),
            (self.fs.open, (path,), {"read": True, "truncate": True}),
            (self.fs.open, (path,), {"read": True, "append": True}),
            (self.fs.create, (str(self.allowed / "new"), 0o600), {}),
            (self.fs.mkdir, (str(self.allowed / "dir"), 0o700), {}),
            (self.fs.unlink, (path,), {}), (self.fs.rmdir, (str(self.allowed),), {}),
            (self.fs.rename, (path, path + "2"), {}), (self.fs.chmod, (path, 0o777), {}),
            (self.fs.truncate, (path, 0), {}), (self.fs.truncate, (path, 0, handle), {}),
            (self.fs.write, (handle, b"X", 0), {}), (self.fs.utimens, (path, None), {}),
            (self.fs.access, (path,), {"write": True}),
        ):
            with self.subTest(operation=callback.__name__, args=args, kwargs=kwargs):
                self.assertDenied(callback, *args, **kwargs)
        self.assertEqual(self.fs.read(handle, 20, 0), b"unchanged")
        self.fs.close(handle)
        self.assertEqual(file.read_bytes(), b"unchanged")
        self.assertFalse(self.fs.getattr(path)["st_mode"] & 0o222)
        self.assertFalse((self.allowed / "new").exists())

    def test_host_symlinks_hardlinks_fifos_and_sockets_are_hidden(self):
        (self.allowed / "symlink").symlink_to(self.secret / "credential")
        (self.allowed / "directory-link").symlink_to(self.secret, target_is_directory=True)
        os.link(self.secret / "credential", self.allowed / "hardlink")
        os.mkfifo(self.allowed / "fifo")
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(self.allowed / "socket"))
            self.assertEqual(self.fs.readdir(str(self.allowed)), [])
            for name in ("symlink", "directory-link/credential", "hardlink", "fifo", "socket"):
                with self.subTest(name=name):
                    path = str(self.allowed / name)
                    self.assertDenied(self.fs.getattr, path)
                    self.assertDenied(self.fs.open, path)
                    self.assertDenied(self.fs.open, path, read=False, write=True, truncate=True)
                    self.assertDenied(self.fs.chmod, path, 0o600)
                    self.assertDenied(self.fs.utimens, path, (1000, 2000))
                    self.assertDenied(self.fs.truncate, path, 0)
        self.assertEqual((self.secret / "credential").read_bytes(), b"outside-secret")
        self.assertTrue(any(kind == "folder" and target == str(self.allowed)
                            for kind, target, _ in self.policy.denied))

    def test_symlink_grant_root_and_path_traversal_are_denied(self):
        alias = self.root / "alias"
        alias.symlink_to(self.secret, target_is_directory=True)
        self.policy.data["folders"].append({"path": str(alias), "write": True})
        self.assertDenied(self.read, alias / "credential")
        for path in (str(self.allowed) + "/../secret/credential", "//etc/passwd",
                     "/./etc", "/etc\0/passwd", "relative"):
            with self.subTest(path=path):
                self.assertErrno(errno.EINVAL, self.fs.getattr, path)

    def test_swapped_path_never_redirects_data_or_truncates(self):
        for replacement in ("symlink", "file"):
            with self.subTest(replacement=replacement):
                file = self.allowed / f"data-{replacement}"
                file.write_bytes(b"original")
                old = self.allowed / f"old-{replacement}"
                reopen = self.local.primitives.reopen
                swapped = []

                def swapping(pin, flags):
                    if not swapped:
                        swapped.append(True)
                        file.rename(old)
                        if replacement == "symlink":
                            file.symlink_to(self.secret / "credential")
                        else:
                            file.write_bytes(b"replacement")
                    return reopen(pin, flags)

                with patch.object(self.local.primitives, "reopen", side_effect=swapping):
                    try:
                        handle = self.fs.open(str(file), read=False, write=True, truncate=True)
                    except OSError:
                        handle = None
                self.assertTrue(swapped)
                self.assertEqual((self.secret / "credential").read_bytes(), b"outside-secret")
                if replacement == "file":
                    self.assertEqual(file.read_bytes(), b"replacement")
                if self.pinned_reopen:
                    # The checked inode itself was opened and truncated, never the replacement.
                    self.assertIsNotNone(handle)
                    self.assertEqual(old.read_bytes(), b"")
                    self.assertDenied(self.fs.write, handle, b"X", 0)
                    self.fs.close(handle)
                else:
                    self.assertIsNone(handle)
                    self.assertEqual(old.read_bytes(), b"original")

    def test_replaced_or_newly_hardlinked_open_inode_is_denied(self):
        file = self.allowed / "data"
        file.write_bytes(b"original")
        handle = self.fs.open(str(file), read=True, write=True)
        os.link(file, self.root / "outside-alias")
        self.assertDenied(self.fs.read, handle, 20, 0)
        (self.root / "outside-alias").unlink()
        self.assertEqual(self.fs.read(handle, 20, 0), b"original")
        file.rename(self.root / "moved-outside")
        file.write_bytes(b"replacement")
        self.assertDenied(self.fs.write, handle, b"X", 0)
        self.assertDenied(self.fs.read, handle, 20, 0)
        self.fs.close(handle)
        self.assertEqual((self.root / "moved-outside").read_bytes(), b"original")
        self.assertEqual(file.read_bytes(), b"replacement")

    def test_private_subtrees_and_ancestor_renames_stay_inaccessible(self):
        parent = self.allowed / "app"
        private = parent / "state"
        private.mkdir(parents=True)
        (private / "policy.json").write_bytes(b"host-owned")
        self.policy.private_paths = (str(private),)
        self.assertEqual(self.fs.readdir(str(parent)), [])
        self.assertFalse(self.policy.denied)
        self.assertDenied(self.read, private / "policy.json")
        self.assertDenied(self.fs.rename, str(parent), str(self.allowed / "moved"))
        self.assertDenied(self.fs.rmdir, str(parent))
        self.assertEqual((private / "policy.json").read_bytes(), b"host-owned")

    def test_private_paths_reject_filesystem_case_and_unicode_aliases(self):
        for canonical, alias in (("PrivateState", "pRIVATEsTATE"), ("caf\u00e9", "cafe\u0301")):
            with self.subTest(canonical=canonical):
                parent = self.allowed / canonical
                private = parent / "state"
                private.mkdir(parents=True)
                credential = private / "policy.json"
                credential.write_bytes(b"host-owned")
                alias_parent = self.allowed / alias
                if not alias_parent.exists() or not os.path.samefile(parent, alias_parent):
                    continue  # This filesystem treats these names as distinct.
                self.policy.private_paths = (str(private),)
                aliased = alias_parent / "state" / "policy.json"
                self.assertDenied(self.read, aliased)
                self.assertDenied(self.fs.open, str(aliased), write=True, truncate=True)
                self.assertDenied(self.fs.create, str(alias_parent / "state" / "new"), 0o600)
                self.assertDenied(self.fs.chmod, str(aliased), 0o777)
                self.assertDenied(self.fs.utimens, str(aliased), (1000, 2000))
                self.assertDenied(self.fs.unlink, str(aliased))
                self.assertDenied(self.fs.rename, str(alias_parent), str(parent) + "-moved")
                self.assertEqual(self.fs.readdir(str(alias_parent)), [])
                self.assertEqual(credential.read_bytes(), b"host-owned")

    def test_private_name_does_not_hide_distinct_case_sensitive_sibling(self):
        private, public = self.allowed / "State", self.allowed / "state"
        private.mkdir()
        try:
            public.mkdir()
        except FileExistsError:
            self.skipTest("This volume is case-insensitive; distinct-name regression runs on Linux")
        (private / "data").write_bytes(b"private")
        (public / "data").write_bytes(b"public")
        self.policy.private_paths = (str(private),)
        self.assertEqual(self.read(public / "data"), b"public")
        self.assertDenied(self.read, private / "data")

    def test_missing_private_directory_cannot_be_created_via_alias(self):
        parent = self.allowed / "PrivateParent"
        parent.mkdir()
        alias_parent = self.allowed / "pRIVATEpARENT"
        if not alias_parent.exists() or not os.path.samefile(parent, alias_parent):
            self.skipTest("This volume is case-sensitive")
        private = parent / "State"
        self.policy.private_paths = (str(private),)
        self.assertDenied(self.fs.mkdir, str(alias_parent / "sTATE"), 0o700)
        self.assertFalse(private.exists())

    def test_new_private_path_revokes_handles_opened_through_alias(self):
        private = self.allowed / "PrivateState"
        private.mkdir()
        file = private / "data"
        file.write_bytes(b"kept")
        alias = self.allowed / "pRIVATEsTATE"
        if not alias.exists() or not os.path.samefile(alias, private):
            self.skipTest("This volume is case-sensitive")
        handle = self.fs.open(str(alias / "data"), read=True, write=True)
        self.policy.private_paths = (str(private),)
        try:
            self.assertDenied(self.fs.read, handle, 10, 0)
            self.assertDenied(self.fs.write, handle, b"X", 0)
            self.assertDenied(self.fs.truncate, None, 0, handle)
        finally:
            self.fs.close(handle)
        self.assertEqual(file.read_bytes(), b"kept")

    def test_directory_cursor_rejects_same_path_inode_replacement(self):
        directory = self.allowed / "directory"
        directory.mkdir()
        (directory / "old").write_bytes(b"old")
        cursor = self.local.open_directory(str(directory))
        self.addCleanup(cursor.close)
        directory.rename(self.allowed / "moved")
        directory.mkdir()
        (directory / "new").write_bytes(b"new")
        self.assertErrno(errno.EACCES, cursor.page, 2, 1024)
        self.assertErrno(errno.EBADF, cursor.page, 2, 1024)

    def test_directory_cursor_invalidates_revoked_virtual_ancestor(self):
        keep = self.allowed / "keep"
        keep.mkdir()
        for index in range(4):
            (self.allowed / f"secret-{index}").write_bytes(b"secret")
        cursor = self.local.open_directory(str(self.allowed))
        self.addCleanup(cursor.close)
        _, done = cursor.page(1, 1024)
        self.assertFalse(done)
        self.policy.data["folders"] = [{"path": str(keep), "write": False}]
        self.assertErrno(errno.EACCES, cursor.page, 1, 1024)
        self.assertEqual(self.fs.readdir(str(self.allowed)), ["keep"])

    def test_nested_mount_crossing_is_rejected_without_mount_privileges(self):
        file = self.allowed / "file"
        file.write_bytes(b"file")
        inode = file.stat().st_ino
        with patch.object(os, "fstat", side_effect=_foreign_device(os.fstat, inode)), \
                patch.object(os, "stat", side_effect=_foreign_device(os.stat, inode)):
            self.assertErrno(errno.EXDEV, self.read, file)
            self.assertErrno(errno.EXDEV, self.fs.getattr, str(file))

    def test_denial_history_is_bounded_and_deduplicated(self):
        path = str(self.secret)
        for _ in range(10):
            self.assertDenied(self.fs.getattr, path)
        self.assertEqual(len(self.policy.denied), 1)
        self.assertEqual(self.policy.denied[0][:2], ("folder", path))
        for index in range(300):
            self.assertDenied(self.fs.getattr, path + str(index))
        self.assertLessEqual(len(self.local._denials), 256)

    def test_cleared_history_can_record_the_same_denial_again(self):
        path = self.secret / "credential"
        self.assertDenied(self.read, path)
        self.assertDenied(self.read, path)
        self.assertEqual(len(self.policy.denied), 1)
        self.policy.denied.clear()
        self.policy.history_generation = 1
        self.assertDenied(self.read, path)
        self.assertEqual(len(self.policy.denied), 1)

    def test_login_shell_program_lookups_are_not_recorded_but_real_programs_are(self):
        log = DenialLog(self.policy)
        log.record("program", "/programs/-bash", "Not an approved program")
        log.record("folder", "/host/-notes", "Not shared")
        log.record("program", "/programs/rust-analyzer", "Not an approved program")
        self.assertEqual([entry[:2] for entry in self.policy.denied],
                         [("folder", "/host/-notes"), ("program", "/programs/rust-analyzer")])

    def test_operating_system_permission_denial_is_reported_as_such(self):
        file = self.allowed / "data"
        file.write_bytes(b"data")

        def refuse(*args, **kwargs):
            raise OSPermissionError(errno.EPERM, "Operation not permitted")

        with patch.object(self.local.primitives, "pin", side_effect=refuse):
            self.assertErrno(errno.EPERM, self.fs.getattr, str(file))
            self.assertErrno(errno.EPERM, self.fs.open, str(file))
        self.assertIn(("folder", str(file), OS_PERMISSION_REASON), self.policy.denied)
        self.assertNotIn("Full Disk Access", OS_PERMISSION_REASON)

    def test_chmod_restores_permissions_after_mode_zero(self):
        file = self.allowed / "data"
        file.write_bytes(b"owner-data")
        self.addCleanup(file.chmod, 0o600)
        self.fs.chmod(str(file), 0)
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0)
        if self.pathless_metadata:
            self.fs.chmod(str(file), 0o600)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        else:
            # Never a pathname chmod: an object that cannot be opened is unsupported.
            self.assertErrno(errno.ENOTSUP, self.fs.chmod, str(file), 0o600)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0)
            file.chmod(0o600)
        self.assertEqual(file.read_bytes(), b"owner-data")

    def test_metadata_updates_nonreadable_directories_and_grant_root(self):
        child = self.allowed / "directory"
        child.mkdir()
        for directory in (child, self.allowed):
            with self.subTest(directory=directory):
                self.addCleanup(directory.chmod, 0o700)
                path = str(directory)
                self.fs.chmod(path, 0)
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0)
                if self.pathless_metadata:
                    self.fs.utimens(path, (1000, 2000))
                    self.assertEqual(directory.stat().st_mtime_ns, 2000_000_000_000)
                    self.fs.chmod(path, 0o700)
                else:
                    self.assertDenied(self.fs.utimens, path, (1000, 2000))
                    self.assertDenied(self.fs.chmod, path, 0o700)
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0)
                    directory.chmod(0o700)
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_utimens_updates_owner_writable_nonreadable_file(self):
        file = self.allowed / "data"
        file.write_bytes(b"owner-data")
        self.addCleanup(file.chmod, 0o600)
        file.chmod(0o200)
        self.fs.utimens(str(file), (1000, 2000))
        self.assertEqual(file.stat().st_atime_ns, 1000_000_000_000)
        self.assertEqual(file.stat().st_mtime_ns, 2000_000_000_000)
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o200)

    def test_metadata_traverses_execute_only_grant_root_and_parent(self):
        if not self.search_traversal:
            self.skipTest("This platform has no search-only directory descriptor")
        parent = self.allowed / "parent"
        parent.mkdir()
        file = parent / "data"
        file.write_bytes(b"owner-data")
        self.addCleanup(file.chmod, 0o600)
        for directory in (self.allowed, parent):
            with self.subTest(directory=directory):
                self.addCleanup(directory.chmod, 0o700)
                directory.chmod(0o100)
                path = str(file)
                self.fs.chmod(path, 0o200)
                self.fs.utimens(path, (1000, 2000))
                self.assertEqual(file.stat().st_mtime_ns, 2000_000_000_000)
                self.fs.chmod(path, 0o600)
                self.assertEqual(self.read(path), b"owner-data")
                self.assertDenied(self.fs.readdir, str(directory))
                directory.chmod(0o700)


class LocalConcurrency:
    """Rename bookkeeping and lock serialization of a local HostFiles."""

    def host(self, cls):
        fs = cls(self.policy, self.make_primitives())
        self.addCleanup(fs.close_all)
        return fs

    def test_handle_validation_serializes_concurrent_file_and_directory_rename(self):
        for directory, write in ((False, False), (False, True),
                                 (True, False), (True, True)):
            with self.subTest(directory=directory, write=write):
                parent = self.allowed / f"parent-{directory}-{write}"
                parent.mkdir()
                file = parent / "data"
                file.write_bytes(b"original")
                path = str(file)
                source = str(parent if directory else file)
                target = source + "-moved"
                entered, resume, attempted = (threading.Event() for _ in range(3))

                class PausedValidation(HostFiles):
                    def _entry(fs, candidate, *args, **kwargs):
                        if (threading.current_thread().name == "held-io"
                                and candidate == path):
                            entered.set()
                            if not resume.wait(5):
                                raise TimeoutError("Validation was not resumed")
                        return super()._entry(candidate, *args, **kwargs)

                fs = self.host(PausedValidation)
                fs._lock = ObservedRLock("rename", attempted)
                handle = fs.open(path, read=True, write=True)
                results, failures = [], []

                def io():
                    try:
                        results.append(fs.write(handle, b"X", 0) if write
                                       else fs.read(handle, 20, 0))
                    except BaseException as error:
                        failures.append(error)

                def rename():
                    try:
                        fs.rename(source, target)
                    except BaseException as error:
                        failures.append(error)

                reader = threading.Thread(target=io, name="held-io")
                renamer = threading.Thread(target=rename, name="rename")
                reader.start()
                try:
                    self.assertTrue(entered.wait(5), "IO did not reach validation")
                    renamer.start()
                    self.assertTrue(attempted.wait(5), "Rename did not contend")
                finally:
                    resume.set()
                    reader.join(5)
                    if renamer.ident is not None:
                        renamer.join(5)
                self.assertFalse(reader.is_alive())
                self.assertFalse(renamer.is_alive())
                self.assertEqual(failures, [])
                self.assertEqual(results, [1 if write else b"original"])
                self.assertEqual(fs.read(handle, 20, 0),
                                 b"Xriginal" if write else b"original")
                self.assertEqual(fs.handle_path(handle),
                                 target + ("/data" if directory else ""))
                fs.close(handle)

    def test_open_and_create_register_before_concurrent_file_and_parent_rename(self):
        for create in (False, True):
            for directory in (False, True):
                with self.subTest(create=create, directory=directory):
                    parent = self.allowed / f"opening-{create}-{directory}"
                    parent.mkdir()
                    file = parent / "data"
                    if not create:
                        file.write_bytes(b"original")
                    path = str(file)
                    source = str(parent if directory else file)
                    target = source + "-moved"
                    opened, resume, attempted, renamed = (
                        threading.Event() for _ in range(4))

                    class PausedRegistration(HostFiles):
                        def _register(fs, candidate, fd, append):
                            os.fstat(fd)
                            opened.set()
                            if not resume.wait(5):
                                raise TimeoutError("Registration was not resumed")
                            return super()._register(candidate, fd, append)

                    fs = self.host(PausedRegistration)
                    fs._lock = ObservedRLock("opening-rename", attempted)
                    handles, failures = [], []

                    def opening():
                        try:
                            handles.append(fs.create(path, 0o600) if create
                                           else fs.open(path, read=True, write=True))
                        except BaseException as error:
                            failures.append(error)

                    def rename():
                        try:
                            fs.rename(source, target)
                        except BaseException as error:
                            failures.append(error)
                        finally:
                            renamed.set()

                    opener = threading.Thread(target=opening, name="opening")
                    renamer = threading.Thread(target=rename, name="opening-rename")
                    opener.start()
                    try:
                        self.assertTrue(opened.wait(5), "Descriptor was not opened")
                        unlocked = fs._lock.lock.acquire(blocking=False)
                        if unlocked:
                            fs._lock.lock.release()
                        renamer.start()
                        self.assertTrue(attempted.wait(5), "Rename did not contend")
                        if unlocked:
                            self.assertTrue(renamed.wait(5), "Rename did not finish")
                    finally:
                        resume.set()
                        opener.join(5)
                        if renamer.ident is not None:
                            renamer.join(5)
                    self.assertFalse(opener.is_alive())
                    self.assertFalse(renamer.is_alive())
                    self.assertEqual(failures, [])
                    self.assertEqual(len(handles), 1)
                    handle = handles[0]
                    self.assertEqual(fs.read(handle, 20, 0), b"" if create else b"original")
                    self.assertEqual(fs.write(handle, b"X", 0), 1)
                    self.assertEqual(fs.read(handle, 20, 0),
                                     b"X" if create else b"Xriginal")
                    fs.close(handle)

    def test_concurrent_parent_rename_cannot_invalidate_pinned_logical_parent(self):
        parent = self.allowed / "parent"
        parent.mkdir()
        file = parent / "data"
        file.write_bytes(b"original")
        destination = str(self.allowed / "result")
        moved = str(self.allowed / "moved")
        pinned, resume, attempted = (threading.Event() for _ in range(3))

        class PausedParent(HostFiles):
            @contextmanager
            def _parent(fs, entry):
                with super()._parent(entry) as value:
                    if (threading.current_thread().name == "child-rename"
                            and entry.target == str(file) and not pinned.is_set()):
                        pinned.set()
                        if not resume.wait(5):
                            raise TimeoutError("Pinned parent was not resumed")
                    yield value

        fs = self.host(PausedParent)
        fs._lock = ObservedRLock("parent-rename", attempted)
        handle = fs.open(str(file), read=True, write=True)
        failures = []

        def rename(old, new):
            try:
                fs.rename(old, new)
            except BaseException as error:
                failures.append(error)

        child = threading.Thread(target=rename, args=(str(file), destination),
                                 name="child-rename")
        ancestor = threading.Thread(target=rename, args=(str(parent), moved),
                                    name="parent-rename")
        child.start()
        try:
            self.assertTrue(pinned.wait(5), "Child rename did not pin its parent")
            ancestor.start()
            self.assertTrue(attempted.wait(5), "Parent rename did not contend")
        finally:
            resume.set()
            child.join(5)
            if ancestor.ident is not None:
                ancestor.join(5)
        self.assertFalse(child.is_alive())
        self.assertFalse(ancestor.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(fs.read(handle, 20, 0), b"original")
        self.assertEqual(fs.write(handle, b"X", 0), 1)
        self.assertEqual((self.allowed / "result").read_bytes(), b"Xriginal")
        self.assertTrue((self.allowed / "moved").is_dir())
        fs.close(handle)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux O_PATH primitives require Linux")
class LinuxHostFilesTests(HostContract, LocalConcurrency, unittest.TestCase):
    make_primitives = staticmethod(LinuxPrimitives)

    def make_host(self, policy):
        fs = HostFiles(policy, LinuxPrimitives())
        return fs, fs


@unittest.skipUnless(os.name == "posix", "Darwin primitives use POSIX descriptor calls")
class DarwinHostFilesTests(HostContract, LocalConcurrency, unittest.TestCase):
    """The Darwin implementation; it uses only POSIX calls, so Linux hosts run it too."""

    make_primitives = staticmethod(DarwinPrimitives)

    def make_host(self, policy):
        fs = HostFiles(policy, DarwinPrimitives())
        return fs, fs

    def test_platform_default_matches_host(self):
        expected = LinuxPrimitives if sys.platform.startswith("linux") else DarwinPrimitives
        self.assertIsInstance(HostFiles(self.policy).primitives, expected)


if __name__ == "__main__":
    unittest.main()
