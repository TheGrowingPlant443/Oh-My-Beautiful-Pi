"""Synthetic private-copy tests. No real ~/.omp, host credentials or network access.

Run with: python3 -m unittest test_omp_copy
SQLite tests exercise the standard macOS/Linux Unix locking VFS with separate
writer processes, WAL checkpoints/restarts, and exact preservation of host
DB/WAL/shm bytes. Fixture inspection must not release a writer's POSIX locks.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, redirect_stdout
import errno
import io
import json
import os
from pathlib import Path
import select
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import omp_copy
from runtime import Cancelled


_SQLITE_WRITER = """
from contextlib import closing
import sqlite3
import sys
import threading
import time

database, mode = sys.argv[1:]
stop = threading.Event()
threading.Thread(target=lambda: (sys.stdin.buffer.read(1), stop.set()), daemon=True).start()
with closing(sqlite3.connect(database, timeout=5)) as connection:
    if mode == "exclusive":
        connection.execute("pragma locking_mode=exclusive")
    connection.execute("pragma journal_mode=" + ("delete" if mode == "rollback-held" else "wal"))
    connection.execute("pragma wal_autocheckpoint=0")
    if mode != "live":
        connection.execute("create table records(value)")
        connection.commit()
        value = 1 if mode == "held" else "committed in WAL"
        connection.execute("insert into records values (?)", (value,))
        if mode in ("committed", "exclusive"):
            connection.commit()
        print("ready", flush=True)
        stop.wait()
        connection.rollback()
    else:
        connection.execute("create table records(batch integer, half integer, data blob)")
        connection.commit()
if mode == "live":
    batch = 0
    while not stop.is_set():
        with closing(sqlite3.connect(database, timeout=5)) as connection:
            connection.execute("pragma wal_autocheckpoint=0")
            for _ in range(8):
                batch += 1
                connection.executemany("insert into records values (?, ?, ?)",
                                       [(batch, 0, b"x" * 8192), (batch, 1, b"y" * 8192)])
                connection.commit()
                if batch == 1:
                    print("ready", flush=True)
                if batch % 3 == 0:
                    connection.execute("pragma wal_checkpoint(truncate)")
                if stop.is_set():
                    break
                time.sleep(0.002)
"""


class OmpCopyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="omp-copy-test-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        # Darwin's system temporary directory can have a symlinked ancestor.
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "synthetic-host-omp"
        self.source.mkdir(mode=0o700)
        self.state = self.root / "policy"
        self.target = self.state / "home" / ".omp"
        self.previous = self.state / "home" / ".omp.previous"

    @contextmanager
    def sqlite_writer(self, database, mode):
        # POSIX locks belong to a process and closing any fd for their inode
        # releases them. Even read_bytes() in a same-process fixture invalidates
        # the SQLite lock being tested, so every live writer is a separate child.
        process = subprocess.Popen([sys.executable, "-c", _SQLITE_WRITER, str(database), mode],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 10)[0], "Writer did not become ready")
            self.assertEqual(process.stdout.readline(), b"ready\n")
            yield process
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise
            finally:
                error = process.stderr.read().decode()
                process.stdout.close()
                process.stderr.close()
            self.assertEqual(process.returncode, 0, error)

    def snapshot(self):
        stream = io.BytesIO()
        report = omp_copy.write_snapshot(stream, self.source)
        stream.seek(0)
        return stream, report

    def assertNoStages(self):
        self.assertEqual(list(self.state.glob(".omp-copy-stage-*")), [])
        self.assertFalse((self.state / ".omp-copy-pending.json").exists())

    @staticmethod
    def archive(entries, report=True):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                member.mode = 0o700 if kind == tarfile.DIRTYPE else 0o600
                member.type = kind
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    member.linkname = value
                    archive.addfile(member)
                elif kind == tarfile.REGTYPE:
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
                else:
                    archive.addfile(member)
            if report:
                payload = json.dumps(report if isinstance(report, dict) else {
                    "version": 1, "source_missing": False,
                    **dict.fromkeys(omp_copy._COUNTS, 0)}).encode()
                member = tarfile.TarInfo("report.json")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        stream.seek(0)
        return stream

    def test_full_contents_permissions_metadata_and_private_wire_format(self):
        (self.source / "credentials").mkdir(mode=0o750)
        (self.source / "credentials" / "token.json").write_text('{"fake":"credential"}')
        (self.source / ".env").write_text("SYNTHETIC_SECRET=not-real\n")
        (self.source / "docs").mkdir()
        (self.source / "docs" / "guide.md").write_text("documentation\n")
        (self.source / "report.json").write_text("a normal source filename")
        (self.source / "back\\slash").write_text("valid Unix filename")
        executable = self.source / "run"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o751)
        os.utime(executable, (1_234_567_890.25, 1_234_567_890.25))
        os.utime(self.source / "credentials", (1_234_567_880.5, 1_234_567_880.5))
        stream, report = self.snapshot()
        with tarfile.open(fileobj=io.BytesIO(stream.getvalue()), mode="r:") as archive:
            for member in archive:
                self.assertFalse(member.name.startswith("/"))
                self.assertEqual((member.uid, member.gid, member.uname, member.gname),
                                 (0, 0, "", ""))
        self.assertNotIn(str(self.source).encode(), stream.getvalue())
        installed = omp_copy.install_snapshot(stream, self.state)
        self.assertEqual(installed, {**report, "copied": True})
        self.assertEqual((self.target / "credentials" / "token.json").read_text(),
                         '{"fake":"credential"}')
        self.assertEqual((self.target / ".env").read_text(), "SYNTHETIC_SECRET=not-real\n")
        self.assertEqual((self.target / "docs" / "guide.md").read_text(), "documentation\n")
        self.assertEqual((self.target / "report.json").read_text(), "a normal source filename")
        self.assertEqual((self.target / "back\\slash").read_text(), "valid Unix filename")
        self.assertEqual(stat.S_IMODE((self.target / "run").stat().st_mode), 0o751)
        self.assertEqual(stat.S_IMODE((self.target / "credentials").stat().st_mode), 0o750)
        self.assertAlmostEqual((self.target / "run").stat().st_mtime, 1_234_567_890.25)
        self.assertAlmostEqual((self.target / "credentials").stat().st_mtime, 1_234_567_880.5)
        self.assertEqual(stat.S_IMODE((self.state / "omp-copy.json").stat().st_mode), 0o600)
        self.assertNoStages()

    def test_independent_files_hardlinks_and_restart_do_not_recopy(self):
        original = self.source / "data"
        original.write_text("host original")
        os.link(original, self.source / "another-name")
        receipt = omp_copy.copy_once(self.source, self.state)
        self.assertNotEqual(original.stat().st_ino, (self.target / "data").stat().st_ino)
        self.assertNotEqual((self.target / "data").stat().st_ino,
                            (self.target / "another-name").stat().st_ino)
        (self.target / "data").write_text("sandbox edit")
        original.write_text("host edit")
        with patch.object(omp_copy, "write_snapshot", side_effect=AssertionError("must not recopy")):
            self.assertEqual(omp_copy.copy_once(self.source, self.state), receipt)
            self.assertEqual(omp_copy.install_snapshot(io.BytesIO(b"not read"), self.state), receipt)
        self.assertEqual((self.target / "data").read_text(), "sandbox edit")
        self.assertEqual((self.target / "another-name").read_text(), "host original")
        self.assertEqual(original.read_text(), "host edit")
        self.assertEqual(omp_copy.copy_status(self.state), receipt)

    def test_initial_backup_recopy_and_explicit_previous_replacement(self):
        self.target.mkdir(parents=True)
        (self.target / "data").write_text("preexisting sandbox")
        (self.source / "data").write_text("first host copy")
        omp_copy.copy_once(self.source, self.state)
        self.assertEqual((self.previous / "data").read_text(), "preexisting sandbox")
        (self.target / "data").write_text("private changes")
        (self.source / "data").write_text("new host contents")
        omp_copy.copy_once(self.source, self.state)
        self.assertEqual((self.previous / "data").read_text(), "preexisting sandbox")
        self.assertEqual((self.target / "data").read_text(), "private changes")
        omp_copy.copy_once(self.source, self.state, replace=True, request_id="1" * 32)
        self.assertEqual((self.previous / "data").read_text(), "private changes")
        self.assertEqual((self.target / "data").read_text(), "new host contents")
        self.assertNoStages()

    def test_copy_request_requires_exact_durable_identity(self):
        self.assertIsNone(omp_copy.read_copy_request(self.state))
        self.assertFalse(self.state.exists())
        self.state.mkdir()
        self.assertIsNone(omp_copy.read_copy_request(self.state))
        marker = self.state / "omp-recopy.json"
        request = {"replace_previous": True, "request_id": "0123456789abcdef" * 2}
        marker.write_text(json.dumps(request))
        self.assertEqual(omp_copy.read_copy_request(self.state), request["request_id"])
        self.assertEqual(json.loads(marker.read_text()), request)
        invalid = [None, [], True, {}, {"replace_previous": True},
                   {**request, "replace_previous": False},
                   {**request, "replace_previous": 1}, {**request, "extra": True}]
        invalid.extend({**request, "request_id": value}
                       for value in (None, 1, "", "a" * 31, "a" * 33, "A" * 32, "g" * 32,
                                     "01234567-89ab-cdef-0123-456789abcdef"))
        for value in invalid:
            with self.subTest(value=value):
                marker.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "request"):
                    omp_copy.read_copy_request(self.state)
                self.assertEqual(json.loads(marker.read_text()), value)
        for payload in ("{", " " * 65537):
            with self.subTest(payload=payload[:10]):
                marker.write_text(payload)
                with self.assertRaises(ValueError):
                    omp_copy.read_copy_request(self.state)

    def test_copy_request_rejects_symlinks_and_nonregular_files(self):
        self.state.mkdir()
        marker = self.state / "omp-recopy.json"
        outside = self.root / "outside"
        outside.mkdir()
        original = json.dumps({"replace_previous": True, "request_id": "1" * 32})
        (outside / marker.name).write_text(original)
        marker.symlink_to(outside / marker.name)
        with self.assertRaises(OSError):
            omp_copy.read_copy_request(self.state)
        marker.unlink()
        marker.mkdir()
        with self.assertRaises((OSError, RuntimeError)):
            omp_copy.read_copy_request(self.state)
        marker.rmdir()
        os.mkfifo(marker)
        with self.assertRaises(RuntimeError):
            omp_copy.read_copy_request(self.state)
        linked_state = self.root / "linked-state"
        linked_state.symlink_to(outside, target_is_directory=True)
        for state in (linked_state, linked_state / "nested"):
            with self.subTest(state=state):
                with self.assertRaises(OSError):
                    omp_copy.read_copy_request(state)
        self.assertEqual((outside / marker.name).read_text(), original)
        self.assertFalse((outside / "nested").exists())

    def test_recopy_api_requires_valid_id_and_explicit_replacement(self):
        for api, source in ((omp_copy.copy_once, self.source),
                            (omp_copy.install_snapshot, io.BytesIO(b"must not be read"))):
            for request_id in (None, "", "A" * 32, "g" * 32, "0" * 31, 123):
                with self.subTest(api=api.__name__, request_id=request_id):
                    with self.assertRaisesRegex(ValueError, "request_id"):
                        api(source, self.state, replace=True, request_id=request_id)
            with self.subTest(api=api.__name__, replace=False):
                with self.assertRaisesRegex(ValueError, "requires replace=True"):
                    api(source, self.state, request_id="1" * 32)
        self.assertFalse(self.state.exists())

    def test_archive_report_cannot_authorize_or_override_recopy_identity(self):
        report = {"version": 1, "source_missing": False,
                  **dict.fromkeys(omp_copy._COUNTS, 0), "request_id": "f" * 32}
        entries = [("tree", tarfile.DIRTYPE, None)]
        initial = omp_copy.install_snapshot(self.archive(entries, report), self.state)
        self.assertNotIn("request_id", initial)
        self.assertNotIn("request_id", omp_copy.copy_status(self.state))
        actual = omp_copy.install_snapshot(self.archive(entries, report), self.state,
                                           replace=True, request_id="1" * 32)
        self.assertEqual(actual["request_id"], "1" * 32)
        self.assertEqual(omp_copy.copy_status(self.state), actual)

    def test_existing_previous_without_receipt_requires_consent(self):
        self.target.mkdir(parents=True)
        self.previous.mkdir()
        (self.target / "data").write_text("current")
        (self.previous / "data").write_text("older")
        (self.source / "data").write_text("source")
        with self.assertRaisesRegex(FileExistsError, "explicitly"):
            omp_copy.copy_once(self.source, self.state)
        self.assertEqual((self.target / "data").read_text(), "current")
        self.assertEqual((self.previous / "data").read_text(), "older")
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()

    def test_missing_source_is_an_empty_once_only_copy(self):
        self.source.rmdir()
        report = omp_copy.copy_once(self.source, self.state)
        self.assertTrue(report["source_missing"])
        self.assertTrue(report["copied"])
        self.assertEqual(list(self.target.iterdir()), [])
        (self.target / "private").write_text("keep me")
        self.source.mkdir()
        (self.source / "late").write_text("not automatically copied")
        omp_copy.copy_once(self.source, self.state)
        self.assertEqual((self.target / "private").read_text(), "keep me")
        self.assertFalse((self.target / "late").exists())

    def test_symlink_text_special_files_and_external_link_chains(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_text("must not be archived")
        (self.source / "file").write_text("inside")
        os.symlink("file", self.source / "inside")
        os.symlink(str(outside), self.source / "absolute")
        os.symlink("../outside", self.source / "relative")
        os.symlink("relative/secret", self.source / "chain")
        os.symlink("missing", self.source / "dangling")
        os.symlink("cycle", self.source / "cycle")
        os.mkfifo(self.source / "fifo")
        endpoint = socket.socket(socket.AF_UNIX)
        self.addCleanup(endpoint.close)
        endpoint.bind(str(self.source / "socket"))
        stream, report = self.snapshot()
        self.assertEqual(report["special_files"], 2)
        self.assertEqual(report["external_links"], 3)
        self.assertNotIn(b"must not be archived", stream.getvalue())
        omp_copy.install_snapshot(stream, self.state)
        for name in ("inside", "absolute", "relative", "chain", "dangling", "cycle"):
            self.assertEqual(os.readlink(self.target / name), os.readlink(self.source / name))
        self.assertFalse((self.target / "fifo").exists())
        self.assertFalse((self.target / "socket").exists())

    @unittest.skipUnless(shutil.which("git"), "synthetic repository tests require Git")
    def test_git_clean_dirty_ignored_untracked_branches_and_history(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("GIT_")}
        environment.update(HOME=str(self.root / "git-home"),
                           XDG_CONFIG_HOME=str(self.root / "git-config"),
                           GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_TERMINAL_PROMPT="0")

        def git(directory, *args):
            result = subprocess.run(
                ["git", "-c", "core.hooksPath=" + os.devnull, "-c", "commit.gpgsign=false",
                 "-c", "init.templateDir=", "-C", str(directory), *args],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            return result.stdout

        expected = {}
        for name in ("clean", "dirty"):
            repository = self.source / name
            repository.mkdir()
            git(repository, "init", "-b", "main")
            git(repository, "config", "user.name", "Synthetic Test")
            git(repository, "config", "user.email", "synthetic@example.invalid")
            (repository / "tracked").write_text("first\n")
            (repository / ".gitignore").write_text("ignored\n")
            git(repository, "add", ".")
            git(repository, "commit", "-m", "first")
            git(repository, "checkout", "-b", "feature")
            (repository / "tracked").write_text("second\n")
            git(repository, "commit", "-am", "second")
            if name == "dirty":
                (repository / "tracked").write_text("dirty worktree\n")
                (repository / "untracked").write_text("untracked\n")
                (repository / "ignored").write_text("ignored but included\n")
                (repository / ".env").write_text("FAKE_KEY=included\n")
            expected[name] = [git(repository, *args) for args in
                              (("rev-parse", "HEAD"), ("branch", "--list"),
                               ("log", "--format=%H"), ("status", "--porcelain", "--ignored"))]
        # Copying regular Git files must invoke no subprocess at all.
        with patch.object(omp_copy.subprocess, "Popen", side_effect=AssertionError("no Git transport")):
            omp_copy.copy_once(self.source, self.state)
        for name in ("clean", "dirty"):
            repository = self.target / name
            actual = [git(repository, *args) for args in
                      (("rev-parse", "HEAD"), ("branch", "--list"),
                       ("log", "--format=%H"), ("status", "--porcelain", "--ignored"))]
            self.assertEqual(actual, expected[name])
        self.assertEqual((self.target / "dirty" / "ignored").read_text(), "ignored but included\n")
        self.assertEqual((self.target / "dirty" / ".env").read_text(), "FAKE_KEY=included\n")

    def test_external_gitdir_and_git_symlink_fail_clearly(self):
        (self.source / ".git").write_text("gitdir: ../external-repository/worktrees/work\n")
        with self.assertRaisesRegex(ValueError, "external gitdir"):
            omp_copy.copy_once(self.source, self.state)
        (self.source / ".git").unlink()
        os.symlink("../external-repository", self.source / ".git")
        with self.assertRaisesRegex(ValueError, "external .git symlink"):
            omp_copy.copy_once(self.source, self.state)
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()

    def test_gitdir_through_external_symlink_and_object_alternates_fail(self):
        os.symlink("../external-git", self.source / "git-location")
        (self.source / ".git").write_text("gitdir: git-location/worktrees/test\n")
        with self.assertRaisesRegex(ValueError, "external gitdir"):
            omp_copy.copy_once(self.source, self.state)
        (self.source / ".git").unlink()
        info = self.source / ".git" / "objects" / "info"
        info.mkdir(parents=True)
        for target in ("../../../outside-objects", str(self.root / "outside-objects"),
                       json.dumps(str(self.root / "outside-objects"))):
            with self.subTest(target=target):
                (info / "alternates").write_text(target + "\n")
                with self.assertRaisesRegex(ValueError, "Git object alternates"):
                    omp_copy.copy_once(self.source, self.state)
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()

    def test_sqlite_committed_wal_and_host_files_are_unchanged(self):
        database = self.source / "sessions.data"
        with self.sqlite_writer(database, "committed"):
            before = {path.name: path.read_bytes() for path in self.source.iterdir()}
            self.assertIn("sessions.data-wal", before)
            # Suffixes belonging to non-databases are ordinary, included files.
            (self.source / "ordinary-wal").write_text("not a SQLite sidecar")
            (self.source / "ordinary-shm").write_text("also ordinary")
            report = omp_copy.copy_once(self.source, self.state)
            self.assertEqual(report["sqlite_databases"], 1)
            after = {path.name: path.read_bytes() for path in self.source.iterdir()
                     if path.name.startswith("sessions.data")}
            self.assertEqual(after, before)
            # Opening a WAL-mode backup may create new private sidecars. Check
            # the transported snapshot before SQLite opens the destination.
            self.assertFalse((self.target / "sessions.data-wal").exists())
            self.assertFalse((self.target / "sessions.data-shm").exists())
            with closing(sqlite3.connect(self.target / "sessions.data")) as copied:
                self.assertEqual(copied.execute("select * from records").fetchall(),
                                 [("committed in WAL",)])
                self.assertEqual(copied.execute("pragma integrity_check").fetchone(), ("ok",))
            self.assertEqual((self.target / "ordinary-wal").read_text(), "not a SQLite sidecar")
            self.assertEqual((self.target / "ordinary-shm").read_text(), "also ordinary")

    def test_sqlite_scratch_ignores_tmpdir_inside_source_and_is_private(self):
        with closing(sqlite3.connect(self.source / "db")) as database:
            database.execute("create table records(value text)")
            database.commit()
        capture = omp_copy._sqlite_capture
        destinations = []

        def inspect_capture(parent, name, fd, destination, check, progress, relative):
            destinations.append(destination)
            self.assertNotIn(self.source, destination.parents)
            self.assertNotIn(self.state / "home", destination.parents)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            capture(parent, name, fd, destination, check, progress, relative)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600
                                for path in destination.iterdir()))

        with patch.dict(os.environ, {"TMPDIR": str(self.source)}), \
                patch.object(tempfile, "tempdir", str(self.source)), \
                patch.object(omp_copy, "_sqlite_capture", side_effect=inspect_capture):
            omp_copy.copy_once(self.source, self.state)
        self.assertTrue(destinations)
        self.assertTrue(all(not path.exists() for path in destinations))
        self.assertEqual(sorted(path.name for path in self.source.iterdir()), ["db"])

    def test_live_wal_concurrent_writer_checkpoint_and_restart_are_coherent(self):
        database = self.source / "live.db"
        with self.sqlite_writer(database, "live"):
            report = omp_copy.copy_once(self.source, self.state)
        self.assertEqual(report["sqlite_databases"], 1)
        with closing(sqlite3.connect(self.target / "live.db")) as copied:
            self.assertEqual(copied.execute("pragma integrity_check").fetchone(), ("ok",))
            groups = copied.execute("select batch, count(*), sum(half) from records group by batch").fetchall()
            self.assertTrue(groups)
            self.assertTrue(all(count == 2 and halves == 1 for _, count, halves in groups))
            self.assertEqual([batch for batch, _, _ in groups], list(range(1, len(groups) + 1)))

    def test_sqlite_capture_wait_is_cancellable_and_never_changes_host(self):
        database = self.source / "held.db"
        with self.sqlite_writer(database, "held"):
            before = {path.name: path.read_bytes() for path in self.source.iterdir()}
            capture = []
            spawn = subprocess.Popen

            def start_capture(*args, **kwargs):
                process = spawn(*args, **kwargs)
                capture.append((process, time.monotonic() + 0.2))
                return process

            def cancel():
                if capture:
                    process, deadline = capture[0]
                    self.assertIsNone(process.poll(), "Capture bypassed the held SQLite writer lock")
                    if time.monotonic() >= deadline:
                        raise Cancelled("cancel synthetic waiting copy")

            with patch.object(omp_copy.subprocess, "Popen", side_effect=start_capture), self.assertRaises(Cancelled):
                omp_copy.copy_once(self.source, self.state, check=cancel)
            self.assertEqual({path.name: path.read_bytes() for path in self.source.iterdir()}, before)
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()

    def test_sqlite_exclusive_browser_lock_times_out_with_path_and_progress(self):
        directory = self.source / "browser-profiles" / "Default"
        directory.mkdir(parents=True)
        database = directory / "Account Web Data"
        messages = []
        with self.sqlite_writer(database, "exclusive"):
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            started = time.monotonic()
            with patch.object(omp_copy, "_SQLITE_LOCK_TIMEOUT", 0.3), \
                    patch.object(omp_copy, "_SQLITE_PROGRESS_INTERVAL", 0.05):
                with self.assertRaisesRegex(
                        RuntimeError, "browser-profiles/Default/Account Web Data.*Close the application"):
                    omp_copy.copy_once(self.source, self.state, progress=messages.append)
            self.assertLess(time.monotonic() - started, 3)
            self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)
        self.assertIn("browser-profiles/Default/Account Web Data", messages[0])
        self.assertTrue(any("waiting:" in message and "elapsed" in message for message in messages))
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()

    def test_sqlite_exclusive_lock_release_completes_same_full_copy(self):
        (self.source / ".env").write_text("SYNTHETIC_SECRET=keep")
        (self.source / "credentials").write_text("synthetic credential")
        (self.source / "docs").mkdir()
        (self.source / "docs" / "notes").write_text("included")
        (self.source / ".git").mkdir()
        (self.source / ".git" / "HEAD").write_text("ref: refs/heads/main")
        database = self.source / "Account Web Data"
        messages = []
        with self.sqlite_writer(database, "exclusive") as writer:
            released = False

            def progress(message):
                nonlocal released
                messages.append(message)
                if "waiting:" in message and not released:
                    released = True
                    writer.stdin.write(b"x")
                    writer.stdin.flush()

            with patch.object(omp_copy, "_SQLITE_PROGRESS_INTERVAL", 0.05):
                report = omp_copy.copy_once(self.source, self.state, progress=progress)
            self.assertTrue(released, messages)
        self.assertEqual(report["sqlite_databases"], 1)
        for relative in (".env", "credentials", "docs/notes", ".git/HEAD"):
            self.assertEqual((self.target / relative).read_bytes(), (self.source / relative).read_bytes())
        with closing(sqlite3.connect(self.target / database.name)) as copied:
            self.assertEqual(copied.execute("pragma integrity_check").fetchone(), ("ok",))
            self.assertEqual(copied.execute("select * from records").fetchall(), [("committed in WAL",)])
        self.assertNoStages()

    def test_sqlite_rollback_journal_uncommitted_changes_are_not_copied(self):
        database = self.source / "rollback.db"
        with self.sqlite_writer(database, "rollback-held"):
            before = {path.name: path.read_bytes() for path in self.source.iterdir()}
            omp_copy.copy_once(self.source, self.state)
            self.assertEqual({path.name: path.read_bytes() for path in self.source.iterdir()}, before)
        with closing(sqlite3.connect(self.target / database.name)) as copied:
            self.assertEqual(copied.execute("pragma integrity_check").fetchone(), ("ok",))
            self.assertEqual(copied.execute("select * from records").fetchall(), [])
        self.assertNoStages()

    def test_sqlite_permission_errors_are_not_retried_as_contention(self):
        database = self.source / "db"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("create table records(value)")
        destination = self.root / "capture"
        destination.mkdir()
        with omp_copy._directory(self.source) as parent:
            descriptor = omp_copy._regular(parent, database.name)
            try:
                for operation in ("_sidecar", "_copy_fd"):
                    with self.subTest(operation=operation), redirect_stdout(io.StringIO()), \
                            patch.object(omp_copy, operation, side_effect=PermissionError(errno.EACCES, "denied")), \
                            patch.object(omp_copy.time, "sleep", side_effect=AssertionError("must not retry")):
                        with self.assertRaises(PermissionError):
                            omp_copy._sqlite_worker(parent, database.name, descriptor, destination)
            finally:
                os.close(descriptor)

    def test_disappearing_source_entry_fails_without_publishing_or_skipping(self):
        (self.source / "credentials").write_text("synthetic credential")
        original = omp_copy._stat

        def disappear(parent, name):
            if name == "credentials":
                return None
            return original(parent, name)

        with patch.object(omp_copy, "_stat", side_effect=disappear):
            with self.assertRaisesRegex(RuntimeError, "credentials.*retry Start.*No files were skipped"):
                omp_copy.copy_once(self.source, self.state)
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()
        omp_copy.copy_once(self.source, self.state)
        self.assertEqual((self.target / "credentials").read_text(), "synthetic credential")

    def test_destination_symlinks_are_not_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "keep").write_text("outside")
        self.state.mkdir()
        os.symlink(outside, self.state / "home")
        (self.source / "data").write_text("new")
        with self.assertRaises(OSError):
            omp_copy.copy_once(self.source, self.state)
        self.assertEqual(sorted(path.name for path in outside.iterdir()), ["keep"])
        (self.state / "home").unlink()
        (self.state / "home").mkdir()
        os.symlink(outside, self.target)
        omp_copy.copy_once(self.source, self.state)
        self.assertTrue(self.previous.is_symlink())
        self.assertEqual(os.readlink(self.previous), str(outside))
        self.assertFalse(self.target.is_symlink())
        omp_copy.copy_once(self.source, self.state, replace=True, request_id="1" * 32)
        self.assertEqual((outside / "keep").read_text(), "outside")
        self.assertEqual(sorted(path.name for path in outside.iterdir()), ["keep"])
        self.assertNoStages()

    def test_marker_and_state_parent_symlinks_are_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker.write_text("untouched")
        self.state.mkdir()
        os.symlink(marker, self.state / "omp-copy.json")
        with self.assertRaises(OSError):
            omp_copy.copy_once(self.source, self.state)
        self.assertEqual(marker.read_text(), "untouched")
        alias = self.root / "alias"
        os.symlink(outside, alias)
        with self.assertRaises(OSError):
            omp_copy.copy_once(self.source, alias / "nested")
        self.assertFalse((outside / "nested").exists())

    def test_source_swap_cannot_redirect_a_regular_file_read(self):
        (self.source / "victim").write_text("original")
        outside = self.root / "outside-secret"
        outside.write_text("must not be read")
        real_open = os.open
        switched = False

        def swap(name, flags, *args, **kwargs):
            nonlocal switched
            if name == "victim" and kwargs.get("dir_fd") is not None and not switched:
                switched = True
                (self.source / "victim").unlink()
                os.symlink(outside, self.source / "victim")
            return real_open(name, flags, *args, **kwargs)

        with patch.object(omp_copy.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                omp_copy.copy_once(self.source, self.state)
        self.assertTrue(switched)
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()

    def test_source_directory_swap_cannot_redirect_traversal(self):
        (self.source / "docs").mkdir()
        (self.source / "docs" / "inside").write_text("original")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_text("must not be read")
        real_open = os.open
        switched = False

        def swap(name, flags, *args, **kwargs):
            nonlocal switched
            if name == "docs" and flags & os.O_DIRECTORY and not switched:
                switched = True
                (self.source / "docs").rename(self.root / "displaced-docs")
                os.symlink(outside, self.source / "docs")
            return real_open(name, flags, *args, **kwargs)

        with patch.object(omp_copy.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                omp_copy.copy_once(self.source, self.state)
        self.assertTrue(switched)
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()

    def test_malicious_archives_never_escape_or_publish(self):
        outside = self.root / "outside"
        outside.mkdir()
        cases = [
            [("../escape", tarfile.REGTYPE, b"bad")],
            [(str(outside / "absolute"), tarfile.REGTYPE, b"bad")],
            [("tree/../escape", tarfile.REGTYPE, b"bad")],
            [("tree/link", tarfile.SYMTYPE, str(outside)),
             ("tree/link/escape", tarfile.REGTYPE, b"bad")],
            [("tree/link", tarfile.LNKTYPE, str(outside / "secret"))],
            [("tree/fifo", tarfile.FIFOTYPE, None)],
            [("tree/duplicate", tarfile.REGTYPE, b"one"),
             ("tree/duplicate", tarfile.REGTYPE, b"two")],
        ]
        for index, entries in enumerate(cases):
            with self.subTest(index=index):
                stream = self.archive([("tree", tarfile.DIRTYPE, None), *entries])
                with self.assertRaises((OSError, ValueError)):
                    omp_copy.install_snapshot(stream, self.state)
                self.assertFalse(omp_copy.copy_status(self.state)["copied"])
                self.assertFalse(self.target.exists())
                self.assertNoStages()
        with self.assertRaises(ValueError):
            omp_copy.install_snapshot(self.archive([("tree", tarfile.SYMTYPE, str(outside))]),
                                      self.state)
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            omp_copy.install_snapshot(self.archive([("tree", tarfile.DIRTYPE, None)], report=False),
                                      self.state)
        self.assertEqual(list(outside.iterdir()), [])

    def test_cancellation_removes_only_private_staging(self):
        self.target.mkdir(parents=True)
        (self.target / "keep").write_text("old sandbox")
        (self.source / "new").write_bytes(b"x" * (3 * 1024 * 1024))
        stream, _ = self.snapshot()

        def cancel_during_extraction():
            if any((path / "tree").exists() for path in self.state.glob(".omp-copy-stage-*")):
                raise Cancelled("cancel synthetic extraction")

        with self.assertRaises(Cancelled):
            omp_copy.install_snapshot(stream, self.state, check=cancel_during_extraction)
        self.assertEqual((self.target / "keep").read_text(), "old sandbox")
        self.assertFalse(self.previous.exists())
        self.assertFalse(omp_copy.copy_status(self.state)["copied"])
        self.assertNoStages()

    def test_interrupted_publish_recovers_staged_copy_without_recapture(self):
        self.target.mkdir(parents=True)
        (self.target / "keep").write_text("old sandbox")
        (self.source / "data").write_text("snapshot")
        real_replace = os.replace

        def fail_receipt(source, destination, *args, **kwargs):
            if destination == "omp-copy.json":
                raise OSError("synthetic interruption after publish")
            return real_replace(source, destination, *args, **kwargs)

        with patch.object(omp_copy.os, "replace", side_effect=fail_receipt):
            with self.assertRaisesRegex(OSError, "synthetic interruption"):
                omp_copy.copy_once(self.source, self.state)
        (self.source / "data").write_text("later host content must not be recaptured")
        with patch.object(omp_copy, "write_snapshot", side_effect=AssertionError("no recapture")):
            self.assertTrue(omp_copy.copy_once(self.source, self.state)["copied"])
        self.assertEqual((self.target / "data").read_text(), "snapshot")
        self.assertEqual((self.previous / "keep").read_text(), "old sandbox")
        self.assertNoStages()

    def test_recopy_replay_after_publish_cleanup_failure_preserves_backup(self):
        (self.source / "data").write_text("initial host")
        omp_copy.copy_once(self.source, self.state)
        (self.target / "data").write_text("private edits to preserve")
        (self.source / "data").write_text("replacement host")
        request_id = "1" * 32
        marker = self.state / "omp-recopy.json"
        marker.write_text(json.dumps({"replace_previous": True, "request_id": request_id}))
        real_remove = omp_copy._remove
        failed = False

        def fail_cleanup(parent, name):
            nonlocal failed
            if not failed and name.startswith(".omp-copy-stage-"):
                failed = True
                raise OSError("synthetic cleanup failure after receipt")
            return real_remove(parent, name)

        with patch.object(omp_copy, "_remove", side_effect=fail_cleanup):
            with self.assertRaisesRegex(OSError, "synthetic cleanup failure"):
                omp_copy.copy_once(self.source, self.state, replace=True, request_id=request_id)
        self.assertTrue(failed)
        self.assertEqual(omp_copy.read_copy_request(self.state), request_id)
        receipt = omp_copy.copy_status(self.state)
        self.assertEqual(receipt["request_id"], request_id)
        self.assertEqual(json.loads((self.state / "omp-copy.json").read_text()), receipt)
        (self.previous / "data").write_text("backup edits after failed acknowledgement")
        (self.target / "data").write_text("current edits after failed acknowledgement")
        with patch.object(omp_copy, "write_snapshot", side_effect=AssertionError("no recapture")):
            self.assertEqual(omp_copy.copy_once(self.source, self.state, replace=True,
                                                request_id=request_id), receipt)
            self.assertEqual(omp_copy.install_snapshot(io.BytesIO(b"must not be read"), self.state,
                                                       replace=True, request_id=request_id), receipt)
        self.assertEqual((self.previous / "data").read_text(),
                         "backup edits after failed acknowledgement")
        self.assertEqual((self.target / "data").read_text(),
                         "current edits after failed acknowledgement")
        new_receipt = omp_copy.copy_once(self.source, self.state, replace=True, request_id="2" * 32)
        self.assertEqual(new_receipt["request_id"], "2" * 32)
        self.assertEqual((self.previous / "data").read_text(),
                         "current edits after failed acknowledgement")
        self.assertEqual((self.target / "data").read_text(), "replacement host")
        self.assertNoStages()

    def test_recopy_replay_recovers_interrupted_receipt_without_rotating_backup(self):
        (self.source / "data").write_text("initial host")
        omp_copy.copy_once(self.source, self.state)
        (self.target / "data").write_text("private edits")
        (self.source / "data").write_text("replacement host")
        stream, _ = self.snapshot()
        request_id = "1" * 32
        real_replace = os.replace

        def fail_receipt(source, destination, *args, **kwargs):
            if destination == "omp-copy.json":
                raise OSError("synthetic interruption after recopy publish")
            return real_replace(source, destination, *args, **kwargs)

        with patch.object(omp_copy.os, "replace", side_effect=fail_receipt):
            with self.assertRaisesRegex(OSError, "synthetic interruption"):
                omp_copy.install_snapshot(stream, self.state, replace=True, request_id=request_id)
        intent = json.loads((self.state / ".omp-copy-pending.json").read_text())
        self.assertEqual(intent["report"]["request_id"], request_id)
        (self.previous / "data").write_text("original backup with later private edits")
        (self.target / "data").write_text("published target with later private edits")
        receipt = omp_copy.install_snapshot(io.BytesIO(b"must not be read"), self.state,
                                             replace=True, request_id=request_id)
        self.assertEqual(receipt["request_id"], request_id)
        self.assertEqual(omp_copy.copy_status(self.state), receipt)
        with patch.object(omp_copy, "write_snapshot", side_effect=AssertionError("no recapture")):
            self.assertEqual(omp_copy.copy_once(self.source, self.state, replace=True,
                                                request_id=request_id), receipt)
        self.assertEqual((self.previous / "data").read_text(),
                         "original backup with later private edits")
        self.assertEqual((self.target / "data").read_text(),
                         "published target with later private edits")
        new_receipt = omp_copy.install_snapshot(self.snapshot()[0], self.state,
                                                replace=True, request_id="2" * 32)
        self.assertEqual(new_receipt["request_id"], "2" * 32)
        self.assertEqual((self.previous / "data").read_text(),
                         "published target with later private edits")
        self.assertEqual((self.target / "data").read_text(), "replacement host")
        self.assertNoStages()

    def test_interrupted_backup_move_recovers_without_losing_either_backup(self):
        self.target.mkdir(parents=True)
        self.previous.mkdir()
        (self.target / "keep").write_text("current sandbox")
        (self.previous / "keep").write_text("older backup")
        (self.source / "data").write_text("snapshot")
        real_rename = os.rename

        def fail_publication(source, destination, *args, **kwargs):
            if source == "tree" and destination == ".omp":
                raise OSError("synthetic interruption before publication")
            return real_rename(source, destination, *args, **kwargs)

        with patch.object(omp_copy.os, "rename", side_effect=fail_publication):
            with self.assertRaisesRegex(OSError, "synthetic interruption"):
                omp_copy.copy_once(self.source, self.state, replace=True, request_id="1" * 32)
        (self.previous / "keep").write_text("current sandbox with backup edits")
        with patch.object(omp_copy, "write_snapshot", side_effect=AssertionError("no recapture")):
            receipt = omp_copy.copy_once(self.source, self.state, replace=True, request_id="1" * 32)
        self.assertEqual(receipt["request_id"], "1" * 32)
        self.assertEqual(omp_copy.copy_status(self.state), receipt)
        self.assertEqual((self.target / "data").read_text(), "snapshot")
        self.assertEqual((self.previous / "keep").read_text(), "current sandbox with backup edits")
        self.assertNoStages()

    def test_concurrent_initial_requests_generate_one_snapshot(self):
        (self.source / "data").write_text("once")
        original = omp_copy.write_snapshot
        entered = threading.Event()
        release = threading.Event()

        def capture(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("synthetic test did not release copy")
            return original(*args, **kwargs)

        with patch.object(omp_copy, "write_snapshot", side_effect=capture) as snapshot:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(omp_copy.copy_once, self.source, self.state)
                self.assertTrue(entered.wait(5))
                second = pool.submit(omp_copy.copy_once, self.source, self.state)
                release.set()
                self.assertEqual(first.result(10), second.result(10))
            self.assertEqual(snapshot.call_count, 1)
        self.assertNoStages()

    def test_source_and_state_must_not_overlap(self):
        with self.assertRaisesRegex(ValueError, "overlap"):
            omp_copy.copy_once(self.source, self.source / "policy")
        with self.assertRaisesRegex(ValueError, "overlap"):
            omp_copy.copy_once(self.source, self.root)


if __name__ == "__main__":
    unittest.main()
