"""The host-file contract through a real framed Unix socket, plus wire-protocol limits."""

import base64
import errno
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

import file_broker
from file_broker import (MAX_CHUNK, MAX_FRAME, FileBrokerServer, RemoteHostFiles, encode_frame,
                         errno_name, errno_value, read_frame)
from host_files import HostFiles
from test_host_files import HostContract, Policy


def _private_directory(test):
    directory = tempfile.TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    os.chmod(directory.name, 0o700)
    return directory.name


@unittest.skipUnless(os.name == "posix", "The broker uses Unix sockets")
class BrokerHostFilesTests(HostContract, unittest.TestCase):
    """Every host-folder guarantee holds unchanged for the VM's RemoteHostFiles."""

    def make_host(self, policy):
        local = HostFiles(policy)
        server = FileBrokerServer(local, os.path.join(_private_directory(self), "broker.sock"))
        self.addCleanup(server.close)
        remote = RemoteHostFiles.connect(server.path)
        self.addCleanup(remote.close_all)
        return remote, local

    def test_large_transfers_are_split_into_bounded_chunks(self):
        file = self.allowed / "large"
        data = os.urandom(3 * MAX_CHUNK + 123)
        handle = self.fs.create(str(file), 0o600)
        self.assertEqual(self.fs.write(handle, data, 0), len(data))
        self.assertEqual(self.fs.read(handle, len(data) + 10, 0), data)
        self.assertEqual(self.fs.read(handle, 10, len(data) - 5), data[-5:])
        self.fs.close(handle)
        self.assertEqual(file.read_bytes(), data)

    def test_directory_listing_is_paged_through_a_connection_cursor(self):
        names = sorted(f"entry-{index:03}" for index in range(7))
        for name in names:
            (self.allowed / name).write_bytes(b"")
        with patch.object(file_broker, "PAGE_NAMES", 2):
            self.assertEqual(self.fs.readdir(str(self.allowed)), names)

    def test_concurrent_requests_complete(self):
        file = self.allowed / "shared"
        file.write_bytes(b"shared-data")
        handle = self.fs.open(str(file))
        results, failures = [], []

        def reading():
            try:
                results.append(self.fs.read(handle, 64, 0))
            except BaseException as error:
                failures.append(error)

        threads = [threading.Thread(target=reading) for _ in range(150)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.fs.close(handle)
        self.assertEqual(failures, [])
        self.assertEqual(results, [b"shared-data"] * 150)


class RawClient:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(path)
        self.next_id = 1

    def send(self, op, **args):
        self.sock.sendall(encode_frame({"id": self.next_id, "op": op, "args": args}))
        self.next_id += 1

    def call(self, op, **args):
        self.send(op, **args)
        return read_frame(self.sock)

    def closed_by_peer(self):
        try:
            return self.sock.recv(1) == b""
        except ConnectionResetError:
            return True

    def close(self):
        self.sock.close()


class CountingScandir:
    """Count actual entries consumed without materializing the directory."""

    def __init__(self, iterator, counts):
        self.iterator = iterator
        self.counts = counts

    def __iter__(self):
        return self

    def __next__(self):
        entry = next(self.iterator)
        self.counts.append(entry.name)
        return entry

    def close(self):
        self.iterator.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@unittest.skipUnless(os.name == "posix", "The broker uses Unix sockets")
class BrokerProtocolTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(os.path.realpath(temp.name))
        self.allowed = self.root / "allowed"
        self.allowed.mkdir()
        self.file = self.allowed / "data"
        self.file.write_bytes(b"data")
        self.policy = Policy([{"path": str(self.allowed), "write": True}])
        self.local = HostFiles(self.policy)
        self.addCleanup(self.local.close_all)
        self.server = FileBrokerServer(self.local, os.path.join(_private_directory(self), "b.sock"))
        self.addCleanup(self.server.close)
        self.raw = self.client()

    def client(self):
        client = RawClient(self.server.path)
        self.addCleanup(client.close)
        return client

    def assertFailure(self, response, name):
        self.assertEqual((response["ok"], response["errno"]), (False, name))

    def wait_server(self, predicate):
        with self.server._condition:
            self.assertTrue(self.server._condition.wait_for(predicate, timeout=5))

    def close_server_promptly(self):
        failures = []

        def closing():
            try:
                self.server.close()
            except BaseException as failure:
                failures.append(failure)

        thread = threading.Thread(target=closing, daemon=True)
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive(), "server shutdown hung")
        self.assertEqual(failures, [])

    def open_arguments(self, **overrides):
        return {"path": str(self.file), "read": True, "write": False,
                "append": False, "truncate": False, **overrides}

    def drain_directory(self, client, page, path=None):
        names = list(page["names"])
        while page["cursor"] is not None:
            response = client.call("readdir", path=str(path or self.allowed),
                                   cursor=page["cursor"])
            self.assertTrue(response["ok"], response)
            page = response["result"]
            names.extend(page["names"])
        return names

    def test_unknown_and_refused_operations_are_rejected(self):
        self.assertFailure(self.raw.call("exec", path=str(self.file)), "ENOSYS")
        for op in ("symlink", "link", "mknod", "chown"):
            with self.subTest(op=op):
                self.assertFailure(self.raw.call(op, path=str(self.file)), "EPERM")
        response = self.raw.call("getattr", path=str(self.file))
        self.assertTrue(response["ok"])
        self.assertEqual(response["id"], 6)

    def test_arguments_are_strict_and_never_native_bitmasks(self):
        opened = self.raw.call("open", path=str(self.file), read=True, write=True,
                               append=False, truncate=False)
        handle = opened["result"]["handle"]
        for op, args in (
            ("open", {"path": str(self.file), "flags": 2}),
            ("open", {"path": str(self.file), "read": 1, "write": False,
                      "append": False, "truncate": False}),
            ("getattr", {"path": str(self.file), "follow": True}),
            ("read", {"handle": handle, "offset": 0, "size": MAX_CHUNK + 1}),
            ("read", {"handle": handle, "offset": -1, "size": 1}),
            ("write", {"handle": handle, "offset": 0,
                       "data": base64.b64encode(b"x" * (MAX_CHUNK + 1)).decode()}),
            ("write", {"handle": handle, "offset": 0, "data": "not base64!"}),
            ("truncate", {"length": 0, "path": str(self.file), "handle": handle}),
            ("chmod", {"path": str(self.file), "mode": 0o10000}),
            ("utimens", {"path": str(self.file), "times": [1, float("inf")]}),
        ):
            with self.subTest(op=op, args=args):
                if op == "utimens":
                    # JSON cannot carry infinity; the encoder refuses it before sending.
                    with self.assertRaises(ValueError):
                        encode_frame({"id": 1, "op": op, "args": args})
                    continue
                self.assertFailure(self.raw.call(op, **args), "EINVAL")
        self.assertFailure(self.raw.call("read", handle="unknown", offset=0, size=1), "EBADF")
        response = self.raw.call("getattr", path=str(self.file))
        self.assertEqual(set(response["result"]) - {"atime", "mtime", "ctime", "ino"},
                         {"kind", "mode", "nlink", "size", "owned"})
        self.assertEqual(response["result"]["kind"], "file")
        self.assertEqual(self.file.read_bytes(), b"data")

    def test_maximum_frame_is_accepted_and_larger_frame_closes_connection(self):
        envelope = {"id": 1, "op": "getattr", "args": {"path": ""}}
        padding = MAX_FRAME - len(encode_frame(envelope)) + 4
        envelope["args"]["path"] = "/" + "a" * (padding - 1)
        frame = encode_frame(envelope)
        self.assertEqual(len(frame) - 4, MAX_FRAME)
        self.raw.sock.sendall(frame)
        self.assertFailure(read_frame(self.raw.sock), "EINVAL")
        self.raw.sock.sendall(struct.pack(">I", MAX_FRAME + 1) + b"{")
        self.assertTrue(self.raw.closed_by_peer())
        with self.assertRaises(file_broker.ProtocolError):
            encode_frame({"data": "x" * MAX_FRAME})

    def test_malformed_frames_close_the_connection(self):
        for payload in (struct.pack(">I", 0),
                        struct.pack(">I", 5) + b"[1,2]",
                        struct.pack(">I", 3) + b"{x}",
                        encode_frame({"id": 1, "op": "getattr"}),
                        encode_frame({"id": True, "op": "getattr", "args": {}})):
            with self.subTest(payload=payload):
                client = self.client()
                client.sock.sendall(payload)
                self.assertTrue(client.closed_by_peer())

    def test_request_ids_must_increase(self):
        self.raw.next_id = 5
        self.assertTrue(self.raw.call("getattr", path=str(self.file))["ok"])
        self.raw.next_id = 5
        self.raw.send("getattr", path=str(self.file))
        self.assertTrue(self.raw.closed_by_peer())

    def test_handles_and_cursors_are_connection_bound(self):
        for index in range(3):
            (self.allowed / f"extra-{index}").write_bytes(b"")
        with patch.object(file_broker, "PAGE_NAMES", 1):
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.assertEqual(len(page["names"]), 1)
            other = self.client()
            self.assertFailure(other.call("readdir", path=str(self.allowed),
                                          cursor=page["cursor"]), "EBADF")
            handle = self.raw.call("open", path=str(self.file), read=True, write=False,
                                   append=False, truncate=False)["result"]["handle"]
            self.assertFailure(other.call("read", handle=handle, offset=0, size=4), "EBADF")
            self.assertFailure(other.call("close", handle=handle), "EBADF")
            following = self.raw.call("readdir", path=str(self.allowed), cursor=page["cursor"])
            self.assertTrue(following["ok"])
            self.assertEqual(len(following["result"]["names"]), 1)
        response = self.raw.call("read", handle=handle, offset=0, size=4)
        self.assertEqual(base64.b64decode(response["result"]["data"]), b"data")

    def test_readdir_continuation_rechecks_authority(self):
        for index in range(3):
            (self.allowed / f"extra-{index}").write_bytes(b"")
        with patch.object(file_broker, "PAGE_NAMES", 1):
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.policy.data["folders"] = []
            self.assertFailure(self.raw.call("readdir", path=str(self.allowed),
                                             cursor=page["cursor"]), "EACCES")
            self.policy.data["folders"] = [{"path": str(self.allowed), "write": True}]
            self.assertFailure(self.raw.call("readdir", path=str(self.allowed),
                                             cursor=page["cursor"]), "EBADF")


    def test_readdir_revoked_parent_cannot_disclose_siblings_of_remaining_grant(self):
        keep = self.allowed / "keep"
        keep.mkdir()
        for index in range(6):
            (self.allowed / f"secret-{index}").write_bytes(b"")
        with patch.object(file_broker, "PAGE_NAMES", 1):
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.assertIsNotNone(page["cursor"])
            self.policy.data["folders"] = [{"path": str(keep), "write": False}]
            self.assertFailure(self.raw.call("readdir", path=str(self.allowed),
                                             cursor=page["cursor"]), "EACCES")
            fresh = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.assertEqual(self.drain_directory(self.raw, fresh), ["keep"])
            self.assertEqual(self.server._cursor_count, 0)

    def test_directory_paging_bounds_enumeration_and_retains_only_cursor(self):
        for index in range(50):
            (self.allowed / f"entry-{index}").write_bytes(b"")
        consumed = []
        scandir = os.scandir
        with patch.object(file_broker, "PAGE_NAMES", 2), \
                patch.object(self.local, "readdir", side_effect=AssertionError("eager listing")), \
                patch("host_files.os.scandir",
                      side_effect=lambda fd: CountingScandir(scandir(fd), consumed)):
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.assertLessEqual(len(consumed), 2)
            self.assertIsNotNone(page["cursor"])
            with self.server._condition:
                entries = [entry for connection in self.server._connections
                           for entry in connection._cursors.values()]
                self.assertEqual(len(entries), 1)
                self.assertEqual(len(entries[0]), 2)
                self.assertEqual(entries[0][0], str(self.allowed))
                self.assertTrue(callable(entries[0][1].page))
                cursor = entries[0][1]
                self.assertIsInstance(cursor._iterator, CountingScandir)
                self.assertTrue(cursor._pending is None or isinstance(cursor._pending, str))
            before = len(consumed)
            following = self.raw.call("readdir", path=str(self.allowed),
                                      cursor=page["cursor"])["result"]
            self.assertLessEqual(len(consumed) - before, 2)
            names = page["names"] + self.drain_directory(self.raw, following)
            self.assertEqual(len(names), 51)
            self.assertEqual(len(set(names)), 51)
            self.assertEqual(self.server._cursor_count, 0)

    def test_directory_pages_bound_encoded_bytes_and_accept_empty_nonterminal_pages(self):
        self.file.unlink()
        names = [f"\u00e9-{index}" for index in range(5)]
        for name in names:
            (self.allowed / name).write_bytes(b"")
        with patch.object(file_broker, "PAGE_BYTES", 24):
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            result = []
            while True:
                encoded = json.dumps(page["names"], ensure_ascii=True, separators=(",", ":"))
                self.assertLessEqual(len(encoded) - 2, 24)
                result.extend(page["names"])
                if page["cursor"] is None:
                    break
                page = self.raw.call("readdir", path=str(self.allowed),
                                     cursor=page["cursor"])["result"]
            self.assertEqual(sorted(result), sorted(names))
        self.policy.private_paths = tuple(str(self.allowed / name) for name in names)
        with patch.object(file_broker, "PAGE_NAMES", 1):
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.assertEqual(page["names"], [])
            self.assertIsNotNone(page["cursor"])
            self.assertEqual(self.drain_directory(self.raw, page), [])
            remote = RemoteHostFiles.connect(self.server.path)
            self.addCleanup(remote.close_all)
            self.assertEqual(remote.readdir(str(self.allowed)), [])

    def test_cursor_limits_reserve_before_opening_or_enumeration(self):
        (self.allowed / "extra").write_bytes(b"")
        other = self.client()
        with patch.object(file_broker, "PAGE_NAMES", 1), \
                patch.object(file_broker, "MAX_CURSORS", 1), \
                patch.object(file_broker, "MAX_GLOBAL_CURSORS", 2), \
                patch.object(self.local, "open_directory",
                             wraps=self.local.open_directory) as opening:
            first = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.assertFailure(self.raw.call("readdir", path=str(self.allowed)), "EMFILE")
            second = other.call("readdir", path=str(self.allowed))["result"]
            third = self.client()
            self.assertFailure(third.call("readdir", path=str(self.allowed)), "EMFILE")
            self.assertEqual(opening.call_count, 2)
            self.assertEqual(self.server._cursor_count, 2)
            self.drain_directory(self.raw, first)
            self.assertTrue(third.call("readdir", path=str(self.allowed))["ok"])
            self.drain_directory(other, second)
        self.server.close()
        self.assertEqual(self.server._cursor_count, 0)

    def test_pending_directory_open_holds_global_cursor_reservation(self):
        entered, release = threading.Event(), threading.Event()
        original = self.local.open_directory

        def opening(path):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test did not release directory open")
            return original(path)

        self.addCleanup(release.set)
        with patch.object(file_broker, "MAX_GLOBAL_CURSORS", 1), \
                patch.object(self.local, "open_directory", side_effect=opening) as opening_mock:
            self.raw.send("readdir", path=str(self.allowed))
            try:
                self.assertTrue(entered.wait(5))
                self.assertFailure(self.client().call("readdir", path=str(self.allowed)), "EMFILE")
                self.assertEqual(opening_mock.call_count, 1)
                self.assertEqual(self.server._cursor_count, 1)
            finally:
                release.set()
            self.assertTrue(read_frame(self.raw.sock)["ok"])
        self.assertEqual(self.server._cursor_count, 0)

    def test_cursor_errors_and_disconnect_close_directory_resources(self):
        (self.allowed / "extra").write_bytes(b"")
        cursors = []
        original = self.local.open_directory

        class TrackedCursor:
            def __init__(self, inner):
                self.inner, self.closes = inner, 0

            def page(self, *args):
                return self.inner.page(*args)

            def close(self):
                self.closes += 1
                self.inner.close()

        def opening(path):
            cursor = TrackedCursor(original(path))
            cursors.append(cursor)
            return cursor

        with patch.object(file_broker, "PAGE_NAMES", 1), \
                patch.object(self.local, "open_directory", side_effect=opening):
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.assertFailure(self.raw.call("readdir", path=str(self.root),
                                             cursor=page["cursor"]), "EBADF")
            self.assertEqual(cursors[0].closes, 1)
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.policy.private_paths = (str(self.file),)
            self.assertFailure(self.raw.call("readdir", path=str(self.allowed),
                                             cursor=page["cursor"]), "EACCES")
            self.assertEqual(cursors[1].closes, 1)
            self.policy.private_paths = ()
            page = self.raw.call("readdir", path=str(self.allowed))["result"]
            self.drain_directory(self.raw, page)
            self.assertEqual(cursors[2].closes, 1)
            self.raw.call("readdir", path=str(self.allowed))
            self.raw.close()
            self.server.close()
            self.assertEqual([cursor.closes for cursor in cursors], [1, 1, 1, 1])
            self.assertEqual(self.server._cursor_count, 0)

    def test_pending_opens_reserve_per_connection_handle_and_cursor_capacity(self):
        other = self.client()
        for operation, limit, count_name in (
                ("open", "MAX_HANDLES", "_handle_count"),
                ("readdir", "MAX_CURSORS", "_cursor_count")):
            with self.subTest(operation=operation):
                entered, release = threading.Event(), threading.Event()
                method = "open" if operation == "open" else "open_directory"
                original = getattr(self.local, method)
                calls = 0
                calls_lock = threading.Lock()

                def opening(*args, **kwargs):
                    nonlocal calls
                    with calls_lock:
                        calls += 1
                        first = calls == 1
                    if first:
                        entered.set()
                        if not release.wait(5):
                            raise RuntimeError("test did not release open")
                    return original(*args, **kwargs)

                arguments = self.open_arguments() if operation == "open" else {
                    "path": str(self.allowed)}
                with patch.object(file_broker, limit, 1), \
                        patch.object(self.local, method, side_effect=opening):
                    self.raw.send(operation, **arguments)
                    try:
                        self.assertTrue(entered.wait(5))
                        self.assertFailure(self.raw.call(operation, **arguments), "EMFILE")
                        other_result = other.call(operation, **arguments)
                        self.assertTrue(other_result["ok"], other_result)
                        self.assertEqual(calls, 2)
                    finally:
                        release.set()
                    first_result = read_frame(self.raw.sock)
                    self.assertTrue(first_result["ok"], first_result)
                if operation == "open":
                    self.assertTrue(self.raw.call(
                        "close", handle=first_result["result"]["handle"])["ok"])
                    self.assertTrue(other.call(
                        "close", handle=other_result["result"]["handle"])["ok"])
                self.assertEqual(getattr(self.server, count_name), 0)


    def test_disconnect_closes_every_connection_handle(self):
        for _ in range(3):
            response = self.raw.call("open", path=str(self.file), read=True, write=False,
                                     append=False, truncate=False)
            self.assertTrue(response["ok"])
        self.assertEqual(len(self.local._handles), 3)
        self.raw.close()
        self.server.close()
        self.assertEqual(self.local._handles, {})

    def test_handle_limit_per_connection(self):
        with patch.object(file_broker, "MAX_HANDLES", 2):
            arguments = {"path": str(self.file), "read": True, "write": False,
                         "append": False, "truncate": False}
            first = self.raw.call("open", **arguments)["result"]["handle"]
            self.raw.call("open", **arguments)
            self.assertFailure(self.raw.call("open", **arguments), "EMFILE")
            self.assertFailure(self.raw.call("create", path=str(self.allowed / "new"), mode=0o600,
                                             read=True, write=True, exclusive=True), "EMFILE")
            self.assertTrue(self.raw.call("close", handle=first)["ok"])
            self.assertTrue(self.raw.call("open", **arguments)["ok"])
        self.assertEqual(len(self.local._handles), 2)

    def test_global_handle_limit_reserves_pending_open_before_create_or_truncate(self):
        entered, release = threading.Event(), threading.Event()
        original = self.local.open

        def opening(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test did not release open")
            return original(*args, **kwargs)

        self.addCleanup(release.set)
        other = self.client()
        with patch.object(file_broker, "MAX_GLOBAL_HANDLES", 1), \
                patch.object(self.local, "open", side_effect=opening) as opening_mock:
            self.raw.send("open", **self.open_arguments())
            try:
                self.assertTrue(entered.wait(5))
                self.assertFailure(other.call("open", **self.open_arguments(
                    write=True, truncate=True)), "EMFILE")
                self.assertFailure(other.call("create", path=str(self.allowed / "new"),
                                               mode=0o600, read=True, write=True,
                                               exclusive=True), "EMFILE")
                self.assertEqual(opening_mock.call_count, 1)
                self.assertEqual(self.file.read_bytes(), b"data")
                self.assertFalse((self.allowed / "new").exists())
            finally:
                release.set()
            handle = read_frame(self.raw.sock)["result"]["handle"]
            self.assertEqual(self.server._handle_count, 1)
            self.assertTrue(self.raw.call("close", handle=handle)["ok"])
            handle = other.call("open", **self.open_arguments())["result"]["handle"]
            self.assertTrue(other.call("close", handle=handle)["ok"])
        self.assertEqual(self.server._handle_count, 0)

    def test_failed_opens_release_handle_and_cursor_reservations(self):
        with patch.object(file_broker, "MAX_GLOBAL_HANDLES", 1), \
                patch.object(file_broker, "MAX_GLOBAL_CURSORS", 1):
            missing = str(self.allowed / "missing")
            self.assertFailure(self.raw.call("open", **self.open_arguments(path=missing)), "ENOENT")
            self.assertFailure(self.raw.call("readdir", path=missing), "ENOENT")
            self.assertEqual(self.server._handle_count, 0)
            self.assertEqual(self.server._cursor_count, 0)
            self.assertTrue(self.raw.call("open", **self.open_arguments())["ok"])
            self.assertTrue(self.raw.call("readdir", path=str(self.allowed))["ok"])

    def test_global_workers_bound_requests_across_connections(self):
        entered = [threading.Event(), threading.Event()]
        waiting, release = threading.Event(), threading.Event()
        original = self.local.getattr
        count = 0
        count_lock = threading.Lock()

        def blocking(path):
            nonlocal count
            with count_lock:
                index = count
                count += 1
            if index < 2:
                entered[index].set()
                if not release.wait(5):
                    raise RuntimeError("test did not release request")
            return original(path)

        self.addCleanup(release.set)
        second, third = self.client(), self.client()
        reserve = self.server._reserve_request

        def admission(connection):
            with self.server._condition:
                if self.server._requests == 2:
                    waiting.set()
            return reserve(connection)

        with patch.object(file_broker, "MAX_GLOBAL_WORKERS", 2), \
                patch.object(self.local, "getattr", side_effect=blocking), \
                patch.object(self.server, "_reserve_request", side_effect=admission), \
                patch.object(self.server._pool, "submit", wraps=self.server._pool.submit) as submit:
            self.raw.send("getattr", path=str(self.file))
            second.send("getattr", path=str(self.file))
            try:
                self.assertTrue(all(event.wait(5) for event in entered))
                third.send("getattr", path=str(self.file))
                self.assertTrue(waiting.wait(5))
                self.assertEqual(self.server._requests, 2)
                self.assertEqual(submit.call_count, 2)
                self.assertEqual(len(self.server._pool._threads), 2)
                self.assertEqual(count, 2)
            finally:
                release.set()
            for client in (self.raw, second, third):
                self.assertTrue(read_frame(client.sock)["ok"])
        self.wait_server(lambda: self.server._requests == 0)

    def test_per_connection_workers_do_not_consume_other_connections_capacity(self):
        entered, release, waiting = threading.Event(), threading.Event(), threading.Event()
        original = self.local.getattr

        def blocking(path):
            if path == str(self.allowed):
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("test did not release request")
            return original(path)

        reserve = self.server._reserve_request

        def admission(connection):
            if connection._requests == 1:
                waiting.set()
            return reserve(connection)

        self.addCleanup(release.set)
        with patch.object(file_broker, "MAX_CONCURRENCY", 1), \
                patch.object(file_broker, "MAX_GLOBAL_WORKERS", 2), \
                patch.object(self.local, "getattr", side_effect=blocking), \
                patch.object(self.server, "_reserve_request", side_effect=admission):
            self.raw.send("getattr", path=str(self.allowed))
            try:
                self.assertTrue(entered.wait(5))
                self.raw.send("getattr", path=str(self.file))
                self.assertTrue(waiting.wait(5))
                self.assertTrue(self.client().call("getattr", path=str(self.file))["ok"])
                with self.server._condition:
                    self.assertTrue(all(connection._requests <= 1
                                        for connection in self.server._connections))
            finally:
                release.set()
            self.assertTrue(read_frame(self.raw.sock)["ok"])
            self.assertTrue(read_frame(self.raw.sock)["ok"])

    def test_idle_and_incomplete_connections_are_capped_and_admission_recovers(self):
        self.assertTrue(self.raw.call("getattr", path=str(self.file))["ok"])
        with patch.object(file_broker, "MAX_CONNECTIONS", 2):
            incomplete = self.client()
            incomplete.sock.sendall(struct.pack(">I", 100) + b"{")
            rejected = self.client()
            self.assertTrue(rejected.closed_by_peer())
            self.assertEqual(len(self.server._connections), 2)
            self.assertTrue(self.raw.call("getattr", path=str(self.file))["ok"])
            incomplete.close()
            self.wait_server(lambda: len(self.server._connections) == 1)
            replacement = self.client()
            self.assertTrue(replacement.call("getattr", path=str(self.file))["ok"])
            self.server.close()
            self.assertTrue(self.raw.closed_by_peer())
            self.assertTrue(replacement.closed_by_peer())

    def test_connection_thread_start_failure_releases_socket_and_admission(self):
        self.assertTrue(self.raw.call("getattr", path=str(self.file))["ok"])
        with patch.object(file_broker, "MAX_CONNECTIONS", 2):
            with patch.object(file_broker._Connection, "start",
                              side_effect=RuntimeError("injected start failure")):
                failed = self.client()
                self.assertTrue(failed.closed_by_peer())
            self.assertEqual(len(self.server._connections), 1)
            replacement = self.client()
            self.assertTrue(replacement.call("getattr", path=str(self.file))["ok"])
        self.close_server_promptly()
        self.assertFalse(self.server._thread.is_alive())

    def test_worker_submit_failure_releases_reservations_and_listener_recovers(self):
        with patch.object(self.server._pool, "submit",
                          side_effect=RuntimeError("injected submit failure")):
            self.raw.send("open", **self.open_arguments())
            self.assertTrue(self.raw.closed_by_peer())
        self.wait_server(lambda: not self.server._connections)
        self.assertEqual(self.server._requests, 0)
        self.assertEqual(self.server._handle_count, 0)
        self.assertEqual(self.local._handles, {})
        replacement = self.client()
        self.assertTrue(replacement.call("getattr", path=str(self.file))["ok"])
        self.close_server_promptly()
        self.assertTrue(all(not thread.is_alive() for thread in self.server._pool._threads))

    def test_worker_thread_start_failure_never_enqueues_side_effects(self):
        start = threading.Thread.start

        def starting(thread):
            if thread.name == "file-broker-request":
                raise RuntimeError("injected worker start failure")
            return start(thread)

        with patch.object(threading.Thread, "start", starting):
            self.raw.send("create", path=str(self.allowed / "not-created"), mode=0o600,
                          read=True, write=True, exclusive=True)
            self.assertTrue(self.raw.closed_by_peer())
        self.wait_server(lambda: not self.server._connections)
        self.assertEqual(self.server._requests, 0)
        self.assertEqual(list(self.server._pool._queue), [])
        self.assertEqual(self.server._pool._threads, [])
        self.assertFalse((self.allowed / "not-created").exists())
        self.assertTrue(self.client().call("getattr", path=str(self.file))["ok"])
        self.assertFalse((self.allowed / "not-created").exists())
        self.close_server_promptly()

    def test_shutdown_closes_inflight_pending_and_incomplete_peers_before_waiting(self):
        entered, waiting, release = threading.Event(), threading.Event(), threading.Event()
        original = self.local.getattr

        def blocking(path):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test did not release request")
            return original(path)

        reserve = self.server._reserve_request

        def admission(connection):
            if self.server._requests:
                waiting.set()
            return reserve(connection)

        self.addCleanup(release.set)
        pending, incomplete = self.client(), self.client()
        incomplete.sock.sendall(b"\x00")
        closing = threading.Thread(target=self.server.close, daemon=True)
        with patch.object(file_broker, "MAX_GLOBAL_WORKERS", 1), \
                patch.object(self.local, "getattr", side_effect=blocking), \
                patch.object(self.server, "_reserve_request", side_effect=admission):
            self.raw.send("getattr", path=str(self.file))
            try:
                self.assertTrue(entered.wait(5))
                pending.send("getattr", path=str(self.file))
                self.assertTrue(waiting.wait(5))
                closing.start()
                for client in (self.raw, pending, incomplete):
                    self.assertTrue(client.closed_by_peer())
                self.assertTrue(closing.is_alive())
            finally:
                release.set()
                if closing.ident is not None:
                    closing.join(5)
            self.assertFalse(closing.is_alive())
        self.assertEqual(self.server._requests, 0)
        self.assertEqual(self.server._connections, set())
        self.assertTrue(all(not thread.is_alive() for thread in self.server._pool._threads))

    def test_revocation_fails_open_handle_io_without_restart(self):
        remote = RemoteHostFiles.connect(self.server.path)
        self.addCleanup(remote.close_all)
        handle = remote.open(str(self.file), read=True, write=True)
        self.policy.data["folders"] = []
        with self.assertRaises(OSError) as failure:
            remote.write(handle, b"X", 0)
        self.assertEqual(failure.exception.errno, errno.EACCES)
        self.policy.data["folders"] = [{"path": str(self.allowed), "write": True}]
        self.assertEqual(remote.write(handle, b"D", 0), 1)
        remote.close(handle)
        self.assertEqual(self.file.read_bytes(), b"Data")

    def test_transport_failure_is_io_error_without_fallback(self):
        remote = RemoteHostFiles.connect(self.server.path)
        handle = remote.open(str(self.file))
        self.server.close()
        for callback, args in ((remote.read, (handle, 4, 0)),
                               (remote.getattr, (str(self.file),)),
                               (remote.open, (str(self.file),))):
            with self.subTest(operation=callback.__name__):
                with self.assertRaises(OSError) as failure:
                    callback(*args)
                self.assertEqual(failure.exception.errno, errno.EIO)
        self.assertEqual(self.local._handles, {})
        remote.close_all()

    def test_errno_names_translate_on_the_receiving_side(self):
        self.assertEqual(errno_value("EACCES"), errno.EACCES)
        self.assertEqual(errno_value("ENOTSUP"), errno.ENOTSUP)
        for name in ("errorcode", "ENOPE", "", "EIO"):
            self.assertEqual(errno_value(name), errno.EIO)
        self.assertEqual(errno_name(errno.EXDEV), "EXDEV")
        self.assertEqual(errno_name(987654), "EIO")

    def test_server_requires_private_socket_directory(self):
        shared = tempfile.TemporaryDirectory()
        self.addCleanup(shared.cleanup)
        os.chmod(shared.name, 0o755)
        with self.assertRaises(OSError) as failure:
            FileBrokerServer(self.local, os.path.join(shared.name, "b.sock"))
        self.assertEqual(failure.exception.errno, errno.EACCES)
        with self.assertRaises(ValueError):
            FileBrokerServer(self.local, "relative.sock")
        occupied = os.path.join(_private_directory(self), "file")
        Path(occupied).write_bytes(b"")
        with self.assertRaises(OSError) as failure:
            FileBrokerServer(self.local, occupied)
        self.assertEqual(failure.exception.errno, errno.EEXIST)


if __name__ == "__main__":
    unittest.main()
