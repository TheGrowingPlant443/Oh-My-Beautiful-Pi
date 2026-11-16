"""Framed host-file broker: the Mac host serves HostFiles to its Linux VM.

The host runs FileBrokerServer on a private Unix socket; host-initiated SSH
forwards that socket into the VM, where RemoteHostFiles implements the
HostFiles interface for AccessFS's `/host` view. There is no TCP listener and
no fallback: a failed transport makes every later guest operation fail with
EIO, and disconnecting closes every handle and directory cursor it opened.

Wire format: a 4-byte big-endian payload length, then a UTF-8 JSON object of
at most 1 MiB. Requests are {"id", "op", "args"} with strictly increasing ids
per connection. Responses are {"id", "ok": true, "result"} or
{"id", "ok": false, "errno": "<symbolic name>"}; numeric errno values, open
flags and other host-native bitmasks never cross the wire. File data is
base64 with at most 64 KiB decoded per request. Every operation re-checks the
host policy through HostFiles, including IO on already-open handles.
Directory pages enumerate incrementally and reauthorize through HostFiles'
cursor API. Admission includes pending opens and pages: each server permits
16 connections, 64 outstanding requests, 4096 handles and 64 directory cursors.
Requests wait for bounded shared worker capacity; excess connections and failed
worker submissions are disconnected. No complete listing is retained by the host.
"""

import base64
import binascii
import errno
import json
import math
import os
import secrets
import select
import socket
import stat
import struct
import sys
import threading
from collections import deque


MAX_FRAME = 1 << 20
MAX_CHUNK = 64 << 10
MAX_HANDLES = 4096
MAX_CONCURRENCY = 64
MAX_CURSORS = 64
MAX_CONNECTIONS = 16
MAX_GLOBAL_WORKERS = 64
MAX_GLOBAL_HANDLES = 4096
MAX_GLOBAL_CURSORS = 64
MAX_PATH = 4096
PAGE_BYTES = 512 << 10
PAGE_NAMES = 4096
NOBODY = 65534
_ENCODED_CHUNK = 4 * ((MAX_CHUNK + 2) // 3)
_HEADER = struct.Struct(">I")
_ERRNO_NAMES = frozenset(name for name in dir(errno)
                         if name.startswith("E") and isinstance(getattr(errno, name), int))
_KINDS = {"file": stat.S_IFREG, "directory": stat.S_IFDIR}
# Requests the host never performs on behalf of the VM.
_REFUSED = frozenset({"symlink", "link", "mknod", "chown"})


class ProtocolError(Exception):
    """Malformed framing or envelope; the connection cannot continue."""


def _failure(code):
    return OSError(code, os.strerror(code))


def errno_name(code):
    return errno.errorcode.get(code, "EIO")


def errno_value(name):
    return getattr(errno, name) if name in _ERRNO_NAMES else errno.EIO


def _reject_constant(value):
    raise ValueError(f"Invalid JSON constant {value}")


def encode_frame(message):
    payload = json.dumps(message, ensure_ascii=True, separators=(",", ":"),
                         allow_nan=False).encode("ascii")
    if len(payload) > MAX_FRAME:
        raise ProtocolError("Frame exceeds 1 MiB")
    return _HEADER.pack(len(payload)) + payload


def _read_exact(sock, size):
    buffer = bytearray(size)
    view = memoryview(buffer)
    received = 0
    while received < size:
        count = sock.recv_into(view[received:])
        if count == 0:
            if received == 0:
                return None
            raise ProtocolError("Connection closed inside a frame")
        received += count
    return bytes(buffer)


def read_frame(sock):
    """The next decoded message, or None on a clean end of stream."""
    header = _read_exact(sock, _HEADER.size)
    if header is None:
        return None
    (length,) = _HEADER.unpack(header)
    if not 0 < length <= MAX_FRAME:
        raise ProtocolError("Invalid frame length")
    payload = _read_exact(sock, length)
    if payload is None:
        raise ProtocolError("Connection closed inside a frame")
    try:
        message = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as failure:
        raise ProtocolError("Invalid frame payload") from failure
    if not isinstance(message, dict):
        raise ProtocolError("Frame is not an object")
    return message


def _integer(value, minimum=0, maximum=None):
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError("Invalid integer")
    return value


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("Invalid number")
    return value


def _boolean(value):
    if type(value) is not bool:
        raise ValueError("Invalid boolean")
    return value


def _string(value, limit=MAX_PATH):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("Invalid string")
    return value


def _fields(args, required, optional=()):
    keys = set(args)
    if not set(required) <= keys or keys - set(required) - set(optional):
        raise ValueError("Invalid operation arguments")


def encode_attributes(attrs):
    mode = attrs["st_mode"]
    kind = "directory" if stat.S_ISDIR(mode) else "file" if stat.S_ISREG(mode) else None
    if kind is None:
        raise _failure(errno.EACCES)
    wire = {"kind": kind, "mode": stat.S_IMODE(mode), "nlink": attrs["st_nlink"],
            "size": attrs["st_size"], "owned": attrs.get("st_uid") == os.getuid()}
    for key in ("atime", "mtime", "ctime"):
        if "st_" + key in attrs:
            wire[key] = float(attrs["st_" + key])
    if "st_ino" in attrs:
        wire["ino"] = attrs["st_ino"]
    return wire


def decode_attributes(wire):
    if not isinstance(wire, dict) or wire.get("kind") not in _KINDS:
        raise ValueError("Invalid attributes")
    _fields(wire, ("kind", "mode", "nlink", "size", "owned"), ("atime", "mtime", "ctime", "ino"))
    owned = _boolean(wire["owned"])
    attrs = {"st_mode": _KINDS[wire["kind"]] | _integer(wire["mode"], maximum=0o7777),
             "st_nlink": _integer(wire["nlink"]), "st_size": _integer(wire["size"]),
             "st_uid": os.getuid() if owned else NOBODY,
             "st_gid": os.getgid() if owned else NOBODY}
    for key in ("atime", "mtime", "ctime"):
        if key in wire:
            attrs["st_" + key] = float(_number(wire[key]))
    if "ino" in wire:
        attrs["st_ino"] = _integer(wire["ino"])
    return attrs


_STATFS_NUMBERS = ("f_bsize", "f_frsize", "f_blocks", "f_bfree", "f_bavail",
                   "f_files", "f_ffree", "f_favail", "f_namemax")


def encode_statfs(values):
    wire = {key: values[key] for key in _STATFS_NUMBERS if key in values}
    if "f_flag" in values:
        wire["flags"] = {"readonly": bool(values["f_flag"] & os.ST_RDONLY),
                         "nosuid": bool(values["f_flag"] & os.ST_NOSUID)}
    return wire


def decode_statfs(wire):
    if not isinstance(wire, dict):
        raise ValueError("Invalid filesystem status")
    _fields(wire, (), (*_STATFS_NUMBERS, "flags"))
    values = {key: _integer(wire[key]) for key in _STATFS_NUMBERS if key in wire}
    if "flags" in wire:
        flags = wire["flags"]
        if not isinstance(flags, dict):
            raise ValueError("Invalid filesystem flags")
        _fields(flags, ("readonly", "nosuid"))
        values["f_flag"] = ((os.ST_RDONLY if _boolean(flags["readonly"]) else 0)
                            | (os.ST_NOSUID if _boolean(flags["nosuid"]) else 0))
    return values


def _socket_limit():
    return 104 if sys.platform == "darwin" else 108


class _RequestPool:
    """Shared bounded workers; start failure cannot leave an enqueued request.

    ThreadPoolExecutor enqueues before starting a worker, so a failed submit
    can still run later. Here admission and successful startup precede enqueue.
    The server reserves every outstanding request before calling submit.
    """

    def __init__(self):
        self._condition = threading.Condition()
        self._threads = []
        self._queue = deque()
        self._busy = 0
        self._closed = False

    def submit(self, callback, *args):
        with self._condition:
            if self._closed or len(self._queue) >= MAX_GLOBAL_WORKERS:
                raise RuntimeError("Request pool unavailable")
            if (self._busy + len(self._queue) >= len(self._threads)
                    and len(self._threads) < MAX_GLOBAL_WORKERS):
                thread = threading.Thread(target=self._run, name="file-broker-request",
                                          daemon=True)
                thread.start()
                self._threads.append(thread)
            self._queue.append((callback, args))
            self._condition.notify()

    def _run(self):
        while True:
            with self._condition:
                while not self._queue and not self._closed:
                    self._condition.wait()
                if not self._queue:
                    return
                callback, args = self._queue.popleft()
                self._busy += 1
            try:
                callback(*args)
            finally:
                with self._condition:
                    self._busy -= 1

    def shutdown(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()
        for thread in self._threads:
            thread.join()


class _Connection:
    """One client: its opaque handles, directory cursors and bounded request workers."""

    def __init__(self, server, sock):
        self.server = server
        self.host_files = server.host_files
        self.sock = sock
        self._state = server._condition
        self._send = threading.Lock()
        self._handles = {}
        self._cursors = {}
        self._handle_count = 0
        self._cursor_count = 0
        self._requests = 0
        self._closed = False
        self._last_id = 0
        self.thread = threading.Thread(target=self._run, name="file-broker-connection", daemon=True)
        self._operations = {
            "getattr": self._getattr, "readdir": self._readdir, "open": self._open,
            "create": self._create, "read": self._read, "write": self._write,
            "truncate": self._truncate, "flush": self._flush, "fsync": self._fsync,
            "close": self._close, "mkdir": self._mkdir, "unlink": self._unlink,
            "rmdir": self._rmdir, "rename": self._rename, "chmod": self._chmod,
            "utimens": self._utimens, "access": self._access, "statfs": self._statfs,
        }

    def start(self):
        self.thread.start()

    def close(self):
        with self._state:
            self._closed = True
            self._state.notify_all()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _envelope(self, message):
        if set(message) != {"id", "op", "args"}:
            raise ProtocolError("Invalid request envelope")
        request_id, op, args = message["id"], message["op"], message["args"]
        if type(request_id) is not int or request_id <= self._last_id:
            raise ProtocolError("Request ids must increase")
        if not isinstance(op, str) or not isinstance(args, dict):
            raise ProtocolError("Invalid request envelope")
        self._last_id = request_id
        return request_id, op, args

    def _run(self):
        try:
            while True:
                message = read_frame(self.sock)
                if message is None:
                    break
                request = self._envelope(message)
                if not self.server._reserve_request(self):
                    break
                try:
                    self.server._pool.submit(self._serve, *request)
                except Exception:
                    self.server._release_request(self)
                    break
        except (ProtocolError, OSError):
            pass
        finally:
            self._retire()

    def _retire(self):
        self.close()
        with self._state:
            while self._requests:
                self._state.wait()
            handles, self._handles = self._handles, {}
            cursors, self._cursors = self._cursors, {}
        try:
            for handle in handles.values():
                try:
                    self.host_files.close(handle)
                except OSError:
                    pass
                finally:
                    self._release_resource("handle")
            for _, cursor in cursors.values():
                try:
                    cursor.close()
                except OSError:
                    pass
                finally:
                    self._release_resource("cursor")
        finally:
            self.sock.close()
            self.server._forget(self)

    def _serve(self, request_id, op, args):
        try:
            try:
                response = {"id": request_id, "ok": True, "result": self._dispatch(op, args)}
            except OSError as failure:
                response = {"id": request_id, "ok": False,
                            "errno": errno_name(failure.errno or errno.EIO)}
            except (KeyError, TypeError, ValueError, binascii.Error):
                response = {"id": request_id, "ok": False, "errno": "EINVAL"}
            except Exception:
                response = {"id": request_id, "ok": False, "errno": "EIO"}
            try:
                frame = encode_frame(response)
            except (ProtocolError, ValueError):
                frame = encode_frame({"id": request_id, "ok": False, "errno": "EIO"})
            try:
                with self._send:
                    self.sock.sendall(frame)
            except OSError:
                self.close()
        finally:
            self.server._release_request(self)

    def _dispatch(self, op, args):
        operation = self._operations.get(op)
        if operation is None:
            raise _failure(errno.EPERM if op in _REFUSED else errno.ENOSYS)
        return operation(args)

    def _handle(self, token):
        with self._state:
            handle = self._handles.get(_string(token, 64))
        if handle is None:
            raise _failure(errno.EBADF)
        return handle

    def _reserve_resource(self, kind):
        with self._state:
            count = "_" + kind + "_count"
            local_limit = MAX_HANDLES if kind == "handle" else MAX_CURSORS
            global_limit = MAX_GLOBAL_HANDLES if kind == "handle" else MAX_GLOBAL_CURSORS
            if self._closed:
                raise _failure(errno.EIO)
            if (getattr(self, count) >= local_limit
                    or getattr(self.server, count) >= global_limit):
                raise _failure(errno.EMFILE)
            setattr(self, count, getattr(self, count) + 1)
            setattr(self.server, count, getattr(self.server, count) + 1)

    def _release_resource(self, kind):
        with self._state:
            count = "_" + kind + "_count"
            setattr(self, count, getattr(self, count) - 1)
            setattr(self.server, count, getattr(self.server, count) - 1)

    def _open_handle(self, operation, *args, **kwargs):
        token = secrets.token_hex(16)
        self._reserve_resource("handle")
        try:
            handle = operation(*args, **kwargs)
        except BaseException:
            self._release_resource("handle")
            raise
        with self._state:
            self._handles[token] = handle
        return {"handle": token}

    def _getattr(self, args):
        _fields(args, ("path",))
        return encode_attributes(self.host_files.getattr(_string(args["path"])))

    def _readdir(self, args):
        _fields(args, ("path",), ("cursor",))
        path, token = _string(args["path"]), args.get("cursor")
        cursor = None
        if token is None:
            self._reserve_resource("cursor")
        else:
            with self._state:
                entry = self._cursors.pop(_string(token, 64), None)
            if entry is None:
                raise _failure(errno.EBADF)
            previous_path, cursor = entry
        retained = False
        try:
            if cursor is None:
                cursor = self.host_files.open_directory(path)
            elif previous_path != path:
                raise _failure(errno.EBADF)
            names, done = cursor.page(PAGE_NAMES, PAGE_BYTES)
            if done:
                return {"names": names, "cursor": None}
            token = secrets.token_hex(16)
            with self._state:
                self._cursors[token] = (path, cursor)
            retained = True
            return {"names": names, "cursor": token}
        finally:
            if not retained:
                try:
                    if cursor is not None:
                        cursor.close()
                finally:
                    self._release_resource("cursor")

    def _open(self, args):
        _fields(args, ("path", "read", "write", "append", "truncate"))
        return self._open_handle(
            self.host_files.open, _string(args["path"]), read=_boolean(args["read"]),
            write=_boolean(args["write"]), append=_boolean(args["append"]),
            truncate=_boolean(args["truncate"]))

    def _create(self, args):
        _fields(args, ("path", "mode", "read", "write", "exclusive"), ("append",))
        return self._open_handle(
            self.host_files.create, _string(args["path"]),
            _integer(args["mode"], maximum=0o7777), read=_boolean(args["read"]),
            write=_boolean(args["write"]), append=_boolean(args.get("append", False)),
            exclusive=_boolean(args["exclusive"]))

    def _read(self, args):
        _fields(args, ("handle", "offset", "size"))
        data = self.host_files.read(self._handle(args["handle"]),
                                    _integer(args["size"], maximum=MAX_CHUNK),
                                    _integer(args["offset"]))
        return {"data": base64.b64encode(data).decode("ascii")}

    def _write(self, args):
        _fields(args, ("handle", "offset", "data"))
        encoded = _string(args["data"], _ENCODED_CHUNK)
        data = base64.b64decode(encoded, validate=True)
        if len(data) > MAX_CHUNK:
            raise ValueError("Write chunk exceeds 64 KiB")
        return {"written": self.host_files.write(self._handle(args["handle"]), data,
                                                 _integer(args["offset"]))}

    def _truncate(self, args):
        _fields(args, ("length",), ("path", "handle"))
        if ("path" in args) == ("handle" in args):
            raise ValueError("Truncate needs exactly one of path or handle")
        length = _integer(args["length"])
        if "handle" in args:
            self.host_files.truncate(None, length, self._handle(args["handle"]))
        else:
            self.host_files.truncate(_string(args["path"]), length)

    def _flush(self, args):
        _fields(args, ("handle",))
        self.host_files.flush(self._handle(args["handle"]))

    def _fsync(self, args):
        _fields(args, ("handle", "datasync"))
        self.host_files.fsync(self._handle(args["handle"]), _boolean(args["datasync"]))

    def _close(self, args):
        _fields(args, ("handle",))
        with self._state:
            handle = self._handles.pop(_string(args["handle"], 64), None)
        if handle is None:
            raise _failure(errno.EBADF)
        try:
            self.host_files.close(handle)  # Release stays permitted after revocation.
        finally:
            self._release_resource("handle")

    def _mkdir(self, args):
        _fields(args, ("path", "mode"))
        self.host_files.mkdir(_string(args["path"]), _integer(args["mode"], maximum=0o7777))

    def _unlink(self, args):
        _fields(args, ("path",))
        self.host_files.unlink(_string(args["path"]))

    def _rmdir(self, args):
        _fields(args, ("path",))
        self.host_files.rmdir(_string(args["path"]))

    def _rename(self, args):
        _fields(args, ("old", "new"))
        self.host_files.rename(_string(args["old"]), _string(args["new"]))

    def _chmod(self, args):
        _fields(args, ("path", "mode"))
        self.host_files.chmod(_string(args["path"]), _integer(args["mode"], maximum=0o7777))

    def _utimens(self, args):
        _fields(args, ("path", "times"))
        times = args["times"]
        if times is not None:
            if not isinstance(times, list) or len(times) != 2:
                raise ValueError("Invalid times")
            times = tuple(_number(value) for value in times)
        self.host_files.utimens(_string(args["path"]), times)

    def _access(self, args):
        _fields(args, ("path", "read", "write", "execute"))
        self.host_files.access(_string(args["path"]), read=_boolean(args["read"]),
                               write=_boolean(args["write"]), execute=_boolean(args["execute"]))

    def _statfs(self, args):
        _fields(args, ("path",))
        return encode_statfs(self.host_files.statfs(_string(args["path"])))


class FileBrokerServer:
    """Serves one HostFiles to framed clients on a Unix socket in a private directory."""

    def __init__(self, host_files, path):
        self.host_files = host_files
        self.path = os.fspath(path)
        if not os.path.isabs(self.path):
            raise ValueError("The broker socket path must be absolute")
        if len(os.fsencode(self.path)) >= _socket_limit():
            raise _failure(errno.ENAMETOOLONG)
        parent = os.lstat(os.path.dirname(self.path))
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                or parent.st_mode & 0o077):
            raise OSError(errno.EACCES, "The broker socket directory must be owner-only")
        try:
            existing = os.lstat(self.path)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.geteuid():
                raise _failure(errno.EEXIST)
            os.unlink(self.path)  # A stale socket from an earlier run in this private directory.
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._sock.bind(self.path)
            # The owner-only parent already excludes other users; the mode is defence in depth.
            os.chmod(self.path, 0o600)
            self._identity = os.lstat(self.path)[1:3]
            self._sock.listen(8)
        except BaseException:
            self._sock.close()
            raise
        self._wake_read, self._wake_write = os.pipe()
        self._condition = threading.Condition()
        self._lock = self._condition
        self._pool = _RequestPool()
        self._requests = 0
        self._handle_count = 0
        self._cursor_count = 0
        self._connections = set()
        self._closed = False
        self._thread = threading.Thread(target=self._accept, name="file-broker", daemon=True)
        self._thread.start()

    def _accept(self):
        while True:
            ready, _, _ = select.select([self._sock, self._wake_read], [], [])
            if self._wake_read in ready:
                return
            try:
                sock, _ = self._sock.accept()
            except OSError:
                continue
            with self._lock:
                if self._closed:
                    sock.close()
                    return
                if len(self._connections) >= MAX_CONNECTIONS:
                    sock.close()
                    continue
                connection = None
                try:
                    connection = _Connection(self, sock)
                    self._connections.add(connection)
                    connection.start()
                except Exception:
                    if connection is not None:
                        self._connections.discard(connection)
                    sock.close()

    def _reserve_request(self, connection):
        with self._condition:
            while not self._closed and not connection._closed:
                if (self._requests < MAX_GLOBAL_WORKERS
                        and connection._requests < MAX_CONCURRENCY):
                    self._requests += 1
                    connection._requests += 1
                    return True
                self._condition.wait()
            return False

    def _release_request(self, connection):
        with self._condition:
            self._requests -= 1
            connection._requests -= 1
            self._condition.notify_all()

    def _forget(self, connection):
        with self._lock:
            self._connections.discard(connection)
            self._condition.notify_all()

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            connections = list(self._connections)
            self._condition.notify_all()
        # Wake incomplete-frame readers and blocked sends before any join.
        for connection in connections:
            connection.close()
        os.write(self._wake_write, b"x")
        self._thread.join()
        self._sock.close()
        os.close(self._wake_read)
        os.close(self._wake_write)
        try:
            if os.lstat(self.path)[1:3] == self._identity:
                os.unlink(self.path)
        except FileNotFoundError:
            pass
        for connection in connections:
            connection.thread.join()
        self._pool.shutdown()


class _Waiter:
    __slots__ = ("event", "response")

    def __init__(self):
        self.event = threading.Event()
        self.response = None


class RemoteHostFiles:
    """The HostFiles interface over one broker connection (guest side).

    Handles are the host's opaque strings. A lost transport fails every pending
    and later operation with EIO; there is no reconnection or local fallback.
    """

    def __init__(self, sock):
        self._sock = sock
        self._send = threading.Lock()
        self._state = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENCY)
        self._pending = {}
        self._next_id = 1
        self._failed = False
        self._reader = threading.Thread(target=self._read_responses,
                                        name="file-broker-client", daemon=True)
        self._reader.start()

    @classmethod
    def connect(cls, path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(os.fspath(path))
        except BaseException:
            sock.close()
            raise
        return cls(sock)

    def _fail(self):
        with self._state:
            self._failed = True
            pending, self._pending = self._pending, {}
        for waiter in pending.values():
            waiter.event.set()
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _read_responses(self):
        try:
            while True:
                message = read_frame(self._sock)
                if message is None:
                    break
                request_id, ok = message.get("id"), message.get("ok")
                if (type(request_id) is not int or type(ok) is not bool
                        or set(message) != {"id", "ok", "result" if ok else "errno"}
                        or not (ok or isinstance(message["errno"], str))):
                    break
                with self._state:
                    waiter = self._pending.pop(request_id, None)
                if waiter is None:
                    break
                waiter.response = message
                waiter.event.set()
        except (ProtocolError, OSError):
            pass
        finally:
            self._fail()
            self._sock.close()

    def _call(self, op, **args):
        with self._slots:
            waiter = _Waiter()
            with self._send:
                with self._state:
                    if self._failed:
                        raise _failure(errno.EIO)
                    request_id = self._next_id
                    self._next_id += 1
                try:
                    frame = encode_frame({"id": request_id, "op": op, "args": args})
                except (ProtocolError, ValueError):
                    raise _failure(errno.EINVAL) from None
                with self._state:
                    # Registered under the lock _fail uses, so a failure always wakes it.
                    if self._failed:
                        raise _failure(errno.EIO)
                    self._pending[request_id] = waiter
                try:
                    self._sock.sendall(frame)
                except OSError:
                    self._fail()
                    raise _failure(errno.EIO) from None
            waiter.event.wait()
        response = waiter.response
        if response is None:
            raise _failure(errno.EIO)
        if not response["ok"]:
            raise _failure(errno_value(response["errno"]))
        return response["result"]

    @staticmethod
    def _checked(call, *args):
        """Malformed host replies are IO failures, never guessed values."""
        try:
            return call(*args)
        except (KeyError, TypeError, ValueError, binascii.Error):
            raise _failure(errno.EIO) from None

    def getattr(self, target):
        return self._checked(decode_attributes, self._call("getattr", path=target))

    def readdir(self, target):
        names, cursor = [], None
        while True:
            args = {"path": target} if cursor is None else {"path": target, "cursor": cursor}
            page = self._call("readdir", **args)
            if (not isinstance(page, dict) or set(page) != {"names", "cursor"}
                    or not isinstance(page["names"], list)
                    or not all(isinstance(name, str) for name in page["names"])
                    or not (page["cursor"] is None or isinstance(page["cursor"], str))):
                raise _failure(errno.EIO)
            names.extend(page["names"])
            cursor = page["cursor"]
            if cursor is None:
                names.sort()
                return names

    @staticmethod
    def _token(result):
        if not isinstance(result, dict) or not isinstance(result.get("handle"), str):
            raise _failure(errno.EIO)
        return result["handle"]

    def open(self, target, *, read=True, write=False, append=False, truncate=False):
        return self._token(self._call("open", path=target, read=read, write=write,
                                      append=append, truncate=truncate))

    def create(self, target, mode, *, read=True, write=True, append=False, exclusive=True):
        return self._token(self._call("create", path=target, mode=mode, read=read,
                                      write=write, append=append, exclusive=exclusive))

    def read(self, handle, size, offset):
        chunks = []
        while size > 0:
            count = min(size, MAX_CHUNK)
            result = self._call("read", handle=handle, offset=offset, size=count)
            data = self._checked(lambda: base64.b64decode(result["data"], validate=True))
            if len(data) > count:
                raise _failure(errno.EIO)
            chunks.append(data)
            if len(data) < count:
                break
            offset += count
            size -= count
        return b"".join(chunks)

    def write(self, handle, data, offset):
        data = bytes(data)
        total = 0
        for start in range(0, max(len(data), 1), MAX_CHUNK):
            chunk = data[start:start + MAX_CHUNK]
            result = self._call("write", handle=handle, offset=offset + start,
                                data=base64.b64encode(chunk).decode("ascii"))
            written = result.get("written") if isinstance(result, dict) else None
            if type(written) is not int or not 0 <= written <= len(chunk):
                raise _failure(errno.EIO)
            total += written
            if written < len(chunk):
                break
        return total

    def truncate(self, target, length, handle=None):
        if handle is not None:
            self._call("truncate", handle=handle, length=length)
        else:
            self._call("truncate", path=target, length=length)

    def flush(self, handle):
        self._call("flush", handle=handle)

    def fsync(self, handle, datasync=False):
        self._call("fsync", handle=handle, datasync=bool(datasync))

    def close(self, handle):
        self._call("close", handle=handle)

    def close_all(self):
        """Ends the connection; the host closes every handle it opened."""
        self._fail()
        self._reader.join()

    def mkdir(self, target, mode):
        self._call("mkdir", path=target, mode=mode)

    def unlink(self, target):
        self._call("unlink", path=target)

    def rmdir(self, target):
        self._call("rmdir", path=target)

    def rename(self, old, new):
        self._call("rename", old=old, new=new)

    def chmod(self, target, mode):
        self._call("chmod", path=target, mode=mode)

    def utimens(self, target, times=None):
        self._call("utimens", path=target,
                   times=None if times is None else [float(times[0]), float(times[1])])

    def access(self, target, *, read=False, write=False, execute=False):
        self._call("access", path=target, read=read, write=write, execute=execute)

    def statfs(self, target):
        return self._checked(decode_statfs, self._call("statfs", path=target))
