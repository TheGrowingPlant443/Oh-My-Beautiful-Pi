"""Local control UI; its bearer token and policy never enter the container."""
import argparse
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
from urllib.parse import parse_qs, urlsplit

from catalog import find_folders
from host_browser import open_url
from policy import Policy
from runtime import Runtime

LOG_CAP = 256 << 10


def read_log(path, log_start, after):
    """launch.log bytes [max(after, log_start), end) as text, capped to the last LOG_CAP bytes of that range.

    Before any operation (`log_start` None) nothing is returned. An incomplete trailing UTF-8 sequence is held
    back for the next request, so a character split by a concurrent write is never shown as replacement text.
    """
    try:
        with open(path, "rb") as stream:
            end = os.fstat(stream.fileno()).st_size
            begin = min(end, max(after, end if log_start is None else log_start))
            truncated = end - begin > LOG_CAP
            if truncated:
                begin = end - LOG_CAP
            stream.seek(begin)
            data = stream.read(end - begin)
    except FileNotFoundError:
        begin, data, truncated = 0, b"", False
    if truncated:
        skip = 0
        while skip < min(3, len(data)) and data[skip] & 0xC0 == 0x80:
            skip += 1
        data, begin = data[skip:], begin + skip
    for back in range(1, min(4, len(data)) + 1):
        lead = data[-back]
        if lead & 0xC0 != 0x80:
            width = 2 if lead >> 5 == 0b110 else 3 if lead >> 4 == 0b1110 else 4 if lead >> 3 == 0b11110 else 1
            if width > back:
                data = data[:-back]
            break
    return {"start": log_start, "end": begin + len(data), "text": data.decode("utf-8", errors="replace"),
            "truncated": truncated}


def state_directory(explicit=None, platform=sys.platform, home=None, environ=None):
    """--state-dir if given; otherwise the platform default, keeping an existing pre-macOS-support default."""
    if explicit is not None:
        return explicit
    home = Path.home() if home is None else home
    environ = os.environ if environ is None else environ
    old = Path(environ.get("XDG_STATE_HOME") or home / ".local/state") / "ombp-start"
    if platform != "darwin":
        return old
    new = home / "Library/Application Support/ombp-start"
    old_exists, new_exists = os.path.lexists(old), os.path.lexists(new)
    if old_exists and new_exists:
        # Never merge two secret/state directories automatically.
        raise ValueError(f"Launcher state exists in both {old} and {new}; choose one with --state-dir")
    return old if old_exists else new


def default_source(explicit, saved, cwd):
    """--source-dir, else the last successful launch's source, else a checkout here (or above start app)."""
    if explicit is not None:
        return str(explicit)
    if saved:
        return saved["source"]
    checkout = cwd.parent if cwd.name == "start app" else cwd
    return str(checkout) if (checkout / "flake.nix").is_file() else ""


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, policy, runtime, port=0, source=""):
        self.policy = policy
        self.runtime = runtime
        self.source = str(source)
        self.token = secrets.token_urlsafe(32)
        super().__init__(("127.0.0.1", port), Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"

    @property
    def url(self):
        return f"{self.origin}/#{self.token}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        # Local control requests are deliberately not retained in access logs.
        pass

    def respond(self, status, value, content_type="application/json"):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        return (self.headers.get("Host") == self.server.origin.removeprefix("http://")
                and self.headers.get("Origin", self.server.origin) == self.server.origin
                and secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + self.server.token))

    def do_GET(self):
        files = {"/": ("index.html", "text/html; charset=utf-8"),
                 "/ui.js": ("ui.js", "text/javascript; charset=utf-8"),
                 "/ui.css": ("ui.css", "text/css; charset=utf-8")}
        url = urlsplit(self.path)
        if self.path in files:
            name, content_type = files[self.path]
            self.respond(200, (Path(__file__).parent / name).read_bytes(), content_type)
        elif url.path in ("/api/status", "/api/catalog", "/api/folders", "/api/log"):
            if not self.authorized():
                self.respond(403, {"error": "Unauthorized control request"})
                return
            if url.path == "/api/catalog":
                self.respond(200, self.server.runtime.catalog())
                return
            if url.path == "/api/log":
                after = parse_qs(url.query).get("after", ["0"])[0]
                if not (after.isascii() and after.isdigit()):
                    self.respond(400, {"error": "after must be a non-negative integer byte offset"})
                    return
                # Only the offset is read under the runtime lock; the file read holds none.
                self.respond(200, read_log(self.server.runtime.log_path, self.server.runtime.log_origin(),
                                           int(after)))
                return
            if url.path == "/api/folders":
                query = parse_qs(url.query).get("q", [""])[0]
                self.respond(200, find_folders(query, private_paths=self.server.policy.private_paths))
                return
            self.respond(200, {"policy": self.server.policy.snapshot(), "history": self.server.policy.events(),
                               "runtime": self.server.runtime.status(), "source": self.server.source,
                               "history_error": self.server.policy.history_error,
                               "requirements": self.server.runtime.requirements_status(),
                               "home": str(Path.home())})
        else:
            self.respond(404, {"error": "Not found"})

    def do_POST(self):
        if not self.authorized():
            self.respond(403, {"error": "Unauthorized control request"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 131072:
                raise ValueError("Invalid request size")
            self.connection.settimeout(10)
            value = json.loads(self.rfile.read(length))
            if self.path == "/api/policy":
                self.server.policy.replace(value)
            elif self.path == "/api/start":
                operation = self.server.runtime.start(value["source"], value["mode"], value["desktop"], value["gpu"],
                                                      value["agent"])
                # Accepted: progress and failures arrive through /api/status.
                self.respond(202, {"operation_id": operation})
                return
            elif self.path == "/api/prepare":
                if value != {}:
                    raise ValueError("Prepare takes an empty JSON object")
                self.respond(202, {"operation_id": self.server.runtime.prepare()})
                return
            elif self.path == "/api/omp-copy":
                if not isinstance(value, dict) or set(value) != {"replace_previous"}:
                    raise ValueError("Copy again requires explicit backup replacement confirmation")
                self.server.runtime.copy_omp_again(value["replace_previous"])
            elif self.path == "/api/stop":
                self.server.runtime.stop()
            elif self.path == "/api/history/clear":
                self.server.policy.clear_history()
            elif self.path == "/api/history/forget":
                self.server.policy.forget(value)
            else:
                self.respond(404, {"error": "Not found"})
                return
            self.respond(200, {"ok": True})
        except (ValueError, OSError, RuntimeError, KeyError, TypeError) as error:
            self.respond(400, {"error": str(error)})
        except Exception:
            self.respond(500, {"error": "Operation failed; inspect launcher terminal and launch.log"})
            raise


def auto_start(runtime, settings):
    """Start OMBP like a Start click; failures show in the UI like a failed run."""
    try:
        runtime.start(settings["source"], settings["mode"], settings["desktop"], settings["gpu"], settings["agent"])
    except Exception as error:  # Any failure must reach the UI instead of dying in this thread.
        runtime.fail(f"Automatic start failed: {error}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path,
                        help="Launcher state (default: ${XDG_STATE_HOME:-~/.local/state}/ombp-start; on macOS "
                             "~/Library/Application Support/ombp-start unless the former already exists)")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--source-dir", type=Path,
                        help="OMBP checkout to build on each Start click (default: the last successful launch's, "
                             "else the working directory or its parent from start app, if it is a checkout)")
    args = parser.parse_args()
    try:
        policy = Policy(state_directory(args.state_dir))
        source = default_source(args.source_dir, policy.last_launch(), Path.cwd())
    except ValueError as error:
        parser.error(str(error))
    lock_fd = os.open(policy.directory / "launcher.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        parser.error("A launcher already owns this state directory")
    runtime = Runtime(policy)
    server = Server(policy, runtime, args.port, source)

    def shutdown(_signal, _frame):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    print(server.url, flush=True)
    if settings := policy.snapshot()["auto_start"]:
        threading.Thread(target=auto_start, args=(runtime, settings), daemon=True).start()
    if not args.no_browser:
        try:
            open_url(server.url)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            # The launcher keeps serving: the printed URL still works in a supported browser.
            print(f"Could not open the launcher UI: {error}\nOpen {server.url}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    finally:
        runtime.close()
        server.server_close()
        os.close(lock_fd)


if __name__ == "__main__":
    main()
