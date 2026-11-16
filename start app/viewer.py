"""Host viewer for the macOS VM's isolated displays: noVNC pages on their own 127.0.0.1 origin.

Each published display generation has a random credential that only opens a WebSocket to that display's owned
SSH forward (a private host Unix socket). It is never a control-API credential: the control server is a different
origin with its own bearer token, and this server has no control routes. The viewer offers keyboard, pointer and
resize only: no clipboard bridge, file transfer, power or navigation actions.
"""
import asyncio
import mimetypes
from pathlib import Path
import secrets
import socket
import threading

from aiohttp import WSMsgType, web

KINDS = ("ombp", "browser")
TITLES = {"ombp": "OMBP · isolated desktop", "browser": "OMBP · isolated browser"}
# Only the RFB client library; noVNC's own app/ UI (clipboard panel, power menu, settings) is never served.
ASSET_TREES = ("core", "vendor")
MAX_FRAME = 1 << 20
CHUNK = 1 << 16
PROTOCOL = "binary"
TOKEN_PREFIX = "ombp."
HERE = Path(__file__).resolve().parent

PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><link rel="stylesheet" href="/viewer.css"><script type="module" src="/viewer.js"></script></head>
<body><div id="screen"></div><div id="status" role="status">Connecting…</div></body>
</html>
"""


class _Display:
    def __init__(self, kind, generation, socket_path):
        self.kind = kind
        self.generation = generation
        self.socket_path = str(socket_path)
        self.id = secrets.token_hex(8)
        self.token = secrets.token_urlsafe(32)
        self.sessions = set()


class ViewerServer:
    """One aiohttp server thread. publish/retire/desktops/close are safe from any launcher thread."""

    def __init__(self, asset_dir):
        self.assets = Path(asset_dir).resolve(strict=True)
        if not (self.assets / "core/rfb.js").is_file():
            raise ValueError(f"noVNC assets not found at {self.assets}; start through the Nix launcher")
        self.host = "127.0.0.1"
        self.port = None
        self.origin = None
        self._displays = {}
        self._lock = threading.Lock()
        self._loop = None
        self._runner = None
        self._thread = None

    # --- lifecycle -----------------------------------------------------------------------------------------------

    def start(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind((self.host, 0))
        listener.listen(64)
        self.port = listener.getsockname()[1]
        self.origin = f"http://{self.host}:{self.port}"
        ready = threading.Event()
        failure = []

        def serve():
            loop = self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                app = web.Application(middlewares=[self._guard], client_max_size=4096)
                app.router.add_get("/view/{id}", self._page)
                app.router.add_get("/viewer.js", self._own_file)
                app.router.add_get("/viewer.css", self._own_file)
                app.router.add_get("/novnc/{path:.+}", self._asset)
                app.router.add_get("/ws/{id}", self._socket)
                # No access log: request lines and headers stay out of every log.
                self._runner = web.AppRunner(app, access_log=None, handle_signals=False)
                loop.run_until_complete(self._runner.setup())
                loop.run_until_complete(web.SockSite(self._runner, listener).start())
            except BaseException as error:
                failure.append(error)
                ready.set()
                loop.close()
                return
            ready.set()
            loop.run_forever()
            loop.run_until_complete(self._runner.cleanup())
            loop.close()

        self._thread = threading.Thread(target=serve, name="ombp-viewer", daemon=True)
        self._thread.start()
        ready.wait()
        if failure:
            raise RuntimeError(f"Viewer server failed to start: {failure[0]}")
        return self

    def close(self):
        for kind in KINDS:
            self.retire(kind)
        if self._loop is not None and self._thread is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=10)
            self._thread = None

    # --- registry ------------------------------------------------------------------------------------------------

    def publish(self, kind, generation, socket_path):
        """Publish one display generation reachable through `socket_path`; return its viewer URL."""
        if kind not in KINDS or not isinstance(generation, int) or isinstance(generation, bool):
            raise ValueError("Invalid display")
        display = _Display(kind, generation, socket_path)
        with self._lock:
            previous = self._displays.get(kind)
            self._displays[kind] = display
        if previous is not None:
            self._disconnect(previous)
        return self._url(display)

    def retire(self, kind, generation=None):
        """Revoke a display's credential and disconnect its viewers; a newer generation is left alone."""
        with self._lock:
            display = self._displays.get(kind)
            if display is None or (generation is not None and display.generation != generation):
                return
            del self._displays[kind]
        self._disconnect(display)

    def desktops(self):
        with self._lock:
            return [{"kind": kind, "url": self._url(self._displays[kind])} for kind in KINDS if kind in self._displays]

    def _url(self, display):
        # The fragment never reaches a server; the viewer strips it from history before connecting.
        return f"{self.origin}/view/{display.id}#{display.token}"

    def _disconnect(self, display):
        loop = self._loop
        if loop is None or loop.is_closed():
            return

        def cancel():
            for task in list(display.sessions):
                task.cancel()
        try:
            loop.call_soon_threadsafe(cancel)
        except RuntimeError:
            pass

    def _lookup(self, display_id):
        with self._lock:
            return next((item for item in self._displays.values() if item.id == display_id), None)

    # --- HTTP ----------------------------------------------------------------------------------------------------

    @web.middleware
    async def _guard(self, request, handler):
        # DNS rebinding: only this exact loopback authority is ever served.
        if request.headers.get("Host") != f"{self.host}:{self.port}":
            return web.Response(status=403, text="Forbidden")
        try:
            response = await handler(request)
        except web.HTTPException as error:
            # Unknown routes and methods: a plain response that still carries the security headers.
            response = web.Response(status=error.status, text=error.reason)
        if not response.prepared:
            self._secure(response)
        return response

    def _secure(self, response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            f"connect-src ws://{self.host}:{self.port}; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    async def _page(self, request):
        display = self._lookup(request.match_info["id"])
        if display is None:
            return web.Response(status=410, text="This isolated display has closed. Use Open in the launcher.")
        return web.Response(text=PAGE.format(title=TITLES[display.kind]), content_type="text/html", charset="utf-8")

    async def _own_file(self, request):
        name = request.path.lstrip("/")
        return web.Response(body=(HERE / name).read_bytes(), charset="utf-8",
                            content_type="text/javascript" if name.endswith(".js") else "text/css")

    async def _asset(self, request):
        relative = Path(request.match_info["path"])
        if relative.is_absolute() or ".." in relative.parts or not relative.parts \
                or relative.parts[0] not in ASSET_TREES:
            return web.Response(status=404, text="Not found")
        path = (self.assets / relative).resolve()
        if not path.is_relative_to(self.assets) or not path.is_file():
            return web.Response(status=404, text="Not found")
        kind = "text/javascript" if path.suffix in (".js", ".mjs") else (
            mimetypes.guess_type(path.name)[0] or "application/octet-stream")
        return web.Response(body=path.read_bytes(), content_type=kind)

    # --- WebSocket -----------------------------------------------------------------------------------------------

    def _authorized(self, request, display):
        if display is None or request.headers.get("Origin") != self.origin:
            return False
        offered = [item.strip() for item in request.headers.get("Sec-WebSocket-Protocol", "").split(",")]
        tokens = [item[len(TOKEN_PREFIX):] for item in offered if item.startswith(TOKEN_PREFIX)]
        if PROTOCOL not in offered or len(tokens) != 1:
            return False
        return secrets.compare_digest(tokens[0].encode("utf-8", "replace"), display.token.encode())

    async def _socket(self, request):
        display = self._lookup(request.match_info["id"])
        if not self._authorized(request, display):
            return web.Response(status=403, text="Forbidden")
        task = asyncio.current_task()
        display.sessions.add(task)
        writer = None
        try:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(display.socket_path), 10)
            except (OSError, asyncio.TimeoutError):
                return web.Response(status=502, text="Isolated display is not reachable")
            # Negotiate only "binary": the credential-bearing protocol is never echoed back.
            ws = web.WebSocketResponse(protocols=(PROTOCOL,), max_msg_size=MAX_FRAME, autoping=True, heartbeat=30)
            await ws.prepare(request)
            if self._lookup(display.id) is not display:
                await ws.close()
                return ws

            async def upstream():
                async for message in ws:
                    if message.type != WSMsgType.BINARY:
                        break
                    writer.write(message.data)
                    await writer.drain()

            async def downstream():
                while data := await reader.read(CHUNK):
                    await ws.send_bytes(data)

            pumps = [asyncio.ensure_future(upstream()), asyncio.ensure_future(downstream())]
            try:
                await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for pump in pumps:
                    pump.cancel()
                await asyncio.gather(*pumps, return_exceptions=True)
                await ws.close()
            return ws
        finally:
            display.sessions.discard(task)
            if writer is not None:
                writer.close()
