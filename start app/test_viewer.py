import asyncio
import http.client
import json
import logging
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest

try:
    import aiohttp
except ImportError:  # The launcher's Nix Python always has it; a bare system Python may not.
    aiohttp = None

from app import Server
from policy import Policy
from runtime import Runtime

BANNER = b"RFB 003.008\n"


class VncStub:
    """A real Unix-socket endpoint standing in for the owned SSH forward: RFB banner, then echo."""

    def __init__(self, path):
        self.path = str(path)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen(8)
        self.connections = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            self.connections.append(connection)
            threading.Thread(target=self.echo, args=(connection,), daemon=True).start()

    @staticmethod
    def echo(connection):
        try:
            connection.sendall(BANNER)
            while data := connection.recv(65536):
                connection.sendall(data)
        except OSError:
            pass
        finally:
            connection.close()

    def close(self):
        self.listener.close()


@unittest.skipIf(aiohttp is None, "viewer needs aiohttp (pinned in the launcher's Nix Python)")
class ViewerTests(unittest.TestCase):
    def setUp(self):
        from viewer import ViewerServer
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        assets = self.root / "novnc"
        for name, text in (("core/rfb.js", "export default class RFB {}\n"), ("vendor/pako/x.js", "export {};\n"),
                           ("app/ui.js", "clipboard UI\n"), ("vnc.html", "<html></html>\n")):
            (assets / name).parent.mkdir(parents=True, exist_ok=True)
            (assets / name).write_text(text)
        (self.root / "outside.js").write_text("secret\n")
        self.stub = VncStub(self.root / "ombp.sock")
        self.addCleanup(self.stub.close)
        self.other = VncStub(self.root / "browser.sock")
        self.addCleanup(self.other.close)
        self.viewer = ViewerServer(assets).start()
        self.addCleanup(self.viewer.close)
        self.url = self.viewer.publish("ombp", 1, self.stub.path)
        self.page, self.token = self.url.split("#")
        self.display_id = self.page.rsplit("/", 1)[1]

    def run_async(self, coroutine):
        return asyncio.run(asyncio.wait_for(coroutine, 20))

    async def _connect(self, display_id=None, protocols=None, origin=None, host=None):
        headers = {"Origin": self.viewer.origin if origin is None else origin}
        if host is not None:
            headers["Host"] = host
        session = aiohttp.ClientSession()
        try:
            ws = await session.ws_connect(
                f"ws://127.0.0.1:{self.viewer.port}/ws/{display_id or self.display_id}",
                protocols=protocols if protocols is not None else ("binary", f"ombp.{self.token}"),
                headers=headers, autoping=True)
        except BaseException:
            await session.close()
            raise
        return session, ws

    def handshake_status(self, **kwargs):
        async def attempt():
            try:
                session, ws = await self._connect(**kwargs)
            except aiohttp.WSServerHandshakeError as error:
                return error.status
            await ws.close()
            await session.close()
            return 101
        return self.run_async(attempt())

    def http(self, path, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.viewer.port, timeout=10)
        self.addCleanup(connection.close)
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()

    def test_owned_unix_forward_reaches_real_loopback_tcp_vnc(self):
        async def exchange():
            connections = []

            async def vnc(reader, writer):
                connections.append(writer.get_extra_info("peername"))
                try:
                    writer.write(BANNER)
                    await writer.drain()
                    while data := await reader.read(65536):
                        writer.write(data)
                        await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()

            async with await asyncio.start_server(vnc, "127.0.0.1", 0) as tcp:
                port = tcp.sockets[0].getsockname()[1]

                async def forward(reader, writer):
                    upstream, outgoing = await asyncio.open_connection("127.0.0.1", port)

                    async def copy(source, destination):
                        while data := await source.read(65536):
                            destination.write(data)
                            await destination.drain()

                    pumps = [asyncio.create_task(copy(reader, outgoing)),
                             asyncio.create_task(copy(upstream, writer))]
                    try:
                        await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
                    finally:
                        for pump in pumps:
                            pump.cancel()
                        await asyncio.gather(*pumps, return_exceptions=True)
                        for stream in (writer, outgoing):
                            stream.close()
                            await stream.wait_closed()

                path = self.root / "forward.sock"
                async with await asyncio.start_unix_server(forward, path) as unix:
                    url = self.viewer.publish("ombp", 2, path)
                    page, token = url.split("#")
                    session, ws = await self._connect(display_id=page.rsplit("/", 1)[1],
                                                      protocols=("binary", f"ombp.{token}"))
                    try:
                        self.assertEqual(await ws.receive_bytes(), BANNER)
                        await ws.send_bytes(b"RFB client input")
                        self.assertEqual(await ws.receive_bytes(), b"RFB client input")
                        self.assertEqual(len(connections), 1)
                        self.assertEqual(connections[0][0], "127.0.0.1")
                    finally:
                        await ws.close()
                        await session.close()
        self.run_async(exchange())

    def test_good_credential_proxies_only_its_display_and_negotiates_only_binary(self):
        async def exchange():
            session, ws = await self._connect()
            try:
                self.assertEqual(ws.protocol, "binary")
                self.assertEqual(ws._response.headers.get("Sec-WebSocket-Protocol"), "binary")
                banner = await ws.receive_bytes()
                await ws.send_bytes(b"\x00client-bytes\xff")
                echoed = await ws.receive_bytes()
                return banner, echoed
            finally:
                await ws.close()
                await session.close()
        banner, echoed = self.run_async(exchange())
        self.assertEqual(banner, BANNER)
        self.assertEqual(echoed, b"\x00client-bytes\xff")
        self.assertEqual(len(self.stub.connections), 1)
        self.assertEqual(self.other.connections, [])

    def test_bad_origin_host_or_credential_cannot_upgrade(self):
        browser_url = self.viewer.publish("browser", 1, self.other.path)
        browser_page, browser_token = browser_url.split("#")
        cases = {
            "cross origin": {"origin": "http://evil.example"},
            "control-like origin": {"origin": f"http://127.0.0.1:{self.viewer.port + 1}"},
            "no origin": {"origin": ""},
            "rebinding host": {"host": f"evil.example:{self.viewer.port}"},
            "wrong token": {"protocols": ("binary", "ombp." + "A" * 43)},
            "other display token": {"protocols": ("binary", f"ombp.{browser_token}")},
            "token without binary": {"protocols": (f"ombp.{self.token}",)},
            "binary without token": {"protocols": ("binary",)},
            "two tokens": {"protocols": ("binary", f"ombp.{self.token}", "ombp.other")},
            "unknown display": {"display_id": "0" * 16},
        }
        for name, kwargs in cases.items():
            with self.subTest(name):
                self.assertEqual(self.handshake_status(**kwargs), 403)
        self.assertEqual(self.stub.connections, [])
        self.assertEqual(self.other.connections, [])
        # The browser display's own credential opens only the browser display.
        self.assertEqual(self.handshake_status(display_id=browser_page.rsplit("/", 1)[1],
                                               protocols=("binary", f"ombp.{browser_token}")), 101)
        self.assertEqual(self.stub.connections, [])

    def test_viewer_credential_cannot_use_the_control_api(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        policy = Policy(Path(temp.name) / "state")
        runtime = Runtime(policy)
        self.addCleanup(runtime.close)
        control = Server(policy, runtime)
        thread = threading.Thread(target=control.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(control.server_close)
        self.addCleanup(control.shutdown)
        self.assertNotEqual(control.origin, self.viewer.origin)
        before = json.dumps(policy.snapshot(), sort_keys=True)

        def call(method, path, headers, body=None):
            connection = http.client.HTTPConnection("127.0.0.1", control.server_port, timeout=10)
            self.addCleanup(connection.close)
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            return response.status, response.read()

        for headers in ({"Authorization": f"Bearer {self.token}"},
                        {"Authorization": f"Bearer {self.token}", "Origin": self.viewer.origin},
                        # Even the real control token is refused from the viewer's origin.
                        {"Authorization": f"Bearer {control.token}", "Origin": self.viewer.origin}):
            status, body = call("GET", "/api/status", headers)
            self.assertEqual(status, 403)
            self.assertNotIn(b"policy", body)
            changed = {**policy.snapshot(), "internet": not policy.snapshot()["internet"]}
            status, _ = call("POST", "/api/policy", {**headers, "Content-Type": "application/json"},
                             json.dumps(changed))
            self.assertEqual(status, 403)
        self.assertEqual(json.dumps(policy.snapshot(), sort_keys=True), before)
        # The control token is no viewer credential either, and the viewer has no control routes.
        self.assertEqual(self.handshake_status(protocols=("binary", f"ombp.{control.token}")), 403)
        for path in ("/api/status", "/api/policy"):
            self.assertEqual(self.http(path, {"Authorization": f"Bearer {control.token}"})[0], 404)

    def test_retire_revokes_credential_and_disconnects_live_viewers(self):
        async def scenario():
            session, ws = await self._connect()
            try:
                self.assertEqual(await ws.receive_bytes(), BANNER)
                self.viewer.retire("ombp", generation=2)  # stale generation: nothing happens
                await ws.send_bytes(b"still")
                self.assertEqual(await ws.receive_bytes(), b"still")
                self.viewer.retire("ombp", generation=1)
                message = await ws.receive()
                return message.type
            finally:
                await ws.close()
                await session.close()
        self.assertIn(self.run_async(scenario()), (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                                                   aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR))
        self.assertEqual(self.viewer.desktops(), [])
        self.assertEqual(self.handshake_status(), 403)
        self.assertEqual(self.http(f"/view/{self.display_id}")[0], 410)

    def test_new_generation_replaces_credential(self):
        url = self.viewer.publish("ombp", 2, self.stub.path)
        self.assertNotEqual(url, self.url)
        self.assertEqual(self.viewer.desktops(), [{"kind": "ombp", "url": url}])
        self.assertEqual(self.handshake_status(), 403)
        page, token = url.split("#")
        self.assertEqual(self.handshake_status(display_id=page.rsplit("/", 1)[1],
                                               protocols=("binary", f"ombp.{token}")), 101)
        with self.assertRaises(ValueError):
            self.viewer.publish("host", 1, self.stub.path)

    def test_pages_and_assets_are_restricted_and_carry_csp(self):
        status, headers, body = self.http(f"/view/{self.display_id}")
        self.assertEqual(status, 200)
        self.assertNotIn(self.token.encode(), body)
        csp = headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn(f"connect-src ws://127.0.0.1:{self.viewer.port}", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        status, headers, _ = self.http("/novnc/core/rfb.js")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/javascript"))
        self.assertEqual(self.http("/novnc/vendor/pako/x.js")[0], 200)
        self.assertEqual(self.http("/viewer.js")[0], 200)
        for path in ("/novnc/app/ui.js", "/novnc/vnc.html", "/novnc/core/../../outside.js",
                     "/novnc/core/%2e%2e/%2e%2e/outside.js", "/api/status"):
            with self.subTest(path):
                self.assertEqual(self.http(path)[0], 404)
        self.assertEqual(self.http(f"/view/{self.display_id}", {"Host": f"localhost:{self.viewer.port}"})[0], 403)

    def test_credentials_never_reach_logs(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
        handler = Capture(level=logging.DEBUG)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, previous)
        self.assertEqual(self.handshake_status(), 101)
        self.assertEqual(self.handshake_status(origin="http://evil.example"), 403)
        self.assertEqual(self.handshake_status(protocols=("ombp." + self.token, "other")), 403)
        self.http(f"/view/{self.display_id}")
        self.assertFalse([record for record in records if self.token in record])


@unittest.skipIf(aiohttp is None or not os.environ.get("START_APP_NOVNC"), "needs the pinned noVNC tree (START_APP_NOVNC)")
class PinnedNoVncTests(unittest.TestCase):
    def test_every_module_rfb_imports_is_served(self):
        import re
        from viewer import ViewerServer
        viewer = ViewerServer(os.environ["START_APP_NOVNC"]).start()
        self.addCleanup(viewer.close)
        pending, seen = ["/novnc/core/rfb.js"], set()
        while pending:
            path = pending.pop()
            if path in seen:
                continue
            seen.add(path)
            connection = http.client.HTTPConnection("127.0.0.1", viewer.port, timeout=10)
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read().decode()
            connection.close()
            self.assertEqual(response.status, 200, path)
            self.assertTrue(response.getheader("Content-Type").startswith("text/javascript"), path)
            for target in re.findall(r"""^\s*(?:import|export)\b[^'"]*?from\s+['"]([^'"]+)['"]""", body, re.M):
                self.assertTrue(target.startswith("."), (path, target))
                pending.append(os.path.normpath(os.path.join(os.path.dirname(path), target)))
        self.assertGreater(len(seen), 20)
        # The viewer script imports the same entry point the pinned package ships.
        self.assertIn('import RFB from "/novnc/core/rfb.js";', Path(__file__).with_name("viewer.js").read_text())


if __name__ == "__main__":
    unittest.main()
