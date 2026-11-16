import http.client
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch
import tempfile
import threading
import unittest

from app import Server, auto_start, default_source, state_directory
from policy import Policy
from runtime import Runtime
from test_runtime import FakeNix, _until


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.policy = Policy(Path(self.temp.name) / "state")
        self.runtime = Runtime(self.policy)
        offline = self.policy.snapshot()
        offline["internet"] = False
        self.policy.replace(offline)
        self.addCleanup(self.runtime.close)
        self.server = Server(self.policy, self.runtime)
        self.valid_policy = self.policy.snapshot()
        self.valid_policy.update(websites=["https://example.com/api"], internet=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        self.addCleanup(connection.close)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        return response.status, response.read()

    def test_unauthorized_and_cross_origin_cannot_change_permissions(self):
        for headers in ({}, {"Authorization": f"Bearer {self.server.token}", "Origin": "https://evil.example"},
                        {"Authorization": f"Bearer {self.server.token}", "Host": "evil.example"}):
            self.assertEqual(self.request("POST", "/api/policy", json.dumps(self.valid_policy), headers)[0], 403)
            self.assertFalse(self.policy.snapshot()["internet"])

    def test_authenticated_control_applies_validated_policy(self):
        self.assertEqual(self.request("POST", "/api/policy", json.dumps(self.valid_policy),
                                     {"Authorization": f"Bearer {self.server.token}", "Origin": self.server.origin})[0], 200)
        self.assertEqual(self.policy.snapshot()["websites"], ["https://example.com"])
        self.assertTrue(self.policy.snapshot()["internet"])

    def test_copy_again_requires_authentication_explicit_consent_and_idle_runtime(self):
        path = "/api/omp-copy"
        body = json.dumps({"replace_previous": True})
        pending = self.policy.directory / "omp-recopy.json"
        for headers in ({}, {"Authorization": f"Bearer {self.server.token}", "Origin": "https://evil.example"}):
            self.assertEqual(self.request("POST", path, body, headers)[0], 403)
        self.assertFalse(pending.exists())
        headers = {"Authorization": f"Bearer {self.server.token}"}
        for value in ({}, {"replace_previous": False}, {"replace_previous": 1}, {"replace_previous": True, "extra": 1}):
            self.assertEqual(self.request("POST", path, json.dumps(value), headers)[0], 400)
        self.assertFalse(pending.exists())
        self.assertEqual(self.request("POST", path, body, headers)[0], 200)
        first = json.loads(pending.read_text())
        self.assertEqual(set(first), {"replace_previous", "request_id"})
        self.assertIs(first["replace_previous"], True)
        self.assertRegex(first["request_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(self.request("POST", path, body, headers)[0], 200)
        self.assertEqual(json.loads(pending.read_text()), first)
        status = json.loads(self.request("GET", "/api/status", headers=headers)[1])
        self.assertTrue(status["runtime"]["omp_copy_pending"])
        pending.unlink()
        with patch.object(self.runtime, "operation", object()):
            self.assertEqual(self.request("POST", path, body, headers)[0], 400)
        self.assertFalse(pending.exists())
        self.assertEqual(self.request("POST", path, body, headers)[0], 200)
        self.assertNotEqual(json.loads(pending.read_text())["request_id"], first["request_id"])

    def test_private_history_requires_authenticated_same_origin_get(self):
        target = "https://private.example.com"
        self.policy.deny("website", target, "not allowed")
        for headers in ({}, {"Authorization": f"Bearer {self.server.token}", "Origin": "https://evil.example"}):
            status, body = self.request("GET", "/api/status", headers=headers)
            self.assertEqual(status, 403)
            self.assertNotIn(target.encode(), body)
        status, body = self.request("GET", "/api/status", headers={"Authorization": f"Bearer {self.server.token}"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["history"][0]["target"], target)

    def test_malformed_permission_requests_preserve_state(self):
        before = self.policy.snapshot()
        headers = {"Authorization": f"Bearer {self.server.token}"}
        for body in (None, "{", json.dumps({"internet": True})):
            self.assertEqual(self.request("POST", "/api/policy", body, headers)[0], 400)
            self.assertEqual(self.policy.snapshot(), before)

    def test_static_path_traversal_cannot_read_private_policy(self):
        self.policy.replace(self.valid_policy)
        for path in ("/../../policy.json", "/../state/policy.json"):
            status, body = self.request("GET", path)
            self.assertEqual(status, 404)
            self.assertNotIn(b"https://example.com", body)

    def test_catalog_folders_and_history_clear_require_same_origin_authentication(self):
        self.policy.deny("website", "https://denied.example", "not allowed")
        for headers in ({}, {"Authorization": f"Bearer {self.server.token}", "Origin": "https://evil.example"}):
            self.assertEqual(self.request("GET", "/api/catalog", headers=headers)[0], 403)
            self.assertEqual(self.request("GET", "/api/folders?q=x", headers=headers)[0], 403)
            self.assertEqual(self.request("POST", "/api/history/clear", "{}", headers)[0], 403)
        self.assertEqual(self.policy.events()[0]["target"], "https://denied.example")
        headers = {"Authorization": f"Bearer {self.server.token}"}
        self.assertEqual(self.request("GET", "/api/catalog", headers=headers)[0], 200)
        self.assertEqual(self.request("GET", "/api/folders?q=a%2Fb", headers=headers), (200, b"[]"))
        before = self.policy.snapshot()
        self.assertEqual(self.request("POST", "/api/history/clear", "{}", headers)[0], 200)
        self.assertEqual(Policy(self.policy.directory).events(), [])
        self.assertEqual(self.policy.snapshot(), before)

    def test_start_is_accepted_as_an_operation_whose_progress_is_polled(self):
        fake = FakeNix(self, Path(self.temp.name))
        fake.behave("hang")
        headers = {"Authorization": f"Bearer {self.server.token}"}
        launch = json.dumps({"source": str(fake.source), "mode": "normal", "desktop": False, "gpu": "none",
                             "agent": "omp"})
        self.assertEqual(self.request("POST", "/api/start", launch,
                                      {"Authorization": "Bearer wrong", "Origin": self.server.origin})[0], 403)
        self.assertEqual(fake.read("nix-args"), [])
        status, body = self.request("POST", "/api/start", launch, headers)
        self.assertEqual(status, 202)
        operation = json.loads(body)["operation_id"]

        def runtime():
            return json.loads(self.request("GET", "/api/status", headers=headers)[1])["runtime"]
        # The request returned while the build is still running; status reports its progress.
        _until(lambda: runtime()["phase"] == "building")
        self.assertEqual((runtime()["operation_id"], runtime()["running"]), (operation, False))
        status, body = self.request("POST", "/api/start", launch, headers)
        self.assertEqual(status, 400)
        self.assertEqual(self.request("POST", "/api/stop", "{}", headers)[0], 200)
        _until(lambda: runtime()["phase"] == "stopped")
        fake.behave("ok")
        operation = json.loads(self.request("POST", "/api/start", launch, headers)[1])["operation_id"]
        _until(lambda: runtime()["running"])
        self.assertEqual((runtime()["operation_id"], runtime()["backend"]), (operation, "native"))
        _until(lambda: fake.read("launched"))
        self.assertEqual(fake.read("launched"), ["omp"])

    @unittest.skipUnless(sys.platform == "darwin", "Prepare is the macOS VM operation")
    def test_prepare_is_authenticated_empty_body_and_cancellable_operation(self):
        headers = {"Authorization": f"Bearer {self.server.token}"}
        self.assertEqual(self.request("POST", "/api/prepare", "{}")[0], 403)
        self.assertEqual(self.request("POST", "/api/prepare", '{"unknown":true}', headers)[0], 400)
        entered = threading.Event()
        def preparing(children, log):
            entered.set()
            children.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=60)
        with patch.object(self.runtime.isolated, "prepare", preparing):
            status, body = self.request("POST", "/api/prepare", "{}", headers)
            self.assertEqual(status, 202)
            self.assertTrue(entered.wait(5))
            current = self.runtime.status()
            self.assertEqual(current["operation_id"], json.loads(body)["operation_id"])
            self.assertEqual((current["phase"], current["operation"]), ("preparing", "prepare"))
            self.assertEqual(self.request("POST", "/api/stop", "{}", headers)[0], 200)
            _until(lambda: self.runtime.status()["phase"] == "stopped")
            self.assertFalse(self.runtime.status()["running"])

    def test_automatic_start_failure_reaches_status(self):
        auto_start(self.runtime, {"source": str(Path(self.temp.name) / "missing"), "mode": "container",
                                  "desktop": True, "gpu": "none", "agent": "omp"})
        status = self.runtime.status()
        self.assertEqual(status["phase"], "failed")
        self.assertTrue(status["error"].startswith("Automatic start failed: "), status["error"])

    def test_log_follows_the_last_operation_incrementally_and_requires_authentication(self):
        headers = {"Authorization": f"Bearer {self.server.token}"}

        def log(query=""):
            status, body = self.request("GET", f"/api/log{query}", headers=headers)
            self.assertEqual(status, 200)
            return json.loads(body)
        path = self.policy.directory / "launch.log"
        path.write_bytes(b"previous launcher session\n")
        self.assertEqual(log(), {"start": None, "end": 26, "text": "", "truncated": False})
        self.assertIsNone(self.runtime.status()["log_start"])
        fake = FakeNix(self, Path(self.temp.name))
        fake.behave("fail")
        self.runtime.start(str(fake.source), "normal", False, "none", "omp")
        _until(lambda: self.runtime.status()["phase"] == "failed")
        status = self.runtime.status()
        # A failed launch's log stays viewable: only this operation's bytes, never the earlier session's.
        self.assertEqual(status["log_start"], 26)
        self.assertIsInstance(status["operation_started"], float)
        first = log("?after=0")
        self.assertEqual(first["start"], 26)
        self.assertRegex(first["text"], r"\A==> Launch started \S+ \(operation [0-9a-f]{32}\)\n")
        self.assertIn("==> Building OMBP (omp)\n", first["text"])
        self.assertIn("build failed", first["text"])
        self.assertTrue(first["text"].endswith(f"==> Stopping\n==> Launch failed: {status['error']}\n"), first["text"])
        self.assertEqual(first["end"], path.stat().st_size)
        with path.open("ab") as output:
            output.write("more ✓".encode() + "✓".encode()[:2])
        # The incomplete trailing UTF-8 sequence is held back until its last byte arrives.
        self.assertEqual(log(f"?after={first['end']}"),
                         {"start": 26, "end": first["end"] + 8, "text": "more ✓", "truncated": False})
        with path.open("ab") as output:
            output.write("✓".encode()[2:] + b"x" * (300 << 10))
        tail = log(f"?after={first['end'] + 8}")
        self.assertEqual((tail["truncated"], len(tail["text"]), tail["end"]), (True, 256 << 10, path.stat().st_size))
        for query in ("?after=-1", "?after=1.5", "?after=x", "?after=%C2%B2"):
            self.assertEqual(self.request("GET", f"/api/log{query}", headers=headers)[0], 400)
        for unauthorized in ({}, {**headers, "Origin": "https://evil.example"}, {**headers, "Host": "evil.example"}):
            status, body = self.request("GET", "/api/log", headers=unauthorized)
            self.assertEqual(status, 403)
            self.assertNotIn(b"build failed", body)


class DefaultsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.old = self.home / ".local/state/ombp-start"
        self.new = self.home / "Library/Application Support/ombp-start"

    def test_macos_state_keeps_existing_default_and_refuses_ambiguity(self):
        def default(platform="darwin", environ=None):
            return state_directory(None, platform, self.home, environ or {})
        self.assertEqual(default(), self.new)
        self.assertEqual(default("linux"), self.old)
        self.assertEqual(default("linux", {"XDG_STATE_HOME": str(self.home / "xdg")}), self.home / "xdg/ombp-start")
        self.old.mkdir(parents=True)
        self.assertEqual(default(), self.old)
        self.new.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "--state-dir"):
            default()
        self.assertEqual(default("linux"), self.old)
        # Explicit state is always respected, and nothing was merged or moved.
        explicit = self.home / "chosen"
        self.assertEqual(state_directory(explicit, "darwin", self.home, {}), explicit)
        self.assertTrue(self.old.is_dir() and self.new.is_dir())
        self.assertEqual(os.listdir(self.old), [])

    def test_source_precedence(self):
        checkout = self.home / "checkout"
        launcher = checkout / "start app"
        launcher.mkdir(parents=True)
        (launcher / "flake.nix").write_text("{}")
        saved = {"source": "/saved/checkout"}
        self.assertEqual(default_source(Path("/explicit"), saved, launcher), "/explicit")
        self.assertEqual(default_source(None, saved, launcher), "/saved/checkout")
        # From start app the checkout is its parent, never the launcher's own flake.
        self.assertEqual(default_source(None, None, launcher), "")
        (checkout / "flake.nix").write_text("{}")
        self.assertEqual(default_source(None, None, launcher), str(checkout))
        self.assertEqual(default_source(None, None, checkout), str(checkout))
        # Finder starts in /, which is no checkout: the user chooses one.
        self.assertEqual(default_source(None, None, self.home), "")


if __name__ == "__main__":
    unittest.main()
