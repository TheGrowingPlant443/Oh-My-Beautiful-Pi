from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
import unittest

from host_browser import BrowserUnavailable, OPEN, open_url


class HostBrowserTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.system = Path(temp.name) / "Applications"
        self.home = Path(temp.name) / "home"
        self.user = self.home / "Applications"
        self.calls = []
        self.code = 0
        # The default browser must never be used on macOS, whatever happens.
        default = patch("webbrowser.open", side_effect=AssertionError("default browser used"))
        self.default = default.start()
        self.addCleanup(default.stop)

    def bundle(self, root, name, executable, mode=0o755):
        program = root / name / "Contents/MacOS" / executable
        program.parent.mkdir(parents=True)
        program.write_text("#!/bin/sh\n")
        program.chmod(mode)
        return root / name

    def fake_run(self, args, **kwargs):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, self.code, b"", b"LSOpenURLsWithRole() failed")

    def open(self, url="http://127.0.0.1:1/#secret"):
        open_url(url, platform="darwin", home=self.home, roots=(self.system, self.user), run=self.fake_run)

    def test_chrome_is_chosen_before_other_chromium_browsers_and_locations(self):
        self.bundle(self.system, "Microsoft Edge.app", "Microsoft Edge")
        chrome = self.bundle(self.user, "Google Chrome.app", "Google Chrome")
        self.open()
        self.assertEqual(self.calls, [[OPEN, "-a", str(chrome), "http://127.0.0.1:1/#secret"]])
        system_chrome = self.bundle(self.system, "Google Chrome.app", "Google Chrome")
        self.open()
        self.assertEqual(self.calls[-1][2], str(system_chrome))
        self.default.assert_not_called()

    def test_unusable_bundle_does_not_shadow_a_working_browser(self):
        self.bundle(self.system, "Google Chrome.app", "Google Chrome", mode=0o644)
        (self.user / "Chromium.app").mkdir(parents=True)  # no executable at all
        brave = self.bundle(self.user, "Brave Browser.app", "Brave Browser")
        self.open()
        self.assertEqual(self.calls[-1][2], str(brave))

    def test_missing_browser_is_an_actionable_error_never_the_default_browser(self):
        with self.assertRaisesRegex(BrowserUnavailable, "Google Chrome .* is required"):
            self.open()
        self.assertEqual(self.calls, [])
        self.default.assert_not_called()

    def test_open_failure_is_reported(self):
        self.bundle(self.system, "Google Chrome.app", "Google Chrome")
        self.code = 1
        with self.assertRaisesRegex(BrowserUnavailable, "Could not open Google Chrome.app.*LaunchServices exit 1"):
            self.open()
        self.default.assert_not_called()

    def test_linux_keeps_the_desktop_default_browser(self):
        self.default.side_effect = None
        open_url("http://127.0.0.1:1/", platform="linux", run=self.fake_run)
        self.default.assert_called_once_with("http://127.0.0.1:1/")
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
