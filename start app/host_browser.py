"""Open launcher pages (control UI, isolated display viewers) in the user's browser.

On macOS this is always an installed Chromium-family browser, Google Chrome first, never the system default
browser: a missing browser is an actionable error, not a silent fallback to Safari. Linux keeps webbrowser.open.
"""
import os
from pathlib import Path
import subprocess
import sys
import webbrowser

# (bundle, executable inside Contents/MacOS), in preference order; the same bundles bridge/omp-browser-service.mjs
# discovers for native OMBP browser automation.
DARWIN_BROWSERS = (("Google Chrome.app", "Google Chrome"), ("Chromium.app", "Chromium"),
                   ("Microsoft Edge.app", "Microsoft Edge"), ("Brave Browser.app", "Brave Browser"))
OPEN = "/usr/bin/open"


class BrowserUnavailable(RuntimeError):
    """No supported browser is installed to open a launcher page."""


def darwin_browser(home=None, roots=None):
    """The first installed bundle: each browser in /Applications, then ~/Applications."""
    home = Path.home() if home is None else Path(home)
    roots = (Path("/Applications"), home / "Applications") if roots is None else tuple(map(Path, roots))
    for bundle, executable in DARWIN_BROWSERS:
        for root in roots:
            path = root / bundle
            program = path / "Contents/MacOS" / executable
            if path.is_dir() and program.is_file() and os.access(program, os.X_OK):
                return path
    return None


def open_url(url, platform=sys.platform, home=None, roots=None, run=subprocess.run):
    """Open `url`; on macOS in an explicit Chromium-family bundle, raising BrowserUnavailable if there is none."""
    if platform != "darwin":
        webbrowser.open(url)
        return
    bundle = darwin_browser(home, roots)
    if bundle is None:
        raise BrowserUnavailable(
            "Google Chrome (or Chromium, Microsoft Edge or Brave Browser) is required to open launcher pages on "
            "macOS; install it in /Applications or ~/Applications and open the printed launcher URL in it")
    try:
        result = run([OPEN, "-a", str(bundle), url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, timeout=30)
    except subprocess.TimeoutExpired as error:
        raise BrowserUnavailable(f"{bundle.name} did not accept the page within 30 seconds") from error
    if result.returncode:
        # LaunchServices diagnostics can quote the credential-bearing URL: never copy them into launch.log.
        raise BrowserUnavailable(f"Could not open {bundle.name} (LaunchServices exit {result.returncode}); "
                                 "open the launcher URL in that browser manually")
