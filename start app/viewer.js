// Isolated display viewer. Keyboard, pointer and resize only: no clipboard bridge (clipboard events are never
// handled and clipboardPasteFrom is never called), no file transfer, power or navigation actions.
import RFB from "/novnc/core/rfb.js";

const token = location.hash.slice(1);
// The display credential must not stay in the address bar, history or a bookmark.
history.replaceState(null, "", location.pathname);
const displayId = location.pathname.split("/").pop();
const screen = document.getElementById("screen");
const status = document.getElementById("status");
// How long to wait for the server's first ExtendedDesktopSize rectangle before falling back to local scaling.
const RESIZE_NEGOTIATION_MS = 3000;

function show(text, retry = false) {
  status.replaceChildren(text);
  if (retry) {
    const button = document.createElement("button");
    button.textContent = "Reconnect";
    button.addEventListener("click", connect);
    status.append(" ", button);
  }
  status.hidden = !text;
}

// Remote resize needs the server's ExtendedDesktopSize extension. noVNC 1.7.0 (the pinned version) records that
// negotiation only in RFB._supportsSetDesktopSize and silently ignores resizeSession without it, so read that
// pinned field after giving the first framebuffer updates time to arrive. A late negotiation removes local scaling.
function negotiateResize(rfb) {
  if (typeof rfb._supportsSetDesktopSize !== "boolean") {
    current = null;
    rfb.disconnect();
    show("Incompatible noVNC assets: this launcher requires the pinned noVNC 1.7.0 resize interface.");
    return;
  }
  const started = performance.now();
  const check = () => {
    if (rfb !== current) return;
    if (rfb._supportsSetDesktopSize) {
      rfb.scaleViewport = false;
      return;
    }
    if (performance.now() - started >= RESIZE_NEGOTIATION_MS) {
      rfb.scaleViewport = true;
    }
    setTimeout(check, 250);
  };
  check();
}

let current = null;

function connect() {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    show("This viewer link has no display credential. Open the display again from the launcher.");
    return;
  }
  show("Connecting…");
  const rfb = current = new RFB(screen, `ws://${location.host}/ws/${displayId}`,
    {shared: true, wsProtocols: ["binary", `ombp.${token}`]});
  rfb.resizeSession = true;
  rfb.scaleViewport = false;
  rfb.clipViewport = false;
  rfb.focusOnClick = true;
  rfb.addEventListener("connect", () => {
    show("");
    rfb.focus();
    negotiateResize(rfb);
  });
  rfb.addEventListener("disconnect", event => {
    if (rfb !== current) return;
    current = null;
    show(event.detail.clean ? "Display disconnected." : "Display connection lost.", true);
  });
  rfb.addEventListener("securityfailure", () => show("The display refused this viewer.", true));
}

connect();
