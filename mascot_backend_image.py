"""mascot_backend_image.py
==========================

Real inline pixel-image rendering for supporting terminals, used by the CYPHEX
CLI's pixel-art robot mascot.

Implements two terminal graphics protocols so the mascot can be drawn as an
actual raster image (not ASCII/ANSI block art) when the host terminal
supports it:

* **Kitty graphics protocol** -- the APC escape sequence
  ``ESC _G <control-data> ; <base64-PNG> ESC \\``. Payloads whose base64
  encoding exceeds 4096 bytes are split across multiple chunks, each chunk
  carrying ``m=1`` ("more data follows") except the final chunk, which
  carries ``m=0``.
* **iTerm2 inline image protocol** (also implemented by WezTerm) -- the OSC
  escape sequence
  ``ESC ]1337;File=inline=1;width=<cols>;height=<rows>;preserveAspectRatio=1:<base64-PNG> BEL``.
  iTerm2 accepts either BEL (``0x07``) or ST (``ESC \\``) as the terminator;
  this module prefers BEL but can emit ST on request.

Design notes
------------
* Callers pass an already-loaded ``PIL.Image.Image`` -- nothing here re-reads
  from disk, so an animation loop can decode each mascot frame once and then
  call ``kitty_render_frame`` / ``iterm_render_frame`` on it repeatedly.
* Kitty has a real image-id concept, so redrawing a mascot at the same
  on-screen spot is done by (1) deleting the previous image transmitted
  under a fixed id and (2) transmitting+placing the new frame under that
  *same* id. This is done unconditionally on every call so long-running
  animation loops never leak image ids in the terminal's image table.
* iTerm2's protocol has no id/delete concept -- there, "redraw in place" is
  achieved the conventional way: the caller moves the cursor back up to the
  top-left corner of the previous frame (via ``cursor_up``) before printing
  the next one, so the new image simply overwrites the old cells. The
  ``RowTracker`` helper (or the standalone ``compute_rows`` function) tells
  the caller exactly how many rows the previous frame occupied, so it never
  has to guess.
"""

from __future__ import annotations

import base64
import io
import os
from dataclasses import dataclass, field

from PIL import Image

__all__ = [
    "kitty_available",
    "iterm_available",
    "kitty_render_frame",
    "iterm_render_frame",
    "cursor_up",
    "compute_rows",
    "RowTracker",
    "DEFAULT_KITTY_IMAGE_ID",
    "KITTY_APC_START",
    "KITTY_APC_END",
    "ITERM_OSC_PREFIX",
]

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

ESC = b"\x1b"

# Kitty graphics protocol: an APC (Application Program Command) sequence.
KITTY_APC_START = ESC + b"_G"      # ESC _ G  -- begins every kitty graphics command
KITTY_APC_END = ESC + b"\\"        # ESC \    -- ST, terminates the APC sequence
KITTY_CHUNK_SIZE = 4096            # max base64 bytes allowed per chunk (protocol limit)

# A fixed default image id used to identify "the mascot" in kitty's image
# table across repeated calls, so each new frame overwrites the last rather
# than accumulating. Callers running multiple simultaneous mascots can pass
# their own id per instance.
DEFAULT_KITTY_IMAGE_ID = 900001

# iTerm2 / WezTerm inline image protocol: an OSC 1337 File= sequence.
ITERM_OSC_PREFIX = ESC + b"]1337;File="
BEL = b"\x07"                      # preferred terminator
ST = ESC + b"\\"                   # alternate terminator (also accepted)

# Standard monospace terminal cell aspect assumption: a character cell is
# roughly twice as tall (in pixels) as it is wide. So the pixel-height
# available across N rows equals the pixel-width available across 2*N
# columns. Converting an image's own aspect ratio into a row count for a
# target column count therefore divides by 2.
_CELL_HEIGHT_TO_WIDTH_RATIO = 2.0


# ---------------------------------------------------------------------------
# Terminal capability detection
# ---------------------------------------------------------------------------

def kitty_available() -> bool:
    """Best-effort detection of a Kitty-graphics-protocol-capable terminal.

    Checks the environment only (no terminal query/handshake): TERM
    containing 'kitty', or KITTY_WINDOW_ID being set (kitty always exports
    this for its own windows).
    """
    term = os.environ.get("TERM", "")
    if "kitty" in term.lower():
        return True
    return bool(os.environ.get("KITTY_WINDOW_ID"))


def iterm_available() -> bool:
    """Best-effort detection of an iTerm2-inline-image-capable terminal.

    True for iTerm2 itself (TERM_PROGRAM == 'iTerm.app') or WezTerm, which
    also implements the iTerm2 inline image protocol.
    """
    if os.environ.get("TERM_PROGRAM") == "iTerm.app":
        return True
    return "WEZTERM_EXECUTABLE" in os.environ


# ---------------------------------------------------------------------------
# Shared sizing helper
# ---------------------------------------------------------------------------

def compute_rows(img: Image.Image, target_cols: int) -> int:
    """Compute how many terminal rows an image needs to fill ``target_cols``
    columns while preserving its own pixel aspect ratio, under the standard
    cell-aspect assumption that a cell is twice as tall as it is wide.

    rows = target_cols * (img_height / img_width) / 2
    """
    width, height = img.size
    if width <= 0 or height <= 0 or target_cols <= 0:
        return 1
    aspect = height / width
    rows = round(target_cols * aspect / _CELL_HEIGHT_TO_WIDTH_RATIO)
    return max(1, rows)


@dataclass
class RowTracker:
    """Remembers how many terminal rows the most recently rendered frame for
    one mascot instance occupied, so a redraw-in-place animation loop knows
    exactly how far to ``cursor_up()`` before printing the next frame
    without having to recompute or guess.

    Usage::

        tracker = RowTracker()
        frame = kitty_render_frame(img, target_cols=28)
        tracker.note(img, target_cols=28)
        ...
        sys.stdout.buffer.write(cursor_up(tracker.last_rows))
        sys.stdout.buffer.write(next_frame_bytes)
    """

    last_rows: int = field(default=0)

    def note(self, img: Image.Image, target_cols: int) -> int:
        """Record (and return) the row height that ``img`` at ``target_cols``
        occupies. Call this alongside each render_frame call."""
        self.last_rows = compute_rows(img, target_cols)
        return self.last_rows


# ---------------------------------------------------------------------------
# Shared PNG encoding helper
# ---------------------------------------------------------------------------

def _png_bytes(img: Image.Image) -> bytes:
    """Encode a PIL image as PNG bytes, preserving alpha transparency."""
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Kitty graphics protocol
# ---------------------------------------------------------------------------

def _kitty_delete_command(image_id: int) -> bytes:
    """Delete (and free) any image previously transmitted under ``image_id``.

    d=I -- delete placements *and* free the stored image data for this id.
    Sent before every fresh transmit so repeated animation frames reuse one
    id instead of leaking a new stored image into kitty's image table on
    every call.
    """
    ctrl = f"a=d,d=I,i={image_id}"
    return KITTY_APC_START + ctrl.encode("ascii") + KITTY_APC_END


def kitty_render_frame(
    img: Image.Image,
    target_cols: int,
    image_id: int = DEFAULT_KITTY_IMAGE_ID,
) -> bytes:
    """Build the exact bytes to print one mascot frame via the Kitty graphics
    protocol, sized to ``target_cols`` terminal columns.

    The returned bytes first delete any prior image stored under
    ``image_id`` (avoiding id leaks across many animation frames), then
    transmit-and-display (``a=T``) the new PNG under that same id, chunked
    per the protocol's 4096-base64-byte-per-chunk limit (``m=1`` on every
    chunk but the last, ``m=0`` on the last).

    Because the display action is bound to a fixed image id and reissued at
    the caller's current cursor position, calling this repeatedly at the
    same cursor position replaces the prior frame instead of stacking new
    images.
    """
    rows = compute_rows(img, target_cols)
    png = _png_bytes(img)
    b64 = base64.b64encode(png)

    chunks = [
        b64[i : i + KITTY_CHUNK_SIZE] for i in range(0, len(b64), KITTY_CHUNK_SIZE)
    ] or [b""]
    last_index = len(chunks) - 1

    out = bytearray()
    out += _kitty_delete_command(image_id)

    for index, chunk in enumerate(chunks):
        more = 0 if index == last_index else 1
        if index == 0:
            # a=T   : transmit the payload AND display it at the cursor in one step
            # f=100 : payload format is PNG (kitty decodes it itself)
            # t=d   : transmission medium is "direct" (data is inline in the payload)
            # i=    : fixed image id, reused every call for in-place redraw
            # c=/r= : display size in terminal columns/rows
            # m=    : more chunks follow (1) or this is the last chunk (0)
            ctrl = f"a=T,f=100,t=d,i={image_id},c={target_cols},r={rows},m={more}"
        else:
            # Continuation chunks carry only the m= key plus their payload.
            ctrl = f"m={more}"
        out += KITTY_APC_START + ctrl.encode("ascii") + b";" + chunk + KITTY_APC_END

    return bytes(out)


# ---------------------------------------------------------------------------
# iTerm2 / WezTerm inline image protocol
# ---------------------------------------------------------------------------

def iterm_render_frame(
    img: Image.Image,
    target_cols: int,
    terminator: str = "bel",
) -> bytes:
    """Build the exact bytes to print one mascot frame via the iTerm2 inline
    image protocol (also implemented by WezTerm), sized to ``target_cols``
    terminal columns.

    ``terminator`` selects the sequence's closing byte(s): ``"bel"`` (the
    default, and iTerm2's preferred terminator, ``0x07``) or ``"st"`` (the
    ANSI string terminator ``ESC \\``) -- both are accepted by real iTerm2 /
    WezTerm builds.

    iTerm2 has no image-id/delete concept, so "replace instead of stack" for
    this protocol is achieved by the caller's redraw loop: move the cursor
    back to the top-left of the previous frame with ``cursor_up`` (using
    ``compute_rows``/``RowTracker`` to know how far) before printing the next
    one, so the new image overwrites the same cells in place.
    """
    if terminator not in ("bel", "st"):
        raise ValueError("terminator must be 'bel' or 'st'")

    rows = compute_rows(img, target_cols)
    png = _png_bytes(img)
    b64 = base64.b64encode(png)

    args = (
        f"inline=1;width={target_cols};height={rows};"
        f"preserveAspectRatio=1;size={len(png)}"
    )
    term_bytes = BEL if terminator == "bel" else ST

    return ITERM_OSC_PREFIX + args.encode("ascii") + b":" + b64 + term_bytes


# ---------------------------------------------------------------------------
# Cursor control
# ---------------------------------------------------------------------------

def cursor_up(n_rows: int) -> bytes:
    """Standard CSI cursor-up sequence: ``ESC [ {n} A``.

    Used by a redraw-in-place animation loop to return the cursor to the
    top-left of the previously printed frame before printing the next one.
    ``n_rows`` should come from ``compute_rows`` / ``RowTracker.last_rows``
    for whatever frame was rendered last -- callers should not have to guess
    it. A non-positive ``n_rows`` yields an empty (no-op) sequence.
    """
    if n_rows <= 0:
        return b""
    return f"{n_rows}A".encode("ascii").join([ESC + b"[", b""])


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import re
    import sys

    MASCOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "mascot")
    TARGET_COLS = 28

    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        status = "PASS" if condition else "FAIL"
        print(f"[{status}] {label}")
        if not condition:
            failures.append(label)

    def extract_kitty_b64(data: bytes) -> bytes:
        """Pull the concatenated base64 payload back out of a
        kitty_render_frame() result (skipping the leading delete command,
        which carries no payload)."""
        pieces = re.findall(rb"\x1b_G(.*?)\x1b\\", data, re.DOTALL)
        payload = bytearray()
        for piece in pieces:
            if b";" not in piece:
                # e.g. the "a=d,d=I,i=..." delete command -- no payload
                continue
            _ctrl, _sep, chunk_payload = piece.partition(b";")
            payload += chunk_payload
        return bytes(payload)

    def extract_iterm_b64(data: bytes) -> bytes:
        assert data.startswith(ITERM_OSC_PREFIX)
        body = data[len(ITERM_OSC_PREFIX):]
        if body.endswith(BEL):
            body = body[: -len(BEL)]
        elif body.endswith(ST):
            body = body[: -len(ST)]
        _args, _sep, b64 = body.partition(b":")
        return b64

    print("=== mascot_backend_image.py self-test ===")
    print(f"TERM={os.environ.get('TERM')!r} KITTY_WINDOW_ID={os.environ.get('KITTY_WINDOW_ID')!r} "
          f"TERM_PROGRAM={os.environ.get('TERM_PROGRAM')!r} WEZTERM_EXECUTABLE="
          f"{os.environ.get('WEZTERM_EXECUTABLE')!r}")
    print(f"kitty_available()  -> {kitty_available()}")
    print(f"iterm_available()  -> {iterm_available()}")
    print()

    for name in ("idle.png", "scan.png"):
        path = os.path.join(MASCOT_DIR, name)
        print(f"--- {name} ---")
        img = Image.open(path)
        img.load()
        if img.mode != "RGBA":
            img = img.convert("RGBA")
        check(f"{name}: source image loaded as RGBA", img.mode == "RGBA")

        rows = compute_rows(img, TARGET_COLS)
        print(f"    size={img.size} target_cols={TARGET_COLS} -> computed rows={rows}")
        check(f"{name}: compute_rows returns a positive int", isinstance(rows, int) and rows > 0)

        # --- Kitty ---
        kitty_bytes = kitty_render_frame(img, TARGET_COLS)
        check(f"{name}: kitty frame starts with APC prefix (ESC _G)",
              kitty_bytes.startswith(KITTY_APC_START))
        check(f"{name}: kitty frame contains delete-then-transmit (image id reused, no leak)",
              f"a=d,d=I,i={DEFAULT_KITTY_IMAGE_ID}".encode() in kitty_bytes
              and f"i={DEFAULT_KITTY_IMAGE_ID}".encode() in kitty_bytes)
        kitty_payload_b64 = extract_kitty_b64(kitty_bytes)
        try:
            kitty_png = base64.b64decode(kitty_payload_b64, validate=True)
            kitty_roundtrip = Image.open(io.BytesIO(kitty_png))
            kitty_roundtrip.load()
            kitty_ok = kitty_roundtrip.format == "PNG"
        except Exception as exc:  # noqa: BLE001 - want to report any failure as FAIL
            kitty_ok = False
            print(f"    kitty payload decode error: {exc!r}")
        check(f"{name}: kitty payload is valid base64 decoding to a real PNG", kitty_ok)
        n_chunks = kitty_bytes.count(b"a=T") + kitty_bytes.count(b"m=0;") + kitty_bytes.count(b"m=1;")
        print(f"    kitty frame: {len(kitty_bytes)} bytes total, "
              f"base64 payload {len(kitty_payload_b64)} bytes "
              f"({'multi-chunk' if len(kitty_payload_b64) > KITTY_CHUNK_SIZE else 'single chunk'})")

        # --- iTerm2 ---
        iterm_bytes = iterm_render_frame(img, TARGET_COLS)
        check(f"{name}: iterm frame starts with OSC 1337 File= prefix",
              iterm_bytes.startswith(ITERM_OSC_PREFIX))
        check(f"{name}: iterm frame terminated with BEL by default",
              iterm_bytes.endswith(BEL))
        iterm_payload_b64 = extract_iterm_b64(iterm_bytes)
        try:
            iterm_png = base64.b64decode(iterm_payload_b64, validate=True)
            iterm_roundtrip = Image.open(io.BytesIO(iterm_png))
            iterm_roundtrip.load()
            iterm_ok = iterm_roundtrip.format == "PNG"
        except Exception as exc:  # noqa: BLE001
            iterm_ok = False
            print(f"    iterm payload decode error: {exc!r}")
        check(f"{name}: iterm payload is valid base64 decoding to a real PNG", iterm_ok)
        print(f"    iterm frame: {len(iterm_bytes)} bytes total, "
              f"base64 payload {len(iterm_payload_b64)} bytes")

        # --- ST terminator variant ---
        iterm_st_bytes = iterm_render_frame(img, TARGET_COLS, terminator="st")
        check(f"{name}: iterm frame with terminator='st' ends with ESC \\ instead of BEL",
              iterm_st_bytes.endswith(ST) and not iterm_st_bytes.endswith(BEL))

        print()

    # --- cursor_up / RowTracker ---
    check("cursor_up(5) == ESC [ 5 A", cursor_up(5) == b"\x1b[5A")
    check("cursor_up(0) is empty (no-op)", cursor_up(0) == b"")

    tracker = RowTracker()
    idle_img = Image.open(os.path.join(MASCOT_DIR, "idle.png")).convert("RGBA")
    noted = tracker.note(idle_img, TARGET_COLS)
    check("RowTracker.note() matches compute_rows()", noted == compute_rows(idle_img, TARGET_COLS))
    check("RowTracker.last_rows reflects the noted value", tracker.last_rows == noted)

    print()
    if failures:
        print(f"FAIL ({len(failures)} check(s) failed):")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("PASS (all checks passed)")
        sys.exit(0)
