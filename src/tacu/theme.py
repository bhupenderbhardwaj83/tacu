"""Small ANSI theme that degrades cleanly when color is unavailable."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass

ANSI_ESCAPE = re.compile(r"\x1b(?:[@-_][0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


@dataclass(frozen=True)
class Palette:
    text: str = "\x1b[38;5;250m"       # soft grey
    muted: str = "\x1b[38;5;245m"
    dim: str = "\x1b[2m"               # visually smaller / de-emphasized
    accent: str = "\x1b[38;5;116m"     # calm cyan
    green: str = "\x1b[38;5;108m"
    yellow: str = "\x1b[38;5;179m"     # identifiers
    blue: str = "\x1b[38;5;111m"       # hidden paths
    red: str = "\x1b[38;5;203m"        # juicy secrets (alias of juicy_secret)
    juicy_secret: str = "\x1b[38;5;203m"  # coral — keys, tokens, assignments
    juicy_auth: str = "\x1b[38;5;210m"    # rose — bearer, jwt, passwords
    juicy_id: str = "\x1b[38;5;216m"      # peach — email, phones, PAN, Aadhaar
    juicy_money: str = "\x1b[38;5;175m"   # orchid — cards, IBAN, UPI
    juicy_net: str = "\x1b[38;5;117m"     # sky — URLs, IPs, hosts
    juicy_signal: str = "\x1b[38;5;180m"  # tan — http/config/injection signals
    # Packet flow: sage source, dusty-rose destination (ports, addresses, names).
    src: str = "\x1b[38;2;142;186;158m"
    dst: str = "\x1b[38;2;198;138;138m"
    violet: str = "\x1b[38;5;146m"
    # Question emphasis — #940a6f family, lightened for dark terminals
    question: str = "\x1b[38;2;196;80;155m"
    panel: str = "\x1b[48;5;235m"
    bold: str = "\x1b[1m"
    reset: str = "\x1b[0m"


PALETTE = Palette()


def color_enabled(stream: object | None = None) -> bool:
    # Resolved per call: a default of sys.stdout would bind the interpreter's
    # original stream at import and ignore any later redirect_stdout.
    target = sys.stdout if stream is None else stream
    return "NO_COLOR" not in os.environ and "TERM" in os.environ and bool(getattr(target, "isatty", lambda: False)())


def paint(text: str, color: str, *, enabled: bool | None = None) -> str:
    if enabled is None:
        enabled = color_enabled()
    return f"{color}{text}{PALETTE.reset}" if enabled else text


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


WORDMARK = "t a c u"
TAGLINE = "Terminal Ally & Companion Unit"

_UNICODE_MARK = ">_  t a c u"
_ASCII_MARK = ">_  t a c u"

# Speech-bubble face: prompt, closed-eye arcs, smile; heart sits above the wordmark.
_UNICODE_ART = (
    "╭──────────────╮        ♥",
    "│  >_          │",
    "│   ⌒     ⌒    │     t a c u",
    "│      ◡       │     Terminal Ally & Companion Unit",
    "╰──────────╮   │",
    "           ╰───╯",
)
_ASCII_ART = (
    "+--------------+        <3",
    "|  >_          |",
    "|   ~     ~    |     t a c u",
    "|      u       |     Terminal Ally & Companion Unit",
    "+----------+   |",
    "           +---+",
)


def unicode_safe(stream: object = sys.stdout) -> bool:
    """True when the terminal can render the box-drawing identity cleanly."""
    encoding = getattr(stream, "encoding", None) or ""
    return "utf" in encoding.lower()


def logo(*, enabled: bool | None = None) -> str:
    """One-line identity for prompts, help headers, and status output."""
    mark = _UNICODE_MARK if unicode_safe() else _ASCII_MARK
    return f"{paint(mark, PALETTE.accent + PALETTE.bold, enabled=enabled)}  {paint(TAGLINE, PALETTE.muted, enabled=enabled)}"


def banner(*, enabled: bool | None = None, subtitle: str | None = None) -> str:
    """Full block identity for first-run, setup, and installer completion."""
    art = _UNICODE_ART if unicode_safe() else _ASCII_ART
    lines = [paint(line.rstrip(), PALETTE.accent + PALETTE.bold, enabled=enabled) for line in art]
    if subtitle:
        lines.append(paint(subtitle, PALETTE.dim, enabled=enabled))
    return "\n".join(lines)
