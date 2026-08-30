"""Pause long TTY output after a page, then reveal more with Enter / Space.

This is a more-style pager: lines stay in Terminal scrollback. It is not less(1).
Pipes, captured stdout, and TACU_NO_PAGER=1 print everything at once.
"""

from __future__ import annotations

import builtins
import os
import sys
from contextlib import contextmanager
from typing import Callable, Iterator, TextIO

from .theme import PALETTE, paint

PAGE_SIZE = 20
_MORE = "── more ── Enter: line  Space: page  q: quit"


def configured_page_size() -> int:
    raw = os.environ.get("TACU_PAGE_SIZE", "").strip()
    if raw.isdigit():
        return max(1, int(raw))
    return PAGE_SIZE


def pager_enabled(*, stdout: object | None = None, stdin: object | None = None) -> bool:
    """True only when an interactive user would actually see paging."""

    flag = os.environ.get("TACU_NO_PAGER", "").strip().casefold()
    if flag in {"1", "true", "yes", "on"}:
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    out = sys.stdout if stdout is None else stdout
    inn = sys.stdin if stdin is None else stdin
    if not callable(getattr(out, "isatty", None)) or not out.isatty():
        return False
    if not callable(getattr(inn, "isatty", None)) or not inn.isatty():
        return False
    return True


def default_read_key(stdin: TextIO | None = None) -> str:
    """Read one key without waiting for Enter (Space must be distinguishable)."""

    stream = sys.stdin if stdin is None else stdin
    if os.name == "nt":
        import msvcrt

        char = msvcrt.getwch()
        if char in {"\x00", "\xe0"}:
            msvcrt.getwch()
            return ""
        return char
    try:
        import termios
        import tty
    except ImportError:
        return stream.readline()[:1] or ""
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return stream.readline()[:1] or ""
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        char = stream.read(1)
        if char == "\x1b":
            _drain_escape(stream)
        return char
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _drain_escape(stream: TextIO) -> None:
    try:
        import select

        fd = stream.fileno()
        while select.select([fd], [], [], 0.04)[0]:
            nxt = stream.read(1)
            if not nxt or nxt.isalpha() or nxt == "~":
                break
    except (AttributeError, OSError, ValueError, ImportError):
        return


class LinePager:
    """Wrap a text stream and gate complete lines after ``page_size`` of them."""

    def __init__(
        self,
        stream: TextIO,
        *,
        page_size: int = PAGE_SIZE,
        read_key: Callable[[], str] | None = None,
        stdin: TextIO | None = None,
        prompt_stream: TextIO | None = None,
    ) -> None:
        self._stream = stream
        self._stdin = sys.stdin if stdin is None else stdin
        self._prompt = sys.stderr if prompt_stream is None else prompt_stream
        self._page_size = max(1, page_size)
        self._budget = self._page_size
        self._buf = ""
        self._stopped = False
        self._read_key = read_key or (lambda: default_read_key(self._stdin))

    def isatty(self) -> bool:
        return bool(getattr(self._stream, "isatty", lambda: False)())

    def writable(self) -> bool:
        return True

    def write(self, data: str) -> int:
        text = data if isinstance(data, str) else str(data)
        if not text:
            return 0
        if self._stopped:
            return len(text)
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._emit(line + "\n")
            if self._stopped:
                self._buf = ""
                break
        return len(text)

    def writelines(self, lines: list[str]) -> None:
        for line in lines:
            self.write(line)

    def flush(self) -> None:
        if self._stopped:
            self._buf = ""
            return
        if self._buf:
            self._stream.write(self._buf)
            self._buf = ""
        self._stream.flush()

    def resume(self) -> None:
        """Allow output again after ``q``. Interactive prompts must not stay silent."""

        self._stopped = False
        self._budget = self._page_size

    def prepare_for_prompt(self) -> None:
        """Flush, resume after ``q``, and start a fresh page for the next dump."""

        # Resume first so a leftover partial line is not discarded after quit.
        self.resume()
        self.flush()
        self._budget = self._page_size

    def finalize(self) -> None:
        if not self._stopped and self._buf:
            self._stream.write(self._buf)
            self._buf = ""
        try:
            self._stream.flush()
        except Exception:
            pass

    def _emit(self, line: str) -> None:
        if self._stopped:
            return
        if self._budget <= 0:
            self._wait()
            if self._stopped:
                return
        self._stream.write(line)
        self._budget -= 1

    def _wait(self) -> None:
        self._show_prompt()
        try:
            while True:
                key = self._read_key()
                if not key:
                    self._budget = 10**9
                    return
                if key in {"\r", "\n"}:
                    self._budget = 1
                    return
                if key == " ":
                    self._budget = self._page_size
                    return
                if key in {"q", "Q"}:
                    self._stopped = True
                    return
                if key == "\x03":
                    raise KeyboardInterrupt
        finally:
            self._erase_prompt()

    def _show_prompt(self) -> None:
        text = paint(_MORE, PALETTE.muted)
        try:
            self._prompt.write(text)
            self._prompt.flush()
        except Exception:
            pass

    def _erase_prompt(self) -> None:
        try:
            self._prompt.write("\r\033[2K")
            self._prompt.flush()
        except Exception:
            pass

    def __getattr__(self, name: str) -> object:
        return getattr(self._stream, name)


@contextmanager
def suspend_pager() -> Iterator[None]:
    """Print without paging for an interactive UI (review menu, copy prompt).

    ``q`` on a more-prompt must not hide the next turn body or copy confirmation.
    """

    stream = sys.stdout
    if not isinstance(stream, LinePager):
        yield
        return
    stream.flush()
    sys.stdout = stream._stream
    try:
        yield
    finally:
        if sys.stdout is stream._stream:
            sys.stdout = stream
        stream.prepare_for_prompt()


@contextmanager
def activate_pager(*, page_size: int | None = None) -> Iterator[LinePager | None]:
    """Page ``sys.stdout`` for one CLI invocation when the terminal can pause."""

    if not pager_enabled():
        yield None
        return
    original_stdout = sys.stdout
    original_input = builtins.input
    pager = LinePager(
        original_stdout,
        page_size=configured_page_size() if page_size is None else page_size,
    )
    sys.stdout = pager

    def _input(prompt: str = "") -> str:
        pager.prepare_for_prompt()
        return original_input(prompt)

    builtins.input = _input
    try:
        yield pager
    finally:
        try:
            pager.finalize()
        finally:
            if sys.stdout is pager:
                sys.stdout = original_stdout
            builtins.input = original_input
