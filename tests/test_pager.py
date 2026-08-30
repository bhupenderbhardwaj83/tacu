"""Line pager: first page, then Enter (one line) or Space (one page)."""

from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli
from tacu.pager import LinePager, activate_pager, pager_enabled
from tacu.theme import strip_ansi


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class _Pipe(io.StringIO):
    def isatty(self) -> bool:
        return False


class LinePagerTests(unittest.TestCase):
    def _pager(self, keys: list[str], *, page_size: int = 2) -> tuple[LinePager, io.StringIO, io.StringIO]:
        leftover = list(keys)

        def read_key() -> str:
            if not leftover:
                self.fail("pager asked for more keys than the test provided")
            return leftover.pop(0)

        out = io.StringIO()
        prompt = io.StringIO()
        pager = LinePager(out, page_size=page_size, read_key=read_key, prompt_stream=prompt)
        return pager, out, prompt

    def test_short_output_never_waits(self) -> None:
        pager, out, prompt = self._pager([], page_size=20)
        pager.write("one\ntwo\n")
        pager.finalize()
        self.assertEqual(out.getvalue(), "one\ntwo\n")
        self.assertEqual(strip_ansi(prompt.getvalue()), "")

    def test_enter_reveals_one_line(self) -> None:
        pager, out, _prompt = self._pager(["\n", "\n"], page_size=2)
        pager.write("a\nb\nc\nd\n")
        pager.finalize()
        self.assertEqual(out.getvalue(), "a\nb\nc\nd\n")

    def test_space_reveals_one_page(self) -> None:
        pager, out, _prompt = self._pager([" "], page_size=2)
        pager.write("a\nb\nc\nd\n")
        pager.finalize()
        self.assertEqual(out.getvalue(), "a\nb\nc\nd\n")

    def test_tab_is_ignored_until_space(self) -> None:
        pager, out, _prompt = self._pager(["\t", " "], page_size=2)
        pager.write("a\nb\nc\nd\n")
        pager.finalize()
        self.assertEqual(out.getvalue(), "a\nb\nc\nd\n")

    def test_quit_drops_remaining_lines(self) -> None:
        pager, out, _prompt = self._pager(["q"], page_size=2)
        pager.write("a\nb\nc\nd\ne\n")
        pager.finalize()
        self.assertEqual(out.getvalue(), "a\nb\n")

    def test_one_write_with_many_newlines_still_pages(self) -> None:
        pager, out, _prompt = self._pager([" ", "\n"], page_size=3)
        pager.write("".join(f"L{i}\n" for i in range(7)))
        pager.finalize()
        self.assertEqual(out.getvalue(), "".join(f"L{i}\n" for i in range(7)))

    def test_carriage_return_counts_as_enter(self) -> None:
        pager, out, _prompt = self._pager(["\r"], page_size=1)
        pager.write("a\nb\n")
        pager.finalize()
        self.assertEqual(out.getvalue(), "a\nb\n")

    def test_prompt_is_shown_then_erased(self) -> None:
        pager, _out, prompt = self._pager(["\n"], page_size=1)
        pager.write("a\nb\n")
        pager.finalize()
        raw = prompt.getvalue()
        self.assertIn("Enter: line", strip_ansi(raw))
        self.assertIn("Space: page", strip_ansi(raw))
        self.assertIn("\r\033[2K", raw)

    def test_isatty_delegates_to_the_wrapped_stream(self) -> None:
        pager = LinePager(_TTY(), read_key=lambda: "\n")
        self.assertTrue(pager.isatty())
        pager = LinePager(_Pipe(), read_key=lambda: "\n")
        self.assertFalse(pager.isatty())

    def test_prepare_for_prompt_starts_a_fresh_page(self) -> None:
        pager, out, _prompt = self._pager([], page_size=2)
        pager.write("a\nb\n")
        pager.prepare_for_prompt()
        pager.write("c\nd\n")
        pager.finalize()
        self.assertEqual(out.getvalue(), "a\nb\nc\nd\n")

    def test_quit_then_prepare_for_prompt_shows_later_output(self) -> None:
        """q must not hide the turn body / copy confirmation after the next prompt."""

        pager, out, _prompt = self._pager(["q"], page_size=1)
        pager.write("a\nb\nc\n")
        self.assertEqual(out.getvalue(), "a\n")
        pager.prepare_for_prompt()
        pager._budget = 20
        pager.write("QUERY\nRESPONSE\nCopied.\n")
        pager.finalize()
        self.assertEqual(out.getvalue(), "a\nQUERY\nRESPONSE\nCopied.\n")

    def test_suspend_pager_prints_without_waiting(self) -> None:
        from tacu.pager import suspend_pager

        out = io.StringIO()
        pager = LinePager(out, page_size=1, read_key=lambda: self.fail("paged during suspend"))
        previous = sys.stdout
        sys.stdout = pager
        try:
            pager.write("a\n")
            with suspend_pager():
                print("QUERY")
                print("RESPONSE")
                print("Copied.")
            pager.finalize()
        finally:
            sys.stdout = previous
        self.assertEqual(out.getvalue(), "a\nQUERY\nRESPONSE\nCopied.\n")


class PagerEnablementTests(unittest.TestCase):
    def test_disabled_when_stdout_is_piped(self) -> None:
        self.assertFalse(pager_enabled(stdout=_Pipe(), stdin=_TTY()))

    def test_disabled_when_stdin_is_piped(self) -> None:
        self.assertFalse(pager_enabled(stdout=_TTY(), stdin=_Pipe()))

    def test_disabled_by_environment(self) -> None:
        with patch.dict(os.environ, {"TACU_NO_PAGER": "1"}):
            self.assertFalse(pager_enabled(stdout=_TTY(), stdin=_TTY()))

    def test_enabled_for_interactive_tty(self) -> None:
        with patch.dict(os.environ, {"TACU_NO_PAGER": "", "TERM": "xterm"}):
            self.assertTrue(pager_enabled(stdout=_TTY(), stdin=_TTY()))

    def test_activate_is_noop_when_stdout_is_captured(self) -> None:
        captured = io.StringIO()
        with redirect_stdout(captured), activate_pager() as pager:
            print("hello")
        self.assertIsNone(pager)
        self.assertEqual(captured.getvalue(), "hello\n")


class HelpStillDumpsWhenCapturedTests(unittest.TestCase):
    def test_help_pauses_after_the_first_page_on_a_tty(self) -> None:
        out = _TTY()
        inn = _TTY()
        err = io.StringIO()
        snapshots: list[str] = []
        # The complete command catalog spans several pages; keep advancing until
        # the final global-options box has been rendered.
        keys = [" "] * 8

        def read_key(_stdin=None) -> str:
            snapshots.append(strip_ansi(out.getvalue()))
            if not keys:
                self.fail("help asked for more pager keys than expected")
            return keys.pop(0)

        with patch.dict(os.environ, {"TERM": "xterm", "TACU_NO_PAGER": ""}):
            with patch("sys.stdout", out), patch("sys.stdin", inn), patch("sys.stderr", err), \
                 patch("tacu.pager.default_read_key", new=read_key):
                self.assertEqual(cli.main(["help"]), 0)
        self.assertTrue(snapshots)
        first = snapshots[0]
        self.assertIn("PICK ONE", first)
        self.assertNotIn("GLOBAL OPTIONS", first)
        self.assertLessEqual(first.count("\n"), 20)
        full = strip_ansi(out.getvalue())
        self.assertIn("GLOBAL OPTIONS", full)
        self.assertIn("paging", full)

    def test_help_prints_in_full_when_stdout_is_not_a_tty(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main(["help"]), 0)
        plain = strip_ansi(output.getvalue())
        self.assertIn("PICK ONE", plain)
        self.assertIn("paging", plain)
        self.assertIn("Enter next line", plain)
        self.assertIn("Space next page", plain)
        self.assertTrue("t a c u" in plain[:160] or ">_" in plain[:160] or "TACU" in plain[:80])
        self.assertIn("GLOBAL OPTIONS", plain)
        self.assertGreater(plain.count("\n"), 20)


if __name__ == "__main__":
    unittest.main()
