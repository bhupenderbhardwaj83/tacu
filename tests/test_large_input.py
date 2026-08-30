"""Large-input safety: truncation warnings, full-stream grep, streaming juicy scan."""

from __future__ import annotations

import io
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, core
from tacu.core import MAX_TOOL_BYTES, read_text_blocks, scan_juicy_stream


class StreamGrepTests(unittest.TestCase):
    def test_match_in_the_dropped_middle_is_still_found(self) -> None:
        scanner = cli._StreamGrep("NEEDLE")
        filler = b"padding line\n" * 50_000
        scanner.feed(filler)
        scanner.feed(b"a NEEDLE hides here\n")
        scanner.feed(filler)
        scanner.finish()
        self.assertEqual(scanner.match_count, 1)
        self.assertIn("a NEEDLE hides here", scanner.matches[0])

    def test_matching_is_case_insensitive_and_survives_chunk_splits(self) -> None:
        scanner = cli._StreamGrep("needle")
        # The word is split across two feeds, as a 64 KB pipe read would do.
        scanner.feed(b"start NEE")
        scanner.feed(b"DLE end\n")
        scanner.finish()
        self.assertEqual(scanner.match_count, 1)

    def test_final_line_without_newline_is_scanned(self) -> None:
        scanner = cli._StreamGrep("tail")
        scanner.feed(b"one\ntwo\nthe tail value")
        scanner.finish()
        self.assertEqual(scanner.match_count, 1)

    def test_match_list_is_capped_but_count_is_exact(self) -> None:
        scanner = cli._StreamGrep("hit")
        scanner.feed(b"hit\n" * (cli.MAX_STREAM_GREP_MATCHES + 500))
        scanner.finish()
        self.assertEqual(scanner.match_count, cli.MAX_STREAM_GREP_MATCHES + 500)
        self.assertEqual(len(scanner.matches), cli.MAX_STREAM_GREP_MATCHES)

    def test_inactive_when_no_needle_given(self) -> None:
        scanner = cli._StreamGrep("")
        scanner.feed(b"anything\n")
        scanner.finish()
        self.assertEqual(scanner.match_count, 0)


class TruncationWarningTests(unittest.TestCase):
    def test_no_warning_for_small_input(self) -> None:
        report = cli.CaptureReport(total_bytes=1_000, kept_bytes=1_000, truncated=False)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            cli.warn_if_truncated(report)
        self.assertEqual(stderr.getvalue(), "")

    def test_truncation_states_the_fraction_actually_analysed(self) -> None:
        report = cli.CaptureReport(
            total_bytes=5_000_000_000, kept_bytes=MAX_TOOL_BYTES, truncated=True)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            cli.warn_if_truncated(report)
        message = stderr.getvalue()
        self.assertIn("INPUT TRUNCATED", message)
        self.assertIn("NOT BASED ON ALL YOUR DATA", message)
        self.assertIn("0.01%", message)
        self.assertIn("4.7 GB", message)
        # Points at the fix rather than just complaining.
        self.assertIn("rg", message)

    def test_full_stream_grep_is_reported_as_reliable(self) -> None:
        report = cli.CaptureReport(
            total_bytes=5_000_000_000, kept_bytes=MAX_TOOL_BYTES, truncated=True,
            grep="secret", grep_match_count=3, grep_lines_scanned=90_000_000)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            cli.warn_if_truncated(report)
        message = stderr.getvalue()
        self.assertIn("FULL stream", message)
        self.assertIn("3 match", message)


class StreamGrepEvidenceTests(unittest.TestCase):
    def _evidence(self) -> dict:
        return core.content_result(source="stdin", label="piped stdin", data=b"head only")

    def test_truncated_grep_evidence_uses_full_stream_matches(self) -> None:
        report = cli.CaptureReport(
            total_bytes=10_000_000, kept_bytes=MAX_TOOL_BYTES, truncated=True,
            grep="marker", grep_matches=["row 500000 has the marker"],
            grep_match_count=1, grep_lines_scanned=1_000_000)
        updated = cli.apply_stream_grep(self._evidence(), report)
        body = updated["result"]["stdout"]["text"]
        self.assertIn("row 500000 has the marker", body)
        self.assertEqual(updated["result"]["stdout"]["full_stream_grep"]["matches"], 1)

    def test_untruncated_evidence_is_left_alone(self) -> None:
        report = cli.CaptureReport(total_bytes=100, kept_bytes=100, truncated=False, grep="x")
        original = self._evidence()
        self.assertEqual(cli.apply_stream_grep(original, report), original)

    def test_overflowing_match_count_is_disclosed(self) -> None:
        report = cli.CaptureReport(
            total_bytes=10_000_000, kept_bytes=MAX_TOOL_BYTES, truncated=True,
            grep="hit", grep_matches=["hit"] * 10, grep_match_count=999)
        updated = cli.apply_stream_grep(self._evidence(), report)
        self.assertIn("989 further match", updated["result"]["stdout"]["text"])


class StreamingJuicyScanTests(unittest.TestCase):
    def test_finds_values_across_many_blocks(self) -> None:
        blocks = ["filler line\n" * 5_000, "contact me at person@example.com\n", "more\n" * 5_000]
        scan = scan_juicy_stream(blocks)
        values = {item.value for item in scan.findings}
        self.assertIn("person@example.com", values)
        self.assertTrue(scan.complete)

    def test_memory_stays_flat_on_a_large_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "big.txt"
            with target.open("w") as handle:
                for index in range(200_000):
                    handle.write(f"row {index} filler text without anything notable\n")
                handle.write("late@example.com\n")
            # read_text_blocks must never yield the whole file at once.
            largest = max(len(block) for block in read_text_blocks(target))
            self.assertLessEqual(largest, core.JUICY_BLOCK_CHARS)

            scan = scan_juicy_stream(read_text_blocks(target))
            self.assertIn("late@example.com", {item.value for item in scan.findings})

    def test_deadline_returns_partial_results_instead_of_hanging(self) -> None:
        def slow_blocks():
            for index in range(500):
                yield f"user{index}@example.com\n" + ("filler\n" * 20_000)
                time.sleep(0.001)

        scan = scan_juicy_stream(slow_blocks(), deadline=time.monotonic() + 0.05)
        self.assertFalse(scan.complete)
        self.assertEqual(scan.stopped_reason, "timeout reached")
        self.assertTrue(scan.findings)

    def test_finding_cap_is_honoured(self) -> None:
        blocks = [f"user{index}@example.com\n" for index in range(5_000)]
        scan = scan_juicy_stream(blocks, max_findings=100)
        self.assertLessEqual(len(scan.findings), 100)

    def test_duplicate_values_are_reported_once(self) -> None:
        scan = scan_juicy_stream(["same@example.com\n" * 1_000])
        emails = [item for item in scan.findings if item.kind == "email"]
        self.assertEqual(len(emails), 1)

    def test_line_numbers_keep_increasing_across_blocks(self) -> None:
        blocks = ["padding\n" * 40_000, "a@example.com\n", "padding\n" * 40_000, "b@example.com\n"]
        scan = scan_juicy_stream(blocks)
        found = {item.value: item.line for item in scan.findings if item.kind == "email"}
        self.assertIn("a@example.com", found)
        self.assertIn("b@example.com", found)
        self.assertGreater(found["b@example.com"], found["a@example.com"])


class ScanPerformanceTests(unittest.TestCase):
    def test_dense_match_file_completes_quickly(self) -> None:
        # detect_juicy counts newlines from the start for every match, so a dense
        # file used to degrade quadratically. Blocks bound that cost.
        blocks = [f"user{index}@example.com,note{index}\n" for index in range(60_000)]
        started = time.monotonic()
        scan = scan_juicy_stream(blocks)
        elapsed = time.monotonic() - started
        self.assertTrue(scan.findings)
        self.assertLess(elapsed, 30, f"dense scan took {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
