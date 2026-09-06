"""Deciding "done" by looking at the workspace, not by the last exit code."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import acceptance

INDEX_REQUEST = ("create a simple http index file with Hello greeting back to user "
                 "after taking username as input")


class CriteriaTests(unittest.TestCase):
    def test_a_request_for_an_index_file_claims_an_html_page(self) -> None:
        claims = acceptance.criteria_for(INDEX_REQUEST)
        self.assertTrue(claims)
        self.assertTrue(any("index page" in item.describes for item in claims))

    def test_a_named_file_is_claimed_by_name(self) -> None:
        claims = acceptance.criteria_for("create a file called report.py that prints hello")
        self.assertTrue(any(item.detail == "report.py" for item in claims))

    def test_a_question_claims_nothing(self) -> None:
        self.assertEqual(acceptance.criteria_for("which process is using most cpu"), [])
        self.assertEqual(acceptance.criteria_for("am i compromised"), [])


class CheckTests(unittest.TestCase):
    def test_a_flask_app_does_not_satisfy_a_request_for_an_index_page(self) -> None:
        """The exact miss from the transcript: app.py was accepted as done."""

        claims = acceptance.criteria_for(INDEX_REQUEST)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "app.py").write_text("from flask import Flask\n")
            missing = acceptance.unmet(claims, workspace)
        self.assertTrue(missing, "an index page was requested and none exists")
        self.assertIn("html", missing[0][1])

    def test_an_html_page_satisfies_it(self) -> None:
        claims = acceptance.criteria_for(INDEX_REQUEST)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "index.html").write_text("<!doctype html><html><body>hi</body></html>")
            self.assertEqual(acceptance.unmet(claims, workspace), [])

    def test_a_file_that_does_not_parse_is_not_done(self) -> None:
        claims = acceptance.criteria_for("create a file called broken.py that prints hello")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "broken.py").write_text("def oops(:\n")
            missing = acceptance.unmet(claims, workspace)
        self.assertTrue(any("well formed" in item.describes for item, _why in missing))

    def test_html_without_any_html_element_is_not_a_page(self) -> None:
        claims = acceptance.criteria_for("create a file called page.html")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "page.html").write_text("just some words")
            missing = acceptance.unmet(claims, workspace)
        self.assertTrue(missing)

    def test_the_report_names_what_was_and_was_not_achieved(self) -> None:
        claims = acceptance.criteria_for(INDEX_REQUEST)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "app.py").write_text("x = 1\n")
            text = acceptance.summarise(acceptance.check(claims, workspace))
        self.assertIn("not met", text)
        self.assertIn("index page", text)


if __name__ == "__main__":
    unittest.main()
