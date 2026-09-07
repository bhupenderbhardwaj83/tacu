"""Piping means "here is the data" — for every verb, not just ti ask.

`nmap … | ti auto which ports are open` reported this machine's own listening
ports, because the intent verbs returned before the block that reads stdin and
went looking for data that had already been supplied.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, routing

NMAP = b"""Nmap scan report for host.example (192.168.1.9)
PORT      STATE SERVICE
53/tcp    open  domain
1433/tcp  open  ms-sql-s
5432/tcp  open  postgresql
"""


class PipeIsTheSubjectTests(unittest.TestCase):
    def test_reading_the_input_needs_no_plan(self) -> None:
        for intent in ("which ports are open in this output",
                       "review this and list the ports",
                       "summarise these findings",
                       "what database ports are listed"):
            with self.subTest(intent=intent):
                self.assertTrue(cli._pipe_is_the_subject(intent), intent)

    def test_a_request_that_changes_something_still_plans(self) -> None:
        for intent in ("write these ports to ports.txt",
                       "stop the container named api",
                       "open google chrome"):
            with self.subTest(intent=intent):
                self.assertFalse(cli._pipe_is_the_subject(intent), intent)


class AppNameFromPipedTextTests(unittest.TestCase):
    """Words for the text in front of you are not applications."""

    def test_output_is_not_an_application_to_launch(self) -> None:
        for intent in ("which database ports are open in this output",
                       "which ports are open in the scan results",
                       "what is open in the log",
                       "show what is open in the report"):
            with self.subTest(intent=intent):
                self.assertIsNone(routing.app_to_open_from_intent(intent), intent)
                self.assertFalse(routing.intent_wants_host_mutate(intent), intent)

    def test_a_real_launch_is_untouched(self) -> None:
        self.assertEqual(routing.app_to_open_from_intent("open chrome"), "chrome")
        self.assertEqual(routing.app_to_open_from_intent("launch apple.com in chrome"), "chrome")


class PipedVerbTests(unittest.TestCase):
    """Every verb answers from what was piped, and none asks the host instead."""

    def run_verb(self, verb: str, question: str) -> tuple[str, dict]:
        seen: dict = {}

        def fake_ask(*, store, client, query, tool_result, stream, **kwargs):
            seen["query"] = query
            seen["tool_result"] = tool_result
            print("ANSWERED FROM EVIDENCE")
            return None

        with tempfile.TemporaryDirectory() as home:
            reader = io.BytesIO(NMAP)
            stdin = io.TextIOWrapper(reader)
            stdin.isatty = lambda: False           # type: ignore[method-assign]
            shown = io.StringIO()
            with patch.dict(os.environ, {"TACU_HOME": home}), \
                    patch.object(cli.sys, "stdin", stdin), \
                    patch.object(cli, "ask", fake_ask), \
                    patch("tacu.cli.load_provider"), \
                    redirect_stdout(shown):
                cli.main([verb, question])
            return shown.getvalue(), seen

    def test_each_verb_answers_from_the_pipe(self) -> None:
        for verb in ("ask", "auto", "do"):
            with self.subTest(verb=verb):
                body, seen = self.run_verb(verb, "which database ports are open in this output")
                self.assertIn("ANSWERED FROM EVIDENCE", body)
                self.assertIsNotNone(seen.get("tool_result"),
                                     f"{verb} discarded the piped evidence")

    def test_the_piped_bytes_reach_the_answer(self) -> None:
        _body, seen = self.run_verb("auto", "list the ports in this output")
        blob = repr(seen.get("tool_result"))
        self.assertIn("5432", blob)
        self.assertIn("1433", blob)


if __name__ == "__main__":
    unittest.main()
