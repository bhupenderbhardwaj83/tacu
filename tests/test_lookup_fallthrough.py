"""Routing may suggest, never decide.

Every test here reproduces a failure that shipped. `ti ask "please tell me all
the python servers running on my machine"` answered "No running process matches
python servers" while six were listening on ports 5000, 5001, 5055 and 8000 —
because routing built `process.graph` with the regex-derived filter
"python servers", nothing matched it, and the empty result was reported as an
answer. The path that would have looked properly was never reached.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli
from tacu.codingloop import CodingLoop

SERVERS = "please tell me all the python servers running on my machine"


def _step(*, ok: bool = True, **data: object) -> dict:
    return {"step": 1, "purpose": "look", "command": ("ps",), "policy": "allow",
            "result": {"ok": ok, "data": dict(data)}}


class LooksUpFactsTests(unittest.TestCase):
    def test_the_question_that_was_answered_from_nothing_now_gets_a_look(self) -> None:
        # No question word appears in it, which is why looking was refused.
        self.assertTrue(cli._looks_up_facts(SERVERS))

    def test_a_named_subject_is_enough_without_a_question_word(self) -> None:
        for question in ("tell me the disk usage", "let me know the docker containers",
                         "give me the git branch", "i want to know the uptime"):
            with self.subTest(question=question):
                self.assertTrue(cli._looks_up_facts(question))

    def test_question_forms_still_look(self) -> None:
        for question in ("what is my ip", "is nginx installed", "how many files are here"):
            with self.subTest(question=question):
                self.assertTrue(cli._looks_up_facts(question))

    def test_composition_is_never_answered_by_looking(self) -> None:
        for question in ("write me a poem", "please write a haiku about ports",
                         "translate this to french", "draft a commit message"):
            with self.subTest(question=question):
                self.assertFalse(cli._looks_up_facts(question))

    def test_a_bare_imperative_is_not_a_subject(self) -> None:
        # "stop" is an entity of the container capabilities and also the first
        # word of "stop this request", which is addressed to TACU, not to Docker.
        for question in ("stop this request", "restart it", "run that again"):
            with self.subTest(question=question):
                self.assertFalse(cli._looks_up_facts(question))

    def test_the_vocabulary_comes_from_the_capability_table(self) -> None:
        words = cli._inspectable_words()
        self.assertIn("container", words)
        self.assertIn("servers", words)
        self.assertNotIn("stop", words)


class RoutingHintTests(unittest.TestCase):
    def test_the_hint_names_the_capability_and_carries_no_arguments(self) -> None:
        hint = cli._routing_hint(SERVERS)
        self.assertEqual(hint, "process.graph")
        # The guessed filter is exactly what must not travel with it.
        self.assertNotIn("python servers", hint)

    def test_no_capability_means_no_hint(self) -> None:
        self.assertEqual(cli._routing_hint("write me a poem"), "")


class EmptyRunTests(unittest.TestCase):
    def test_a_clean_run_that_matched_nothing_is_not_an_answer(self) -> None:
        self.assertTrue(cli._run_found_nothing([_step(status="no_results", count=0)]))
        self.assertTrue(cli._run_found_nothing([_step(status="success", count=0)]))

    def test_a_run_that_found_something_is_left_alone(self) -> None:
        self.assertFalse(cli._run_found_nothing([_step(status="success", count=6)]))

    def test_a_failed_step_is_not_an_empty_result(self) -> None:
        # A failure has its own reporting; re-looking would hide the error.
        self.assertFalse(cli._run_found_nothing([_step(ok=False, status="error")]))

    def test_nothing_ran_means_nothing_to_reconsider(self) -> None:
        self.assertFalse(cli._run_found_nothing([]))
        self.assertFalse(cli._run_found_nothing(None))

    def test_emptiness_has_to_be_stated(self) -> None:
        # A tool that reports no count has still come back with something.
        self.assertFalse(cli._run_found_nothing([_step(exit_code=0)]))

    def test_a_rich_payload_without_a_count_is_not_empty(self) -> None:
        # network.interfaces answers "what is my primary ip" and reports no
        # count at all. Reading that as "no evidence" sent an already-answered
        # question off to be looked up again, for nothing.
        interfaces = _step(status="success", primary={"name": "en0"}, interface_count=24)
        graph = _step(status="no_results", count=0)
        self.assertFalse(cli._run_found_nothing([interfaces, graph]))

    def test_one_populated_step_settles_a_mixed_run(self) -> None:
        self.assertFalse(cli._run_found_nothing(
            [_step(status="no_results", count=0), _step(status="success", count=3)]))


class LoopHintTests(unittest.TestCase):
    def _loop(self, hint: str) -> CodingLoop:
        return CodingLoop(workspace=Path.cwd(), goal=SERVERS, client=object(), tools=[],
                          dispatch=lambda name, payload: {}, read_only=True, hint=hint)

    def test_the_hint_reaches_the_opening_turn_as_a_suggestion(self) -> None:
        standing = self._loop("process.graph")._messages()[1]["content"]
        self.assertIn("process.graph", standing)
        self.assertIn("not binding", standing)

    def test_the_hint_is_dropped_once_real_results_exist(self) -> None:
        loop = self._loop("process.graph")
        loop.history.append({"role": "tool", "name": "process", "content": "{}"})
        self.assertNotIn("process.graph", loop._messages()[1]["content"])

    def test_no_hint_leaves_the_standing_block_unchanged(self) -> None:
        self.assertNotIn("Suggested starting point", self._loop("")._messages()[1]["content"])

    def test_the_system_prefix_stays_byte_identical_with_a_hint(self) -> None:
        # Prefix stability is what makes the KV cache reusable across turns.
        self.assertEqual(self._loop("process.graph")._messages()[0],
                         self._loop("")._messages()[0])


class LookupPrefixTests(unittest.TestCase):
    """A read-only run must not be told to use tools it does not have.

    It was: the coding prefix says "call todo_write first", read-only runs strip
    that tool, and the resulting unknown-tool call escalated the lookup to a
    larger model on its very first turn.
    """

    def _prefix(self, *, read_only: bool) -> str:
        loop = CodingLoop(workspace=Path.cwd(), goal=SERVERS, client=object(), tools=[],
                          dispatch=lambda name, payload: {}, read_only=read_only)
        return loop._messages()[0]["content"]

    def test_a_lookup_is_never_told_to_call_todo_write(self) -> None:
        self.assertNotIn("todo_write", self._prefix(read_only=True))

    def test_a_lookup_is_not_told_to_edit_or_run_tests(self) -> None:
        prefix = self._prefix(read_only=True)
        for tool in ("edit_file", "run_tests", "service_process"):
            with self.subTest(tool=tool):
                self.assertNotIn(tool, prefix)

    def test_a_coding_run_still_gets_the_coding_prefix(self) -> None:
        self.assertIn("todo_write", self._prefix(read_only=False))

    def test_a_lookup_is_told_to_widen_before_concluding_absence(self) -> None:
        # The failure being fixed: a narrow filter returned nothing and that was
        # reported as "no python servers" while three were listening.
        self.assertIn("returns nothing", self._prefix(read_only=True))


if __name__ == "__main__":
    unittest.main()
