"""Stepping up to the bigger model, and only on evidence.

Which jobs need the bigger model cannot be read from the wording: both installed
models answer "refactor the auth module" with a single tool call. What can be
read is a run going nowhere — a turn that produced nothing, the same call twice,
half the budget spent with nothing touched. Escalation reacts to those.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu.codingloop import CodingLoop
from tacu.escalation import RunSignals, escalation_reason


class SignalTests(unittest.TestCase):
    def test_a_healthy_run_is_left_alone(self) -> None:
        signals = RunSignals(budget=8)
        signals.note_turn(calls=1, content="", done_reason="stop")
        signals.note_call("read_file", "path=a.py", True)
        signals.note_call("edit_file", "path=a.py", True)
        signals.changed_anything = True
        self.assertIsNone(escalation_reason(signals))

    def test_turns_that_produce_nothing(self) -> None:
        signals = RunSignals(budget=8)
        for _ in range(2):
            signals.note_turn(calls=0, content="", done_reason="stop")
        self.assertIn("neither an action nor an answer", escalation_reason(signals) or "")

    def test_replies_that_run_out_of_room(self) -> None:
        signals = RunSignals(budget=8)
        for _ in range(2):
            signals.note_turn(calls=0, content="", done_reason="length")
        self.assertIn("ran out of room", escalation_reason(signals) or "")

    def test_the_same_call_over_and_over(self) -> None:
        signals = RunSignals(budget=8)
        for _ in range(3):
            signals.note_call("read_file", "path=a.py", True)
        self.assertIn("without progress", escalation_reason(signals) or "")

    def test_a_tool_that_does_not_exist(self) -> None:
        signals = RunSignals(budget=8)
        signals.note_call("imaginary_tool", "{}", False)
        self.assertIn("does not exist", escalation_reason(signals) or "")

    def test_actions_spent_with_nothing_to_show(self) -> None:
        signals = RunSignals(budget=8)
        for index in range(4):
            signals.note_call(f"tool{index}", "{}", True)
        self.assertIn("nothing has changed", escalation_reason(signals) or "")

    def test_work_in_progress_is_not_a_stall(self) -> None:
        signals = RunSignals(budget=8, changed_anything=True)
        for index in range(5):
            signals.note_call(f"tool{index}", "{}", True)
        self.assertIsNone(escalation_reason(signals))


class LoopEscalationTests(unittest.TestCase):
    class Stuck:
        model = "small"

        def chat_tools(self, messages, tools, **kwargs):
            return {"content": "", "done_reason": "stop",
                    "tool_calls": [{"name": "read_file", "arguments": {"path": "a.py"}}]}

    class Capable:
        model = "big"

        def chat_tools(self, messages, tools, **kwargs):
            return {"content": "Nothing needed changing.", "tool_calls": [], "done_reason": "stop"}

    def build(self, directory: Path, **kwargs) -> CodingLoop:
        schema = {"type": "function",
                  "function": {"name": "read_file", "description": "read",
                               "parameters": {"type": "object", "properties": {}}}}
        return CodingLoop(workspace=directory, goal="look", client=self.Stuck(),
                          tools=[schema], dispatch=lambda n, a: {"status": "success"},
                          max_steps=8, **kwargs)

    def test_a_stuck_run_moves_up_and_the_old_model_is_unloaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            made: list[str] = []
            events: list[tuple[str, str]] = []
            with patch("tacu.codingloop.make_room_for", return_value=["small"]) as room:
                loop = self.build(Path(directory), escalate_to="big",
                                  make_client=lambda model: (made.append(model), self.Capable())[1],
                                  on_event=lambda kind, message: events.append((kind, message)))
                outcome = loop.run()
            self.assertEqual(made, ["big"], "the run must continue on the bigger model")
            room.assert_called_once_with("big")
            self.assertTrue(outcome.completed)
            self.assertIn("escalate", [kind for kind, _ in events])

    def test_it_steps_up_once_and_not_repeatedly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            made: list[str] = []
            with patch("tacu.codingloop.make_room_for", return_value=[]):
                loop = self.build(Path(directory), escalate_to="big",
                                  make_client=lambda model: (made.append(model), self.Stuck())[1])
                loop.run()
            # The bigger model is also stuck; a third attempt would be churn.
            self.assertEqual(made, ["big"])

    def test_without_a_stronger_model_the_run_finishes_as_it_is(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            loop = self.build(Path(directory))          # no escalate_to
            outcome = loop.run()
            self.assertFalse(outcome.completed)
            self.assertEqual(outcome.stopped, "step budget")


class ReadOnlyLoopTests(unittest.TestCase):
    """A lookup has nothing to change, so it must not be judged for not changing."""

    class Reader:
        model = "small"

        def __init__(self) -> None:
            self.turns = 0

        def chat_tools(self, messages, tools, **kwargs):
            self.turns += 1
            if self.turns <= 4:
                return {"content": "", "done_reason": "stop",
                        "tool_calls": [{"name": "read_file",
                                        "arguments": {"path": f"file{self.turns}.py"}}]}
            return {"content": "There are four files.", "tool_calls": [], "done_reason": "stop"}

    def test_reading_for_several_turns_is_not_a_stall(self) -> None:
        schema = {"type": "function",
                  "function": {"name": "read_file", "description": "read",
                               "parameters": {"type": "object", "properties": {}}}}
        with tempfile.TemporaryDirectory() as directory:
            made: list[str] = []
            loop = CodingLoop(workspace=Path(directory), goal="count the files",
                              client=self.Reader(), tools=[schema],
                              dispatch=lambda n, a: {"status": "success"}, max_steps=8,
                              read_only=True, escalate_to="big",
                              make_client=lambda model: made.append(model))
            outcome = loop.run()
            self.assertTrue(outcome.completed)
            self.assertEqual(made, [], "four reads in a row is doing the job, not stalling")

    def test_a_read_only_run_is_not_given_a_task_list(self) -> None:
        schema = {"type": "function",
                  "function": {"name": "read_file", "description": "read",
                               "parameters": {"type": "object", "properties": {}}}}
        with tempfile.TemporaryDirectory() as directory:
            loop = CodingLoop(workspace=Path(directory), goal="x", client=self.Reader(),
                              tools=[schema], dispatch=lambda n, a: {}, read_only=True)
            offered = {item["function"]["name"] for item in loop.schemas}
            self.assertNotIn("todo_write", offered)


class LookupRoutingTests(unittest.TestCase):
    def test_a_factual_question_earns_a_look(self) -> None:
        from tacu.cli import _looks_up_facts

        for question in ("is there any .md file inside not_required directory",
                         "how many tests are in this project",
                         "which files import routing",
                         "what version of python is here"):
            with self.subTest(question=question):
                self.assertTrue(_looks_up_facts(question), question)

    def test_a_language_task_does_not(self) -> None:
        from tacu.cli import _looks_up_facts

        for question in ("translate this into polite language",
                         "explain how DNS caching works",
                         "rewrite this paragraph"):
            with self.subTest(question=question):
                self.assertFalse(_looks_up_facts(question), question)


if __name__ == "__main__":
    unittest.main()
