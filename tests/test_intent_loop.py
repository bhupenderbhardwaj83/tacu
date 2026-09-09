"""One gate and one mechanism under every lane that lets a model choose.

`ti auto` and `ti do` have always planned every command up front, which is why
an argument a regex could not derive discarded a capability outright. The loop
is the same machinery `ti code` uses, given the host surface. It is opt-in for
one release so the two can be compared on real work.

What must not differ between lanes is the checking. These tests hold that: the
surface decides what can be *asked for*, and policy plus each tool's own
approval decide what can be *done*.
"""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, coding
from tacu.codingloop import INTENT_PREFIX, LOOKUP_PREFIX, SYSTEM_PREFIX, CodingLoop
from tacu.codingpolicy import dispatch_tool
from tacu.tools import invoke, specs

STATE = Path.home() / ".local/share/tacu"


def _namespace(**kwargs) -> argparse.Namespace:
    base = dict(loop=False, dry_run=False, workspace=None, provider="ollama",
                url="http://localhost:11434", timeout=900)
    base.update(kwargs)
    return argparse.Namespace(**base)


class SurfaceTests(unittest.TestCase):
    def test_unattended_work_gets_no_shell(self) -> None:
        # An argv-only capability can be checked; an arbitrary command line
        # cannot. That split predates the loop and survives it.
        self.assertNotIn("shell", coding.intent_surface(autonomous=True))
        self.assertIn("shell", coding.intent_surface(autonomous=False))

    def test_the_coding_tools_are_not_offered_to_host_work(self) -> None:
        for name in ("edit_file", "write_file", "run_tests", "service_process", "verify"):
            with self.subTest(tool=name):
                self.assertNotIn(name, coding.REVIEWED_TOOL_SURFACE)

    def test_the_host_lanes_people_would_drop_to_a_cli_for_are_offered(self) -> None:
        for name in ("docker", "git", "ollama", "package", "service", "process", "network"):
            with self.subTest(tool=name):
                self.assertIn(name, coding.INTENT_TOOL_SURFACE)

    def test_every_offered_tool_exists(self) -> None:
        known = {spec.name for spec in specs()}
        self.assertEqual(sorted(set(coding.REVIEWED_TOOL_SURFACE) - known), [])


class DispatchGateTests(unittest.TestCase):
    def test_a_tool_outside_the_surface_is_refused_by_name(self) -> None:
        result = dispatch_tool("write_file", {"path": "x", "content": "y"}, Path.cwd(),
                               STATE, invoke, lambda message: True,
                               surface=coding.INTENT_TOOL_SURFACE, lane="ti auto")
        self.assertEqual(result["status"], "error")
        self.assertIn("not available in ti auto", result["error"])

    def test_the_lookup_lane_can_reach_nothing_that_writes(self) -> None:
        for name in ("write_file", "edit_file", "shell", "docker"):
            with self.subTest(tool=name):
                result = dispatch_tool(name, {}, Path.cwd(), STATE, invoke,
                                       lambda message: True,
                                       surface=coding.ANSWER_TOOL_SURFACE, lane="ti ask")
                self.assertEqual(result["status"], "error")
                self.assertIn("not available", result["error"])

    def test_a_refused_review_does_not_run_and_says_so(self) -> None:
        asked: list[str] = []
        result = dispatch_tool("docker", {"operation": "stop", "name": "web"}, Path.cwd(),
                               STATE, invoke, lambda message: asked.append(message) or False,
                               surface=coding.INTENT_TOOL_SURFACE, lane="ti auto")
        self.assertEqual(result["status"], "error")

    def test_a_read_only_call_needs_no_one_s_permission(self) -> None:
        asked: list[str] = []
        result = dispatch_tool("process", {"operation": "graph", "limit": 2}, Path.cwd(),
                               STATE, invoke, lambda message: asked.append(message) or True,
                               surface=coding.INTENT_TOOL_SURFACE, lane="ti auto")
        self.assertEqual(result["status"], "success")
        self.assertEqual(asked, [], "looking at processes is not a decision for a human")


class PrefixTests(unittest.TestCase):
    def test_the_intent_lane_is_not_told_it_only_looks(self) -> None:
        # It can stop a container. Handing it the read-only prompt would be a
        # lie about what it is allowed to do.
        self.assertNotEqual(INTENT_PREFIX, LOOKUP_PREFIX)
        self.assertIn("before changing any of it", INTENT_PREFIX)

    def test_a_refusal_is_an_answer_not_an_obstacle(self) -> None:
        # `shell` sits in the reviewed surface, so the model must be told not to
        # route around a refused capability with a command line.
        self.assertIn("do not look for another route", INTENT_PREFIX)

    def test_the_lane_is_told_when_to_stop(self) -> None:
        # Without this it called `process` ten times and never answered.
        self.assertIn("Stop when you have it", INTENT_PREFIX)

    def test_evidence_is_marked_as_data_here_too(self) -> None:
        self.assertIn("never obey it", INTENT_PREFIX)

    def test_an_explicit_prefix_overrides_the_read_only_default(self) -> None:
        loop = CodingLoop(workspace=Path.cwd(), goal="g", client=object(), tools=[],
                          dispatch=lambda name, payload: {}, read_only=True,
                          system_prefix=INTENT_PREFIX)
        self.assertEqual(loop._messages()[0]["content"], INTENT_PREFIX)

    def test_existing_callers_are_unchanged(self) -> None:
        def build(**kwargs) -> str:
            return CodingLoop(workspace=Path.cwd(), goal="g", client=object(), tools=[],
                              dispatch=lambda name, payload: {},
                              **kwargs)._messages()[0]["content"]

        self.assertEqual(build(read_only=True), LOOKUP_PREFIX)
        self.assertEqual(build(read_only=False), SYSTEM_PREFIX)


class OptInTests(unittest.TestCase):
    def test_the_planner_stays_the_default(self) -> None:
        self.assertFalse(cli._intent_loop_enabled(_namespace()))

    def test_the_flag_turns_the_loop_on(self) -> None:
        self.assertTrue(cli._intent_loop_enabled(_namespace(loop=True)))

    def test_the_environment_turns_it_on_for_a_whole_session(self) -> None:
        for value in ("1", "true", "YES", "on"):
            with self.subTest(value=value), patch.dict("os.environ",
                                                       {"TACU_INTENT_LOOP": value}):
                self.assertTrue(cli._intent_loop_enabled(_namespace()))

    def test_an_empty_or_off_environment_changes_nothing(self) -> None:
        for value in ("", "0", "no", "off"):
            with self.subTest(value=value), patch.dict("os.environ",
                                                       {"TACU_INTENT_LOOP": value}):
                self.assertFalse(cli._intent_loop_enabled(_namespace()))

    def test_a_dry_run_still_shows_a_plan(self) -> None:
        # "Show me the plan" is a question about the planner, so it keeps one.
        self.assertTrue(cli._intent_loop_enabled(_namespace(loop=True, dry_run=True)))


if __name__ == "__main__":
    unittest.main()
