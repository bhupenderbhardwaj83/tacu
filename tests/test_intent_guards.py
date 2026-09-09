"""Four failures from real use, and the guards that keep them fixed.

Each began the same way: a value or a category decided from wording alone, then
acted on as if it had been established. The port came from an IP address, the
filename came from the same IP, a question about commands was answered with a
list of processes, and reasoning about how to answer was printed as the answer.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import routing
from tacu.cli import _looks_up_facts, _names_something_inspectable
from tacu.companion import _recipes_used
from tacu.routing import (_port_from_intent, intent_asks_how_to, intent_wants_a_command,
                          native_steps_for_intent)

HOST_QUESTION = "please show me all the outbound connection with the host 140.82.114.25"


class PortFromAnAddressTests(unittest.TestCase):
    """`140.82.114.25` was read as port 140 by a bare-number fallback."""

    def test_an_address_supplies_no_port(self) -> None:
        self.assertIsNone(_port_from_intent(HOST_QUESTION))

    def test_a_version_or_a_date_supplies_no_port(self) -> None:
        for question in ("tell me about python 3.14.7", "what happened on 2026-09-09",
                         "is 1.2.3.4 reachable"):
            with self.subTest(question=question):
                self.assertIsNone(_port_from_intent(question))

    def test_a_port_that_is_named_is_still_read(self) -> None:
        self.assertEqual(_port_from_intent("what is running on port 8080"), 8080)

    def test_a_bare_number_counts_when_the_sentence_is_about_ports(self) -> None:
        self.assertEqual(_port_from_intent("what is listening on 3000"), 3000)
        self.assertEqual(
            _port_from_intent("using lsof tell me which destinations have connections "
                              "established on tcp 443"), 443)

    def test_a_bare_number_alone_is_not_a_port(self) -> None:
        self.assertIsNone(_port_from_intent("show me the top 10 processes"))


class AddressIsNotAFilenameTests(unittest.TestCase):
    """The same IP was planned as `read_file(path="140.82.114.25")`, which failed."""

    def test_the_plan_holds_no_file_read(self) -> None:
        steps = native_steps_for_intent(HOST_QUESTION)
        self.assertTrue(steps)
        self.assertNotIn("read_file", [step["tool"] for step in steps])

    def test_the_plan_asks_the_right_question_of_the_right_tool(self) -> None:
        first = native_steps_for_intent(HOST_QUESTION)[0]
        self.assertEqual((first["tool"], first["operation"]), ("network", "connections"))
        self.assertEqual(first["inputs"].get("host"), "140.82.114.25")
        self.assertNotIn("port", first["inputs"])

    def test_a_real_filename_is_still_a_filename(self) -> None:
        self.assertIn("app.py", routing._filenames_from_intent("read app.py for me"))

    def test_a_domain_is_still_not_a_filename(self) -> None:
        self.assertEqual(routing._filenames_from_intent("open apple.com"), [])


class CommandQuestionTests(unittest.TestCase):
    """"top 10 OS commands for process related forensics" ran a forensics sweep."""

    def test_a_question_about_commands_is_recognised(self) -> None:
        for question in ("tell me top 10 OS commands for process related forensics",
                         "i need to know all processes related native os commands for mac",
                         "which specific os command can i use to see a process by its id",
                         "what command shows me the open ports",
                         "how can i check that myself"):
            with self.subTest(question=question):
                self.assertTrue(intent_wants_a_command(question), question)

    def test_a_question_about_this_machine_is_not_mistaken_for_one(self) -> None:
        for question in ("what is running on port 8080", "list the docker containers",
                         "how much disk space is free",
                         "please tell me all the python servers running on my machine"):
            with self.subTest(question=question):
                self.assertFalse(intent_wants_a_command(question), question)


class HowToIsStillAboutThisMachineTests(unittest.TestCase):
    """Asking how to see something here was answered with no tool call at all."""

    def test_a_method_question_about_a_real_subject_is_looked_up(self) -> None:
        for question in ("how can i get the information about the process id 37359",
                         "how can i see all the connections with host 140.82.114.25"):
            with self.subTest(question=question):
                self.assertTrue(intent_asks_how_to(question))
                self.assertTrue(_looks_up_facts(question), question)

    def test_a_lesson_is_still_answered_in_words(self) -> None:
        for question in ("explain RAM versus disk",
                         "what is the difference between a process and a thread"):
            with self.subTest(question=question):
                self.assertFalse(_looks_up_facts(question), question)

    def test_a_method_question_about_nothing_here_stays_a_language_task(self) -> None:
        for question in ("how do i write a resignation letter",
                         "how do i center a div in css"):
            with self.subTest(question=question):
                self.assertFalse(_looks_up_facts(question), question)

    def test_plurals_do_not_decide_whether_to_look(self) -> None:
        # The capability table says "connection"; the question said "connections".
        self.assertTrue(_names_something_inspectable("show me the connections"))
        self.assertTrue(_names_something_inspectable("show me the connection"))


class WideningIsNotMatchingTests(unittest.TestCase):
    """Learning to widen instead of returning nothing brought the fault back.

    An empty result was stopped from authoring the answer while another tool had
    found something. Once `process.graph` returned a wider view rather than
    nothing, that view was no longer empty and started speaking first — so
    "what is my primary ip address" listed processes again.
    """

    def _answer(self) -> str:
        from tacu.companion import exact_host_answer

        return exact_host_answer("what is my primary ip address", [
            {"result": {"data": {"operation": "primary_ip", "recipe": ["/sbin/ifconfig"],
                                 "primary": {"name": "en0", "ipv4": ["10.0.0.2"]}}}},
            {"result": {"data": {"operation": "graph", "focus": "primary ip address",
                                 "count": 11, "widened": "nothing is named like that",
                                 "processes": [{"pid": 1, "label": "launchd",
                                                "role": "server"}]}}},
        ])

    def test_the_tool_that_matched_authors_the_answer(self) -> None:
        self.assertIn("en0", self._answer())

    def test_the_widened_list_does_not(self) -> None:
        self.assertNotIn("launchd", self._answer())


class SayWhatWasRunTests(unittest.TestCase):
    """TACU held the exact command and made the user ask three times for it."""

    def test_the_command_behind_an_answer_is_reported(self) -> None:
        results = [{"result": {"data": {"recipe": ["/bin/ps", "-Ao", "pid,command"]}}}]
        self.assertEqual(_recipes_used(results), ["/bin/ps -Ao pid,command"])

    def test_arguments_that_need_quoting_get_it(self) -> None:
        results = [{"result": {"data": {"recipe": ["lsof", "-nP", "-iTCP:80 -sTCP:LISTEN"]}}}]
        self.assertIn("'-iTCP:80 -sTCP:LISTEN'", _recipes_used(results)[0])

    def test_the_same_command_is_not_repeated(self) -> None:
        one = {"result": {"data": {"recipe": ["/bin/ps", "-Ao", "pid"]}}}
        self.assertEqual(len(_recipes_used([one, dict(one)])), 1)

    def test_a_result_with_no_recipe_contributes_nothing(self) -> None:
        self.assertEqual(_recipes_used([{"result": {"data": {"status": "success"}}}]), [])

    def test_a_host_answer_carries_the_command_that_produced_it(self) -> None:
        from tacu.companion import exact_host_answer

        answer = exact_host_answer("what is my primary ip address", [{"result": {"data": {
            "operation": "primary_ip", "primary": {"name": "en0", "ipv4": ["10.0.0.2"]},
            "recipe": ["/sbin/ifconfig"]}}}])
        self.assertIn("Read the same thing yourself with", answer)
        self.assertIn("/sbin/ifconfig", answer)

    def test_tacu_call_syntax_is_removed_from_an_answer(self) -> None:
        from tacu.answer_format import strip_tool_call_syntax
        from tacu.coding import ANSWER_TOOL_SURFACE

        answer = strip_tool_call_syntax(
            "Process 1 is /sbin/launchd.\n\n"
            "To run this yourself, use the following command:\n"
            "process(operation='inspect', pid=1)\n\n"
            "It is owned by root.",
            frozenset(ANSWER_TOOL_SURFACE))
        self.assertNotIn("process(operation", answer)
        self.assertNotIn("following command", answer, "the dangling lead-in goes too")
        self.assertIn("/sbin/launchd", answer)
        self.assertIn("owned by root", answer)
        self.assertNotIn("\n\n\n", answer)

    def test_a_mid_sentence_call_loses_only_that_sentence(self) -> None:
        from tacu.answer_format import strip_tool_call_syntax
        from tacu.coding import ANSWER_TOOL_SURFACE

        answer = strip_tool_call_syntax(
            "There are 3 servers. I used process(operation='graph') to find them.",
            frozenset(ANSWER_TOOL_SURFACE))
        self.assertEqual(answer, "There are 3 servers.")

    def test_code_that_merely_looks_like_a_call_survives(self) -> None:
        from tacu.answer_format import strip_tool_call_syntax
        from tacu.coding import ANSWER_TOOL_SURFACE

        answer = strip_tool_call_syntax(
            "compute_total(a=1) is defined in app.py line 4.",
            frozenset(ANSWER_TOOL_SURFACE))
        self.assertIn("compute_total(a=1)", answer)

    def test_the_lookup_lane_appends_it_in_code_not_by_asking_the_model(self) -> None:
        # Told to quote the command, gemma kept writing
        # "process(operation='inspect', pid=1)" instead. Prompt wording is not a
        # mechanism, so the lane appends the real command itself.
        from tacu.codingloop import LOOKUP_PREFIX

        self.assertIn("Never describe the tool call you", LOOKUP_PREFIX)


if __name__ == "__main__":
    unittest.main()
