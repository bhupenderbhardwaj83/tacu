"""Requests that ask for something to be built, rather than looked at.

Every case here is a way the harness previously dead-ended on an ordinary task:
"create a venv, make index.html the default page, and start the app" was read as
a request to launch an installed application, refused by every verb, and then
reported as done having produced nothing.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import acceptance, diagnose, routing
from tacu.automation import CommandStep, _inside, _split_compound_shell_step
from tacu.harness import planner_shortlist
from tacu.routing import capability_risk

FLASK_TASK = ("in the current working directory, please ensure that index.html page is the "
              "default page for flask application, and start that flask application after "
              "creating a virtual environment and installing requried dependencies in it")


class AppLaunchTests(unittest.TestCase):
    """A clause is not the name of an installed application."""

    def test_a_build_request_is_not_an_application_to_open(self) -> None:
        self.assertIsNone(routing.app_to_open_from_intent(FLASK_TASK))
        self.assertEqual(routing.native_steps_for_intent(FLASK_TASK, include_host_mutate=True), [])

    def test_a_real_launch_still_works(self) -> None:
        for intent, expected in (("open chrome", "chrome"),
                                 ("launch burp suite", "burp suite"),
                                 ("start docker", "docker"),
                                 ("open google chrome and launch apple.com", "google chrome")):
            with self.subTest(intent=intent):
                self.assertEqual(routing.app_to_open_from_intent(intent), expected)

    def test_a_name_is_a_name_not_a_sentence(self) -> None:
        for intent in ("start that flask application after creating a virtual environment",
                       "launch the app once the dependencies are installed",
                       "run the server after installing requirements"):
            with self.subTest(intent=intent):
                self.assertIsNone(routing.app_to_open_from_intent(intent))


class BuildRoutingTests(unittest.TestCase):
    def test_the_request_is_recognised_as_work_to_do(self) -> None:
        self.assertTrue(routing.intent_is_build_task(FLASK_TASK))
        self.assertFalse(routing.intent_is_build_task("what is my current directory"))
        self.assertFalse(routing.intent_is_build_task("is docker installed"))

    def test_a_host_fact_is_not_an_answer_to_a_build_request(self) -> None:
        # "AUTO system(cwd)" was the entire answer to this request.
        offered = {(card["tool"], card["operation"]) for card in planner_shortlist(FLASK_TASK)}
        self.assertNotIn(("system", "cwd"), offered)
        self.assertNotIn(("process", "graph"), offered)

    def test_the_planner_is_offered_tools_that_can_build(self) -> None:
        offered = {(card["tool"], card["operation"]) for card in planner_shortlist(FLASK_TASK)}
        self.assertIn(("write_file", "write"), offered)
        self.assertIn(("shell", "run"), offered)

    def test_host_questions_are_untouched(self) -> None:
        for intent, expected in (("what is my current directory", ("system", "cwd")),
                                 ("is docker installed", ("application", "find")),
                                 ("show me docker containers", ("docker", "ps"))):
            with self.subTest(intent=intent):
                offered = [(card["tool"], card["operation"]) for card in planner_shortlist(intent)]
                self.assertIn(expected, offered)


class DependencyInferenceTests(unittest.TestCase):
    """"Install the required dependencies" names nothing; read the project."""

    def test_installing_is_an_install_request(self) -> None:
        self.assertTrue(diagnose._INSTALL_REQUEST.search("installing the dependencies"))

    def test_the_framework_comes_from_the_request(self) -> None:
        self.assertEqual(diagnose.framework_from_intent(FLASK_TASK), "flask")
        self.assertEqual(
            diagnose.framework_from_intent("set up this django project"), "django")
        # "a python application" names a language, not a package.
        self.assertEqual(diagnose.framework_from_intent("start the python application"), "")

    def test_a_requirements_file_outranks_a_guess(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "requirements.txt").write_text("flask\n", encoding="utf-8")
            args = [step["inputs"]["args"] for step in diagnose.setup_steps(FLASK_TASK, workspace)]
            self.assertTrue(any("-r" in item and "requirements.txt" in item for item in args), args)

    def test_without_one_the_named_framework_is_installed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            steps = diagnose.setup_steps(FLASK_TASK, Path(directory))
            joined = " ".join(" ".join(step["inputs"]["args"]) for step in steps)
            self.assertIn("venv", joined)
            self.assertIn("flask", joined)

    def test_named_packages_still_win(self) -> None:
        self.assertEqual(diagnose._packages_from("install flask and gunicorn"),
                         ["flask", "gunicorn"])


class WorkspaceContainmentTests(unittest.TestCase):
    def test_a_venv_binary_is_inside_the_workspace(self) -> None:
        # bin/python is a symlink to the interpreter that built the venv, so
        # resolving it lands in /usr and the project's own file read as outside.
        workspace = Path("/tmp/project")
        self.assertTrue(_inside(workspace / ".venv" / "bin" / "python", workspace))
        self.assertTrue(_inside(workspace / "app.py", workspace))

    def test_traversal_is_still_refused(self) -> None:
        workspace = Path("/tmp/project")
        for escape in ("../../.ssh/id_rsa", "../../../etc/passwd"):
            with self.subTest(escape=escape):
                self.assertFalse(_inside(workspace / escape, workspace))
        self.assertFalse(_inside(Path("/etc/shadow"), workspace))


class CompoundCommandTests(unittest.TestCase):
    def test_several_commands_in_one_string_become_several_steps(self) -> None:
        # bash read the whole string as a file name and exited 127.
        step = CommandStep("bash", ("--", "python3 -m venv venv && ./venv/bin/pip install -r requirements.txt"),
                           ".", "set up")
        produced = _split_compound_shell_step(step)
        self.assertEqual([item.executable for item in produced],
                         ["python3", "./venv/bin/pip"])

    def test_a_single_command_is_left_alone(self) -> None:
        step = CommandStep("bash", ("--", "ls -la"), ".", "list")
        self.assertEqual(_split_compound_shell_step(step), [step])

    def test_a_non_shell_step_is_left_alone(self) -> None:
        step = CommandStep("python3", ("-m", "venv", ".venv"), ".", "venv")
        self.assertEqual(_split_compound_shell_step(step), [step])


class AcceptanceTests(unittest.TestCase):
    def test_ensure_is_a_claim_like_create(self) -> None:
        claims = [item.describes for item in acceptance.criteria_for(FLASK_TASK)]
        self.assertIn("index.html exists", claims)

    def test_an_unmet_claim_is_reported_rather_than_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = acceptance.unmet(acceptance.criteria_for(FLASK_TASK), Path(directory))
            self.assertTrue(any("index.html exists" in item[0].describes for item in missing))


class ApprovalTests(unittest.TestCase):
    """Looking needs no review; launching does — and must stay possible."""

    def test_reading_is_read_and_launching_is_not(self) -> None:
        self.assertEqual(capability_risk("application", "find"), "read")
        self.assertEqual(capability_risk("filesystem", "list"), "read")
        self.assertNotEqual(capability_risk("application", "open"), "read")

    def test_an_unknown_step_is_never_assumed_safe(self) -> None:
        self.assertNotEqual(capability_risk("nonexistent", "whatever"), "read")


if __name__ == "__main__":
    unittest.main()
