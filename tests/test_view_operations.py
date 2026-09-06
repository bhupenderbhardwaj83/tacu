"""Plain view questions: which application, which version, what is in here.

Looking at your own machine is the thing TACU is for. These questions must reach
a native tool without the caller having to guess the catalog's phrasing, must
read the same under ask, auto and do, and must answer the question that was
asked rather than dumping every fact the tool returned.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu.companion import _application_answer, _merge_app_results, _storage_headline
from tacu.harness import critique_goal
from tacu.routing import (
    intent_is_application_query, intent_is_view_question, native_steps_for_intent,
    _app_name_from_intent,
)

FALCON = {
    "path": "/Applications/Falcon.app", "name": "Falcon", "display_name": "Falcon",
    "version": "7.37", "build": "7.37", "bundle_id": "com.crowdstrike.falcon.App",
    "fs_creation_date": "2026-05-06 23:27:53 +0000",
    "date_added": "2026-08-19 16:52:10 +0000",
}


def tools(intent: str) -> list[tuple[str, str]]:
    return [(step["tool"], step["operation"]) for step in native_steps_for_intent(intent)]


class ApplicationQuestionTests(unittest.TestCase):
    def test_installed_question_about_a_tool_name_reaches_the_application_catalog(self):
        # "docker" names a desktop app here, not the container catalog.
        for intent in ("is docker installed", "where is Docker installed",
                       "what is the full path of Docker", "what version of docker do i have"):
            with self.subTest(intent=intent):
                self.assertIn(("application", "find"), tools(intent) + tools(intent))

    def test_docker_catalog_questions_still_go_to_docker(self):
        self.assertEqual(tools("show me docker containers"), [("docker", "ps")])

    def test_application_answer_is_not_sent_back_for_replanning(self):
        results = [{"result": {"tool": "application", "data": {
            "operation": "find", "query": "docker", "applications": [FALCON]}}}]
        self.assertIsNone(critique_goal("is docker installed", results))

    def test_words_that_are_not_application_names_are_rejected(self):
        for intent in ("what operating system version am i running",
                       "what is the path of this directory",
                       "show me the path to my downloads folder"):
            with self.subTest(intent=intent):
                self.assertIsNone(_app_name_from_intent(intent))
        # A folder search names something, but it is not an application question.
        for intent in ("find the folder named myness on this computer",
                       "what is the path of this directory"):
            with self.subTest(intent=intent):
                self.assertFalse(intent_is_application_query(intent))
                self.assertFalse(any(step["tool"] == "application"
                                     for step in native_steps_for_intent(intent)))

    def test_os_version_question_is_answered_by_the_system_tool(self):
        self.assertEqual(tools("what operating system version am i running"),
                         [("system", "os_version")])


class ApplicationAnswerTests(unittest.TestCase):
    def merged(self) -> dict:
        return _merge_app_results([
            {"applications": [FALCON], "did_you_mean": None},
            {"applications": [dict(FALCON, version=None)], "did_you_mean": None},
        ])

    def test_repeated_lookups_of_one_app_produce_one_statement(self):
        merged = self.merged()
        self.assertEqual(len(merged["applications"]), 1)
        lines = _application_answer("is falcon installed", "falcon", merged)
        self.assertEqual(lines[0], "Yes — Falcon is installed.")
        self.assertEqual(sum(1 for line in lines if line.startswith("Path:")), 1)

    def test_each_question_shape_leads_with_what_it_asked_for(self):
        merged = self.merged()
        self.assertTrue(_application_answer("what is the version of falcon", "falcon", merged)[0]
                        .startswith("Falcon version 7.37"))
        self.assertTrue(_application_answer("when was falcon installed", "falcon", merged)[0]
                        .startswith("Falcon was installed on this machine on 2026-05-06"))
        self.assertTrue(_application_answer("where is falcon installed", "falcon", merged)[0]
                        .startswith("Falcon is installed at"))

    def test_a_typo_is_answered_with_the_closest_installed_name(self):
        lines = _application_answer("is flacon installed", "flacon",
                                    {"applications": [], "did_you_mean": ["Falcon"]})
        self.assertIn("Did you mean: Falcon?", lines[0])


class ViewQuestionRoutingTests(unittest.TestCase):
    def test_a_question_phrased_in_the_users_own_words_still_finds_the_tool(self):
        for intent in ("what files are in this directory",
                       "show me the directory structure of this folder",
                       "what is in this folder"):
            with self.subTest(intent=intent):
                self.assertEqual(tools(intent), [("filesystem", "list")])

    def test_uptime_asked_in_any_wording(self):
        self.assertEqual(tools("what is the uptime of this machine"), [("system", "uptime")])

    def test_a_named_folder_is_listed_rather_than_the_working_directory(self):
        steps = native_steps_for_intent("list the contents of my downloads folder")
        self.assertEqual(steps[0]["inputs"]["root"], str(Path.home() / "Downloads"))

    def test_the_fallback_does_not_hijack_unrelated_requests(self):
        # One shared word is not evidence: this is not a request to list a directory.
        self.assertEqual(tools("list the widget inventory"), [])
        self.assertFalse(intent_is_view_question(
            'replace "print(num1)" with "print(num1 * 2)" in program.py'))

    def test_a_listing_is_not_truncated_to_a_handful(self):
        steps = native_steps_for_intent("what files are in this directory")
        self.assertGreaterEqual(steps[0]["inputs"]["limit"], 200)


class StorageAnswerTests(unittest.TestCase):
    def test_a_disk_question_is_answered_with_the_number_not_the_table(self):
        rows = [
            "Filesystem        Size    Used   Avail Capacity iused ifree %iused  Mounted on",
            "/dev/disk3s1s1   460Gi    12Gi    33Gi    27%    459k  342M    0%   /",
            "devfs             360Ki  360Ki     0Bi   100%    1.2k     0  100%   /dev",
        ]
        self.assertEqual(_storage_headline(rows),
                         "33Gi free of 460Gi on the startup disk (12Gi used, 27% full).")


class LanguageDriftTests(unittest.TestCase):
    """A local multilingual model sometimes finishes an English answer in
    another script. The harness catches that rather than showing it."""

    def test_a_stray_script_is_caught_and_retried(self):
        from tacu.loop import answer_language_drifted, answer_needs_refine

        drift = answer_language_drifted("is docker installed",
                                        "Yes, Docker is installed. यह स्थापित है।")
        self.assertIsNotNone(drift)
        self.assertIn("Devanagari", drift)
        self.assertIsNotNone(answer_needs_refine("what ports are open",
                                                 "Port 8080 is open 端口已打开"))

    def test_an_english_answer_is_left_alone(self):
        from tacu.loop import answer_language_drifted

        self.assertIsNone(answer_language_drifted("is docker installed",
                                                  "Yes, Docker is installed."))

    def test_asking_for_another_language_is_not_drift(self):
        from tacu.loop import answer_language_drifted

        self.assertIsNone(answer_language_drifted("translate this to hindi: hello",
                                                  "नमस्ते"))


if __name__ == "__main__":
    unittest.main()
