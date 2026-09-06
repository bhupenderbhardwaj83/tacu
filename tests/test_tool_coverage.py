"""Git, Docker and Ollama must be reachable in plain language, and ti code must
never quietly plan with the small model.

The expectation these lock down: anything you would drop to the native CLI for
should be answerable through ti ask / ti auto / ti do, without naming the tool.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import coding, routing
from tacu.routing import CAPABILITIES, native_steps_for_intent


def route(intent: str) -> list[tuple[str, str]]:
    return [(step["tool"], step["operation"])
            for step in native_steps_for_intent(intent, include_host_mutate=True)]


def operations(tool: str) -> set[str]:
    return {item.operation for item in CAPABILITIES if item.tool == tool}


class CatalogCoverageTests(unittest.TestCase):
    """Every operation a tool implements has a way in."""

    def test_every_tool_operation_is_reachable_from_the_catalog(self) -> None:
        from tacu.tools import specs

        missing: list[str] = []
        for spec in specs():
            if spec.name not in {"git", "docker", "ollama"}:
                continue
            declared = spec.input_schema["properties"]["operation"]["enum"]
            for operation in declared:
                if operation not in operations(spec.name):
                    missing.append(f"{spec.name}.{operation}")
        self.assertEqual(missing, [])

    def test_the_daily_git_operations_exist(self) -> None:
        for operation in ("pull", "fetch", "clone", "checkout", "merge", "reset",
                          "revert", "restore", "stash", "stash_pop", "tag",
                          "show", "blame", "config", "tags", "stashes"):
            with self.subTest(operation=operation):
                self.assertIn(operation, operations("git"))

    def test_the_daily_docker_operations_exist(self) -> None:
        for operation in ("restart", "kill", "pause", "unpause", "prune", "exec",
                          "info", "version", "disk_usage", "top", "port"):
            with self.subTest(operation=operation):
                self.assertIn(operation, operations("docker"))


class PlainLanguageRoutingTests(unittest.TestCase):
    """The tool's own words are evidence; naming the tool is not required."""

    CASES = (
        ("who wrote this file", ("git", "blame")),
        ("what is staged for commit", ("git", "diff_staged")),
        ("who contributed to this repo", ("git", "shortlog")),
        ("how many commits am i ahead of origin", ("git", "ahead_behind")),
        ("show me my git settings", ("git", "config")),
        ("list the git tags", ("git", "tags")),
        ("stash my changes", ("git", "stash")),
        ("pull the latest from origin", ("git", "pull")),
        ("checkout the main branch", ("git", "checkout")),
        ("merge the feature branch", ("git", "merge")),
        ("revert that commit", ("git", "revert")),
        ("clone the repo", ("git", "clone")),
        ("discard my changes", ("git", "restore")),
        ("how much space is docker using", ("docker", "disk_usage")),
        ("show me docker settings", ("docker", "info")),
        ("which docker version am i on", ("docker", "version")),
        ("what ports does the container expose", ("docker", "port")),
        ("restart the container named api", ("docker", "restart")),
        ("clean up docker space", ("docker", "prune")),
        ("what is my current default ollama model keepalive", ("ollama", "settings")),
        ("show me ollama settings", ("ollama", "settings")),
        ("what is my ollama context window", ("ollama", "settings")),
        ("which ollama version", ("ollama", "version")),
        ("what models are installed", ("ollama", "installed_models")),
    )

    def test_each_request_reaches_its_tool(self) -> None:
        for intent, expected in self.CASES:
            with self.subTest(intent=intent):
                self.assertIn(expected, route(intent), route(intent))

    def test_restart_is_not_read_as_start(self) -> None:
        # "restart" contains "start"; matching it as a substring answered a
        # restart request with docker.start.
        self.assertIn(("docker", "restart"), route("restart the container named api"))
        self.assertIn(("docker", "stop"), route("stop the container named api"))

    def test_unrelated_mutations_do_not_win_by_default(self) -> None:
        # Every host mutation used to be given a score floor, so they all tied.
        self.assertNotIn(("process", "kill"), route("checkout the main branch"))
        self.assertIn(("process", "kill"), route("kill process 4312"))


class SettingsVisibilityTests(unittest.TestCase):
    """Settings must be viewable, and a value that never applies must be named."""

    def test_the_ollama_settings_answer_names_the_conflict(self) -> None:
        import os
        import tempfile
        from unittest.mock import patch

        from tacu.tools import ToolContext, invoke

        with tempfile.TemporaryDirectory() as state, \
                patch.dict(os.environ, {"OLLAMA_KEEP_ALIVE": "60m"}):
            data = invoke("ollama", {"operation": "settings"},
                          ToolContext(Path.cwd(), Path(state))).data or {}
        conflicts = data.get("conflicts") or []
        self.assertTrue(conflicts, "a 60m environment against TACU's own value is a conflict")
        clash = conflicts[0]
        self.assertEqual(clash["environment"], "60m")
        self.assertNotEqual(clash["wins"], "60m")

    def test_the_rendered_answer_says_which_value_applies(self) -> None:
        from tacu.companion import _ollama_settings_answer

        payload = {
            "environment": [{"variable": "OLLAMA_KEEP_ALIVE", "value": "60m",
                             "purpose": "how long a model stays loaded",
                             "in_effect": "60m", "set": True}],
            "tacu_request_options": {"keep_alive": "15m"},
            "active_model": "gemma4:12b-mlx",
            "conflicts": [{"setting": "keep_alive", "environment": "60m",
                           "tacu_sends": "15m", "wins": "15m", "why": "the request wins"}],
        }
        answer = "\n".join(_ollama_settings_answer("what is my keepalive", payload))
        self.assertIn("60m", answer)
        self.assertIn("15m", answer)
        self.assertIn("applies", answer)


class CodingProfileTests(unittest.TestCase):
    def test_a_missing_model_is_refused_with_the_command_that_fixes_it(self) -> None:
        message = coding.missing_model_message("qwen3.8:27b-mlx")
        self.assertIn("ollama pull qwen3.8:27b-mlx", message)
        self.assertIn("TACU_CODING_MODEL", message)

    def test_a_bare_name_matches_its_tagged_model(self) -> None:
        available = ["qwen3.8:27b-mlx", "gemma4:12b-mlx"]
        self.assertTrue(coding.model_is_installed("qwen3.8:27b-mlx", available))
        self.assertTrue(coding.model_is_installed("qwen3.8", available))
        self.assertFalse(coding.model_is_installed("llama9:70b", available))

    def test_the_profile_raises_the_budgets_the_small_model_did_not_need(self) -> None:
        self.assertGreater(coding.PROFILE.num_predict, 1024)
        self.assertGreater(coding.PROFILE.cognitive_turns, 3)
        self.assertLessEqual(coding.PROFILE.max_steps, coding.MAX_CODING_STEPS)

    def test_the_model_in_use_is_never_unloaded(self) -> None:
        from unittest.mock import patch

        with patch.object(coding, "which", return_value="/usr/bin/ollama"), \
             patch.object(coding, "loaded_models",
                          return_value=["qwen3.8:27b-mlx", "gemma4:12b-mlx"]), \
             patch.object(coding, "run_argv", return_value={"exit_code": 0, "stdout": "", "stderr": ""}):
            released = coding.release_other_models("qwen3.8:27b-mlx")
        self.assertEqual(released, ["gemma4:12b-mlx"])

    def test_nothing_is_unloaded_when_nothing_is_loaded(self) -> None:
        from unittest.mock import patch

        with patch.object(coding, "which", return_value="/usr/bin/ollama"), \
             patch.object(coding, "loaded_models", return_value=[]):
            self.assertEqual(coding.release_other_models("qwen3.8:27b-mlx"), [])


if __name__ == "__main__":
    unittest.main()
