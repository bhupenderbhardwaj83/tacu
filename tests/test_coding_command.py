"""Coding startup and live output, exercised through the real CLI entry point."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, coding
from tacu.providers import OllamaProvider
from tacu.theme import strip_ansi
from tacu.tools.contracts import ToolResult


class TTY(io.StringIO):
    def isatty(self):
        return True


class CodingCommandTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.stack.enter_context(patch.dict(os.environ, {
            "TACU_HOME": self.directory, "TACU_MODEL": "gemma4:12b-mlx",
            "TACU_PROVIDER": "ollama", "TACU_OLLAMA_URL": "http://127.0.0.1:11434",
            "TERM": "xterm", "TACU_NO_PAGER": "", "TACU_PAGE_SIZE": "2",
        }))
        for key in ("TACU_CODING_MODEL", "TACU_NUM_CTX", "TACU_NUM_PREDICT"):
            os.environ.pop(key, None)
        self.stack.enter_context(patch.object(cli, "migrate_legacy_home", return_value=None))
        self.stack.enter_context(patch.object(cli, "configured_model", return_value="saved-chat"))
        self.release = self.stack.enter_context(
            patch.object(coding, "release_other_models", return_value=[]))

    def startup(self, words):
        output = io.StringIO()
        with redirect_stdout(output), \
                patch.object(cli, "load_provider", wraps=cli.load_provider) as loaded, \
                patch.object(cli, "handle_coding_command", return_value=0) as run:
            status = cli.main(words)
        return status, loaded, run, strip_ansi(output.getvalue())

    def test_code_and_aliases_construct_only_qwen_with_one_hundred_actions(self):
        for command in ("code", "script", "build"):
            with self.subTest(command=command):
                status, loaded, run, output = self.startup([command, "fix", "tests"])
                self.assertEqual(status, 0)
                loaded.assert_called_once()
                arguments, client = run.call_args.args
                self.assertEqual(client.model, "qwen3.8:27b-mlx")
                self.assertEqual(arguments.max_steps, 100)
                self.assertEqual(arguments.escalate_to, "")
                self.assertEqual(client.num_predict, 4096)
                self.assertEqual(client.num_ctx, 16384)
                self.assertIn("100 step budget", output)
                self.assertNotIn("steps up", output)
                self.release.assert_called_with("qwen3.8:27b-mlx")

    def test_follow_up_starts_on_qwen_again(self):
        for goal in ("fix the tests", "complete the outstanding task"):
            status, _, run, _ = self.startup(["code", goal])
            self.assertEqual(status, 0)
            self.assertEqual(run.call_args.args[1].model, coding.CODING_MODEL)

    def test_coding_model_override_and_explicit_cli_precedence(self):
        with patch.dict(os.environ, {"TACU_CODING_MODEL": "custom-coder"}):
            for words, expected in ((["code", "fix"], "custom-coder"),
                                    (["--model", "chosen", "code", "fix"], "chosen"),
                                    (["--model=gemma4:12b-mlx", "code", "fix"], "gemma4:12b-mlx")):
                with self.subTest(words=words):
                    status, _, run, _ = self.startup(words)
                    self.assertEqual(status, 0)
                    self.assertEqual(run.call_args.args[1].model, expected)
        with patch.dict(os.environ, {"TACU_CODING_MODEL": "   "}):
            _, _, run, _ = self.startup(["code", "fix"])
            self.assertEqual(run.call_args.args[1].model, coding.CODING_MODEL)

    def test_coding_options_do_not_leak_into_later_chat_providers(self):
        self.startup(["code", "fix"])
        ordinary = OllamaProvider("http://127.0.0.1:11434", "chat")
        self.assertEqual(ordinary.num_predict, 1024)
        self.assertEqual(ordinary.num_ctx, 8192)
        with patch.dict(os.environ, {"TACU_NUM_PREDICT": "2048", "TACU_NUM_CTX": "32768"}):
            _, _, run, _ = self.startup(["code", "fix"])
            client = run.call_args.args[1]
            self.assertEqual((client.num_predict, client.num_ctx), (2048, 32768))
            self.assertEqual(os.environ["TACU_NUM_CTX"], "32768")

    def test_client_failure_restores_coding_environment(self):
        with patch.object(cli, "load_provider", side_effect=cli.TacuError("offline")), \
                patch("sys.stderr", io.StringIO()):
            self.assertEqual(cli.main(["code", "fix"]), 1)
        self.assertNotIn("TACU_NUM_PREDICT", os.environ)
        self.assertNotIn("TACU_NUM_CTX", os.environ)
        self.release.assert_not_called()

    def test_step_limits_are_validated_before_a_provider_is_constructed(self):
        for limit in (0, -1, 101):
            with self.subTest(limit=limit), patch("sys.stderr", io.StringIO()) as error:
                status, loaded, run, _ = self.startup(["code", "--max-steps", str(limit), "fix"])
                self.assertEqual(status, 1)
                loaded.assert_not_called()
                run.assert_not_called()
                self.assertIn("between 1 and 100", error.getvalue())
        for limit in (1, 20, 40, 100):
            status, _, run, _ = self.startup(["code", "--max-steps", str(limit), "fix"])
            self.assertEqual(status, 0)
            self.assertEqual(run.call_args.args[0].max_steps, limit)

    def test_keep_models_and_dry_run_do_not_unload(self):
        for flag in ("--keep-models", "--dry-run"):
            self.assertEqual(self.startup(["code", flag, "fix"])[0], 0)
        self.release.assert_not_called()

    def test_remote_provider_does_not_unload_local_models(self):
        self.assertEqual(self.startup(["--url", "http://192.0.2.1:11434", "code", "fix"])[0], 0)
        self.release.assert_not_called()

    def test_ordinary_workflow_models_and_budgets_are_unchanged(self):
        for command in ("ask", "do", "auto"):
            arguments = cli.parser().parse_args([command, "look"])
            self.assertEqual(arguments.model, "gemma4:12b-mlx")
        self.assertEqual(cli.parser().parse_args(["do", "look"]).max_steps, 3)
        self.assertEqual(cli.parser().parse_args(["auto", "look"]).max_steps, cli.MAX_AUTONOMOUS_STEPS)
        self.assertEqual(cli.LOOKUP_STEPS, 8)

    def test_twenty_live_actions_finish_without_a_pager_key(self):
        class Reader:
            model = coding.CODING_MODEL
            turns = 0

            def chat_tools(self, messages, tools):
                self.turns += 1
                if self.turns <= 20:
                    return {"tool_calls": [{"name": "read_file", "arguments": {"path": f"app{self.turns}.py"}}]}
                return {"content": "Inspection complete.", "tool_calls": []}

        for command in ("code", "script", "build"):
            with self.subTest(command=command):
                output, error = TTY(), io.StringIO()
                result = ToolResult("test", "read_file", True, {"content": "source"}, None, 0)
                with patch("sys.stdout", output), patch("sys.stdin", TTY()), \
                        patch("sys.stderr", error), \
                        patch("tacu.pager.default_read_key", side_effect=AssertionError("paused a live job")), \
                        patch.object(cli, "load_provider", return_value=Reader()), \
                        patch.object(cli, "invoke_tool", return_value=result):
                    self.assertEqual(cli.main([command, "--workspace", self.directory, "inspect"]), 0)
                self.assertEqual(output.getvalue().count(" read_file("), 20)
                self.assertIn("Inspection complete.", output.getvalue())
                self.assertNotIn("── more ──", error.getvalue())

    def test_help_dry_run_and_ordinary_output_still_page(self):
        for words in (["help"], ["help", "code"], ["code", "--help"],
                      ["script", "--help"], ["build", "--help"], ["tools", "list"],
                      ["code", "--dry-run", "--workspace", self.directory, "fix"]):
            with self.subTest(words=words):
                output, error = TTY(), io.StringIO()
                with patch("sys.stdout", output), patch("sys.stdin", TTY()), \
                        patch("sys.stderr", error), \
                        patch("tacu.pager.default_read_key", return_value=" ") as key:
                    self.assertEqual(cli.main(words), 0)
                self.assertGreater(key.call_count, 0)
                self.assertIn("── more ──", error.getvalue())
        self.release.assert_not_called()

    def test_failed_live_run_restores_paging_for_the_next_command(self):
        output, error = TTY(), io.StringIO()
        with patch("sys.stdout", output), patch("sys.stdin", TTY()), \
                patch("sys.stderr", error), \
                patch("tacu.pager.default_read_key", return_value=" ") as key:
            with patch.object(cli, "handle_coding_command", side_effect=cli.TacuError("model offline")):
                self.assertEqual(cli.main(["code", "fix"]), 1)
            key.assert_not_called()
            self.assertIs(sys.stdout, output)
            self.assertEqual(cli.main(["help", "code"]), 0)
            self.assertGreater(key.call_count, 0)


if __name__ == "__main__":
    unittest.main()
