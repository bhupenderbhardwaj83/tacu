"""Ghost history ranking and help-catalog smoke tests."""

from __future__ import annotations

import argparse
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, completion, ghost_history
from tacu.theme import strip_ansi


class GhostHistoryTests(unittest.TestCase):
    def test_records_and_ranks_by_prefix_and_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            ghost_history.record_successful_command(["auto", "which", "process", "is", "consuming", "most", "CPU"], cwd="/a")
            ghost_history.record_successful_command(["auto", "top", "tcp", "443"], cwd="/b")
            ghost_history.record_successful_command(["auto", "which", "process", "is", "consuming", "most", "CPU"], cwd="/b")
            hits = ghost_history.suggest_from_history("ti auto which", cwd="/b")
            self.assertTrue(hits)
            self.assertTrue(hits[0].startswith("ti auto which process"))

    def test_ghost_suggest_cli_prints_history_hit(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": directory}):
            ghost_history.record_successful_command(["tools", "map", ".", "--depth", "3"])
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(["__ghost-suggest", "--", "ti tools map"]), 0)
            self.assertIn("ti tools map . --depth 3", output.getvalue())

    def test_zsh_ghost_declares_layered_pipeline(self) -> None:
        script = completion.zsh_ghost()
        self.assertIn("_tacu_ghost_structural", script)
        self.assertIn("_tacu_ghost_from_history", script)
        self.assertIn("_tacu_ghost_semantic", script)
        self.assertIn("_tacu_ghost_model_async", script)
        self.assertIn("suffix:fg=244", script)
        self.assertIn("TACU_GHOST_SUPPRESS_KEY", script)
        self.assertIn("_tacu_reject_ghost", script)
        self.assertIn("TACU_GHOST_MODEL", script)
        self.assertIn("TACU_GHOST_LAST_KEY", script)
        # Exact action tokens must fall through to NEXT (ghost next args).
        self.assertIn('if [[ -n "$suffix" ]]; then', script)


class HelpCatalogTests(unittest.TestCase):
    def test_quick_help_uses_when_does_how_and_footer_boxes(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main(["help"]), 0)
        plain = strip_ansi(output.getvalue())
        self.assertIn("PICK ONE", plain)
        self.assertIn("PROGRESSIVE HELP", plain)
        self.assertIn("GHOST + TAB", plain)
        self.assertIn("ti help tools", plain)
        self.assertIn("FINDINGS", plain)
        self.assertIn("ti juicy", plain)
        self.assertIn("ti extract juicy", plain)
        self.assertIn("ti docker", plain)
        self.assertIn("ti syntax", plain)

    def test_quick_help_names_every_first_class_command(self) -> None:
        from tacu.helptext import OVERVIEW_COMMANDS

        root = cli.parser()
        subparsers = next(
            action for action in root._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        groups: dict[int, list[str]] = {}
        order: list[int] = []
        for name, command_parser in subparsers.choices.items():
            key = id(command_parser)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(name)
        canonical = {groups[key][0] for key in order}
        self.assertEqual(canonical, set(OVERVIEW_COMMANDS))

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(cli.main(["help"]), 0)
        plain = strip_ansi(output.getvalue()).casefold()
        for name in OVERVIEW_COMMANDS:
            self.assertIn(f"ti {name}", plain, f"ti help overview is missing {name!r}")

        for topic in OVERVIEW_COMMANDS:
            page = io.StringIO()
            with redirect_stdout(page):
                self.assertEqual(cli.main(["help", topic]), 0)
            topic_help = strip_ansi(page.getvalue())
            self.assertTrue(topic_help.strip(), f"ti help {topic} is empty")
            self.assertIn("Shape:", topic_help, f"ti help {topic} does not use dense help")
            self.assertIn("|  e.g. ", topic_help, f"ti help {topic} has no runnable example")


if __name__ == "__main__":
    unittest.main()
