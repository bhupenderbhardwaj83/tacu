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


class GhostSuggestionSafetyTests(unittest.TestCase):
    """A ghost suggestion is typed into the user's command line for them."""

    def test_history_suggestions_are_filtered_before_being_offered(self) -> None:
        # One mangled Devanagari line in ~/.zsh_history was replayed into the
        # prompt on every "ti auto ", which read as TACU emitting Hindi.
        from tacu.completion import shell_initialization

        script = shell_initialization("zsh")
        self.assertIn("_tacu_ghost_insertable()", script)
        # Both history sources are guarded, not just one.
        self.assertIn('_tacu_ghost_insertable "$cmd"', script)
        self.assertIn('_tacu_ghost_insertable "$line"', script)

    def test_the_generated_zsh_still_parses(self) -> None:
        import shutil
        import subprocess
        import tempfile

        from tacu.completion import shell_initialization

        zsh = shutil.which("zsh")
        if not zsh:
            self.skipTest("zsh not installed")
        with tempfile.NamedTemporaryFile("w", suffix=".zsh", delete=False) as handle:
            handle.write(shell_initialization("zsh"))
            path = handle.name
        result = subprocess.run([zsh, "-n", path], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

class CodingSectionTests(unittest.TestCase):
    """Coding is a lane of its own, not a memory-and-export utility."""

    def overview(self) -> str:
        from contextlib import redirect_stdout
        from io import StringIO

        from tacu.helptext import print_quick_help
        from tacu.theme import strip_ansi

        shown = StringIO()
        with redirect_stdout(shown):
            print_quick_help()
        return strip_ansi(shown.getvalue())

    def test_code_is_one_of_the_verbs_to_pick_between(self) -> None:
        body = self.overview()
        pick = body.split("PICK ONE", 1)[1].split("\n\n", 1)[0]
        self.assertIn("code", pick)
        for sibling in ("ask", "auto", "run"):
            self.assertIn(sibling, pick)

    def test_coding_has_its_own_section(self) -> None:
        body = self.overview()
        self.assertIn("CODING / SCRIPTING", body)
        coding = body.split("CODING / SCRIPTING", 1)[1].split("MEMORY / EXPORT", 1)[0]
        self.assertIn("ti code INTENT", coding)

    def test_code_is_not_filed_under_memory_and_export(self) -> None:
        body = self.overview()
        memory = body.split("MEMORY / EXPORT", 1)[1]
        self.assertNotIn("ti code INTENT", memory)

    def test_the_help_describes_what_it_now_does(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        from tacu.helptext import print_code_help
        from tacu.theme import strip_ansi

        shown = StringIO()
        with redirect_stdout(shown):
            print_code_help()
        page = strip_ansi(shown.getvalue()).casefold()
        # It starts small and steps up; it no longer refuses without the big model.
        self.assertIn("steps up", page)
        self.assertNotIn("refuses rather than", page)
        self.assertIn("one action at a time", page)

