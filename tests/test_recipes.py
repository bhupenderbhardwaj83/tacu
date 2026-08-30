"""Command/recipe memory tests."""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli
from tacu.recipes import (
    RecipeStore,
    index_intent_results,
    pasteable_from_intent_entry,
    seed_platform_recipes,
)


class RecipeStoreTests(unittest.TestCase):
    def test_upsert_search_and_seed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RecipeStore(Path(directory) / "recipes.db")
            first = store.upsert(
                tool="process",
                operation="top_cpu",
                argv=["/bin/ps", "-Ao", "pid,command"],
                purpose="List processes",
                labels="cpu process",
                intent="top cpu",
                source="auto",
                os_name="macos",
                ps_flavour="bsd",
            )
            again = store.upsert(
                tool="process",
                operation="top_cpu",
                argv=["/bin/ps", "-Ao", "pid,command"],
                purpose="List processes",
                labels="cpu process",
                intent="top cpu again",
                source="auto",
                os_name="macos",
                ps_flavour="bsd",
            )
            self.assertEqual(first.id, again.id)
            self.assertEqual(again.hit_count, 2)
            found = store.search("cpu", os_name="macos")
            self.assertEqual([item.id for item in found], [first.id])
            self.assertIn("ps", again.paste)

    def test_pasteable_from_intent_prefers_recipe_field(self) -> None:
        entry = {
            "purpose": "Rank processes by CPU",
            "command": ["process", "top_cpu"],
            "result": {
                "ok": True,
                "tool": "process",
                "data": {
                    "operation": "top_cpu",
                    "recipe": ["/bin/ps", "-Ao", "pid,%cpu,command"],
                },
            },
        }
        extracted = pasteable_from_intent_entry(entry)
        assert extracted is not None
        self.assertEqual(extracted["tool"], "process")
        self.assertEqual(extracted["operation"], "top_cpu")
        self.assertEqual(extracted["argv"][0], "/bin/ps")

    def test_index_intent_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RecipeStore(Path(directory) / "recipes.db")
            results = [{
                "purpose": "Listening TCP",
                "command": ["network", "listen"],
                "result": {
                    "ok": True,
                    "tool": "network",
                    "data": {
                        "operation": "listen",
                        "recipe": ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
                    },
                },
            }]
            indexed = index_intent_results(store, "listening ports", results, source="auto")
            self.assertEqual(len(indexed), 1)
            self.assertEqual(indexed[0].capability, "network.listen")

    def test_seed_platform_recipes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = RecipeStore(Path(directory) / "recipes.db")
            added = seed_platform_recipes(store)
            self.assertGreaterEqual(added, 3)
            self.assertGreaterEqual(store.count(), 3)


class SyntaxCliTests(unittest.TestCase):
    def test_syntax_list_search_and_copy_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            output = io.StringIO()
            with patch.object(cli, "app_home", return_value=home), \
                 patch.object(cli.subprocess, "run") as run, \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["syntax", "seed"]), 0)
                self.assertEqual(cli.main(["syntax", "search", "cpu"]), 0)
                self.assertEqual(cli.main(["copy", "--command", "cpu"]), 0)
            rendered = output.getvalue()
            self.assertIn("process.top_cpu", rendered)
            self.assertIn("OS clipboard ← recipe #", rendered)
            self.assertTrue(run.called)
            pasted = run.call_args.kwargs.get("input") or b""
            self.assertTrue(
                pasted.startswith(b"/bin/ps")
                or pasted.startswith(b"ps")
                or b"tasklist" in pasted,
                msg=f"unexpected paste payload: {pasted!r}",
            )


if __name__ == "__main__":
    unittest.main()
