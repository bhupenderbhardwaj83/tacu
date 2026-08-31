"""Clipboard tray tests."""

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
from tacu.clipboard import CLIP_LIMIT, ClipStore


class ClipStoreTests(unittest.TestCase):
    def test_crud_search_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ClipStore(Path(directory) / "clipboard.db")
            first = store.add("kubectl get pods -A", label="k8s pods", source="manual")
            second = store.add("brew upgrade", source="cli")
            self.assertEqual(first.id, 1)
            self.assertEqual(store.count(), 2)
            self.assertEqual(store.get(1).label, "k8s pods")
            updated = store.update(2, body="brew upgrade --greedy", label="brew")
            self.assertEqual(updated.body, "brew upgrade --greedy")
            found = store.search("brew")
            self.assertEqual([item.id for item in found], [2])
            self.assertTrue(store.delete(1))
            self.assertEqual(store.count(), 1)
            for index in range(CLIP_LIMIT + 5):
                store.add(f"item {index}")
            self.assertEqual(store.count(), CLIP_LIMIT)
            store.clear()
            self.assertEqual(store.count(), 0)
            again = store.add("nmap -sC 192.168.1.1")
            self.assertEqual(again.id, 1, "empty tray must restart numbering at #1")

    def test_clear_restarts_numbering_from_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ClipStore(Path(directory) / "clipboard.db")
            for index in range(9):
                store.add(f"item {index}")
            self.assertEqual(store.count(), 9)
            self.assertEqual(store.clear(), 9)
            fresh = store.add("nmap -sC 192.168.1.1")
            self.assertEqual(fresh.id, 1)
            self.assertEqual(store.list()[0].id, 1)

    def test_deleting_last_item_restarts_numbering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ClipStore(Path(directory) / "clipboard.db")
            store.add("one")
            store.add("two")
            store.delete(1)
            store.delete(2)
            self.assertEqual(store.count(), 0)
            fresh = store.add("fresh")
            self.assertEqual(fresh.id, 1)


class ClipCliTests(unittest.TestCase):
    def test_edit_body_refreshes_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ClipStore(Path(directory) / "clipboard.db")
            item = store.add("2 This is 2nd item in the clip")
            self.assertEqual(item.label, "2 This is 2nd item in the clip")
            updated = store.update(item.id, body="This is the 3rd item in the clipboard")
            self.assertEqual(updated.body, "This is the 3rd item in the clipboard")
            self.assertEqual(updated.label, "This is the 3rd item in the clipboard")
            renamed = store.update(item.id, label="short")
            self.assertEqual(renamed.label, "short")
            self.assertEqual(renamed.body, "This is the 3rd item in the clipboard")

    def test_clip_edit_cli_refreshes_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            output = io.StringIO()
            with patch.object(cli, "app_home", return_value=home), redirect_stdout(output):
                self.assertEqual(cli.main(["clip", "add", "2 This is 2nd item in the clip"]), 0)
                self.assertEqual(
                    cli.main(["clip", "edit", "1", "This is the 3rd item in the clipboard"]),
                    0,
                )
                self.assertEqual(cli.main(["clip", "list"]), 0)
            rendered = output.getvalue()
            self.assertIn("Updated tray #1 · This is the 3rd item in the clipboard", rendered)
            self.assertIn("This is the 3rd item in the clipboard", rendered)
            self.assertNotIn("2 This is 2nd item in the clip", rendered.split("Updated", 1)[-1])

    def test_clip_add_list_and_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            output = io.StringIO()
            with patch.object(cli, "app_home", return_value=home), \
                 patch.object(cli, "_clipboard_command", return_value=["pbcopy"]), \
                 patch.object(cli.subprocess, "run") as run, \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["clip", "add", "echo hello"]), 0)
                self.assertEqual(cli.main(["clip", "list"]), 0)
                self.assertEqual(cli.main(["clip", "1"]), 0)
            rendered = output.getvalue()
            self.assertIn("Added tray #1", rendered)
            self.assertIn("echo hello", rendered)
            self.assertIn("OS clipboard ← tray #1", rendered)
            self.assertTrue(run.called)
            kwargs = run.call_args.kwargs
            self.assertEqual(kwargs.get("input"), b"echo hello")


if __name__ == "__main__":
    unittest.main()
