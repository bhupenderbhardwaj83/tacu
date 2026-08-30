"""Backup archive round-trip, merge restore, and clip label display."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import backup as backup_module
from tacu.clipboard import ClipStore, is_custom_label, origin_line
from tacu.core import TacuError


def _seed_home(root: Path, *, turns: int = 2, clips: int = 1) -> None:
    root.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(root / "history.db") as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS turns (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL, model TEXT NOT NULL,
              query TEXT NOT NULL, response TEXT NOT NULL, tool_result_json TEXT)"""
        )
        for index in range(1, turns + 1):
            connection.execute(
                "INSERT INTO turns(id,created_at,model,query,response) VALUES (?,?,?,?,?)",
                (index, "2026-01-01T00:00:00Z", "test-model", f"question {index}", f"answer {index}"),
            )
    with ClipStore(root / "clipboard.db") as clips_store:
        for index in range(1, clips + 1):
            clips_store.add(f"snippet {index}", source=f"turn {index} L1")
    (root / "config.json").write_text(json.dumps({"model": "test-model"}), encoding="utf-8")


class ClipLabelTests(unittest.TestCase):
    def test_auto_label_is_not_treated_as_custom(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with ClipStore(Path(directory) / "clipboard.db") as clips:
                auto = clips.add("nmap -sC 192.168.1.1", source="turn 7 L3")
                self.assertFalse(is_custom_label(auto))
                # Falls back to provenance rather than repeating the preview.
                self.assertEqual(origin_line(auto), "turn 7 L3")

    def test_custom_label_wins_over_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with ClipStore(Path(directory) / "clipboard.db") as clips:
                named = clips.add("nmap -sC 192.168.1.1", label="scan", source="turn 7 L3")
                self.assertTrue(is_custom_label(named))
                self.assertEqual(origin_line(named), "scan")

    def test_origin_is_empty_when_nothing_useful_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with ClipStore(Path(directory) / "clipboard.db") as clips:
                bare = clips.add("just some text")
                self.assertEqual(origin_line(bare), "")


class BackupTests(unittest.TestCase):
    def test_create_then_read_manifest_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "home"
            _seed_home(root)
            archive = backup_module.create_backup(Path(directory) / "out.tar.gz", home=root)
            self.assertTrue(archive.path.is_file())
            self.assertIn("history.db", archive.entries)
            self.assertIn("clipboard.db", archive.entries)
            self.assertIn("config.json", archive.entries)
            self.assertFalse(archive.includes_artifacts)

            info = backup_module.read_manifest(archive.path)
            self.assertEqual(info.tacu_version, archive.tacu_version)
            self.assertGreater(info.size_bytes, 0)

    def test_runtime_directory_is_never_archived(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "home"
            _seed_home(root)
            (root / "runtime" / "venv").mkdir(parents=True)
            (root / "runtime" / "venv" / "big").write_text("x" * 1000, encoding="utf-8")
            archive = backup_module.create_backup(Path(directory) / "out.tar.gz", home=root)
            with tarfile.open(archive.path, "r:gz") as bundle:
                names = bundle.getnames()
            self.assertFalse([name for name in names if "runtime" in name])

    def test_artifacts_are_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "home"
            _seed_home(root)
            (root / "artifacts").mkdir()
            (root / "artifacts" / "raw.txt").write_text("evidence", encoding="utf-8")

            without = backup_module.create_backup(Path(directory) / "a.tar.gz", home=root)
            self.assertNotIn("artifacts", without.entries)

            with_artifacts = backup_module.create_backup(
                Path(directory) / "b.tar.gz", home=root, include_artifacts=True)
            self.assertIn("artifacts", with_artifacts.entries)

    def test_restore_replaces_local_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            _seed_home(source, turns=3)
            archive = backup_module.create_backup(Path(directory) / "out.tar.gz", home=source)

            target = Path(directory) / "target"
            _seed_home(target, turns=1)
            backup_module.restore_backup(archive.path, home=target, safety_copy=False)
            with sqlite3.connect(target / "history.db") as connection:
                count = connection.execute("SELECT COUNT(*) FROM turns").fetchone()[0]
            self.assertEqual(count, 3)

    def test_merge_restore_keeps_local_rows_and_adds_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            _seed_home(source, turns=2)
            archive = backup_module.create_backup(Path(directory) / "out.tar.gz", home=source)

            target = Path(directory) / "target"
            _seed_home(target, turns=1)
            with sqlite3.connect(target / "history.db") as connection:
                connection.execute(
                    "INSERT INTO turns(id,created_at,model,query,response) VALUES (?,?,?,?,?)",
                    (99, "2026-02-02T00:00:00Z", "local", "local only", "kept"),
                )
            backup_module.restore_backup(archive.path, home=target, merge=True, safety_copy=False)
            with sqlite3.connect(target / "history.db") as connection:
                rows = dict(connection.execute("SELECT id, query FROM turns").fetchall())
            self.assertIn(99, rows)
            self.assertEqual(rows[99], "local only")
            self.assertIn(2, rows)

    def test_restore_writes_a_safety_copy_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            _seed_home(source, turns=2)
            archive = backup_module.create_backup(Path(directory) / "out.tar.gz", home=source)

            target = Path(directory) / "target"
            _seed_home(target, turns=1)
            _, outcome = backup_module.restore_backup(archive.path, home=target)
            rescue = outcome.get("_safety_copy", "")
            self.assertTrue(rescue)
            self.assertTrue(Path(rescue).is_file())

    def test_list_backups_skips_unrelated_archives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "home"
            _seed_home(root)
            folder = Path(directory) / "cloud"
            folder.mkdir()
            backup_module.create_backup(folder / "tacu-one.tar.gz", home=root)
            stray = folder / "unrelated.tar.gz"
            with tarfile.open(stray, "w:gz") as bundle:
                note = root / "config.json"
                bundle.add(note, arcname="note.json")

            found = backup_module.list_backups(folder)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].path.name, "tacu-one.tar.gz")

    def test_non_tacu_archive_is_rejected_with_a_clear_message(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stray = Path(directory) / "random.tar.gz"
            payload = Path(directory) / "note.txt"
            payload.write_text("hello", encoding="utf-8")
            with tarfile.open(stray, "w:gz") as bundle:
                bundle.add(payload, arcname="note.txt")
            with self.assertRaises(TacuError):
                backup_module.read_manifest(stray)

    def test_destination_folder_gets_a_generated_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "home"
            _seed_home(root)
            folder = Path(directory) / "drive"
            folder.mkdir()
            info = backup_module.create_backup(folder, home=root)
            self.assertEqual(info.path.parent, folder)
            self.assertTrue(info.path.name.startswith("tacu-backup-"))
            self.assertTrue(info.path.name.endswith(".tar.gz"))

    def test_glob_and_folder_arguments_resolve_to_newest_archive(self) -> None:
        # `ti` is aliased to `noglob ti`, so patterns arrive unexpanded.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "home"
            _seed_home(root)
            folder = Path(directory) / "drive"
            folder.mkdir()
            backup_module.create_backup(folder / "tacu-old.tar.gz", home=root)
            newest = backup_module.create_backup(folder / "tacu-new.tar.gz", home=root)
            os.utime(newest.path, (2_000_000_000, 2_000_000_000))

            by_glob = backup_module.resolve_archive(folder / "*.tar.gz")
            self.assertEqual(by_glob, newest.path)
            self.assertTrue(backup_module.resolve_archive(folder).is_file())

    def test_missing_home_reports_a_useful_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(TacuError):
                backup_module.create_backup(Path(directory) / "out.tar.gz",
                                            home=Path(directory) / "absent")


class BackupCliTests(unittest.TestCase):
    def test_cli_create_list_and_restore(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "home"
            _seed_home(root, turns=2)
            folder = Path(directory) / "drive"
            folder.mkdir()
            with patch.dict(os.environ, {"TACU_HOME": str(root)}):
                self.assertEqual(cli.main(["backup", "create", str(folder)]), 0)
                archives = list(folder.glob("*.tar.gz"))
                self.assertEqual(len(archives), 1)
                self.assertEqual(cli.main(["backup", "list", str(folder)]), 0)
                self.assertEqual(cli.main(["backup", "show", str(archives[0])]), 0)
                self.assertEqual(
                    cli.main(["backup", "restore", str(archives[0]), "--yes", "--no-safety-copy"]), 0)


if __name__ == "__main__":
    unittest.main()
