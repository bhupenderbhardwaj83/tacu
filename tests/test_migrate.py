"""ti migrate — the whole working copy, including what git hides, as one zip.

A clone gives you the tracked files. Moving to another machine needs the rest:
the holding pen, the private test harness, the local notes. What must not
travel is only what the other machine rebuilds for itself.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, migrate


def build_working_copy(root: Path) -> None:
    """A checkout with tracked files, ignored files, and rebuildable junk."""

    (root / "src" / "tacu").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "not_required" / "notes").mkdir(parents=True)
    (root / "pre_release_tests").mkdir()
    (root / ".git").mkdir()
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / ".venv" / "lib").mkdir(parents=True)
    (root / "src" / "tacu" / "__pycache__").mkdir()
    (root / "dist").mkdir()

    (root / "pyproject.toml").write_text("[project]\nname='tacu'\n", encoding="utf-8")
    (root / "src" / "tacu" / "cli.py").write_text("print('hi')\n", encoding="utf-8")
    (root / "tests" / "test_x.py").write_text("assert True\n", encoding="utf-8")
    (root / "not_required" / "notes" / "plan.md").write_text("local plan\n", encoding="utf-8")
    (root / "pre_release_tests" / "check.py").write_text("check()\n", encoding="utf-8")
    (root / ".gitignore").write_text("not_required/\n", encoding="utf-8")
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (root / ".env").write_text("SECRET=live\n", encoding="utf-8")
    # Rebuilt on the other machine, never carried.
    (root / "node_modules" / "left-pad" / "index.js").write_text("x\n", encoding="utf-8")
    (root / ".venv" / "lib" / "python.so").write_text("binary\n", encoding="utf-8")
    (root / "src" / "tacu" / "__pycache__" / "cli.pyc").write_text("cached\n", encoding="utf-8")
    (root / "dist" / "tacu.whl").write_text("wheel\n", encoding="utf-8")


class ArchiveNameTests(unittest.TestCase):
    def test_the_name_is_the_agreed_shape(self) -> None:
        # 11:28 UTC is 16:58 IST the same day.
        moment = datetime(2026, 9, 6, 11, 28, tzinfo=timezone.utc)
        self.assertEqual(migrate.archive_stamp(moment), "1658_IST_06_Sep_2026")
        self.assertEqual(migrate.archive_name("juicy detector rewrite", moment),
                         "tacu_1658_IST_06_Sep_2026_juicy-detector-rewrite")

    def test_a_description_survives_being_a_file_name(self) -> None:
        self.assertEqual(migrate.describe_slug("before the 0.4 rewrite!"),
                         "before-the-0-4-rewrite")
        self.assertEqual(migrate.describe_slug("   "), migrate.DEFAULT_DESCRIPTION)
        self.assertEqual(migrate.describe_slug("../../etc/passwd"), "etc-passwd")

    def test_an_archive_can_say_what_it_is(self) -> None:
        parsed = migrate.parse_archive_name(
            "tacu_1658_IST_06_Sep_2026_juicy-detector-rewrite.zip")
        self.assertEqual(parsed, {"time": "1658", "day": "06", "month": "Sep",
                                  "year": "2026", "description": "juicy-detector-rewrite"})
        self.assertIsNone(migrate.parse_archive_name("some-other-file.zip"))


class ContentsTests(unittest.TestCase):
    def test_ignored_work_travels_and_installed_packages_do_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tacu"
            root.mkdir()
            build_working_copy(root)
            plan = migrate.plan_migration(root, Path(directory) / "out.zip")
            carried = {path.relative_to(plan.root).as_posix() for path in plan.files}

            for wanted in ("pyproject.toml", "src/tacu/cli.py", "tests/test_x.py",
                           "not_required/notes/plan.md", "pre_release_tests/check.py",
                           ".gitignore", ".git/HEAD", ".env"):
                with self.subTest(wanted=wanted):
                    self.assertIn(wanted, carried)
            for unwanted in ("node_modules/left-pad/index.js", ".venv/lib/python.so",
                             "src/tacu/__pycache__/cli.pyc", "dist/tacu.whl"):
                with self.subTest(unwanted=unwanted):
                    self.assertNotIn(unwanted, carried)

    def test_credential_files_are_named_before_they_travel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tacu"
            root.mkdir()
            build_working_copy(root)
            plan = migrate.plan_migration(root, Path(directory) / "out.zip")
            self.assertIn(".env", plan.sensitive)

    def test_an_exclusion_is_reported_apart_from_rebuildable_junk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tacu"
            root.mkdir()
            build_working_copy(root)
            plan = migrate.plan_migration(root, Path(directory) / "out.zip",
                                          exclude=("not_required",))
            carried = {path.relative_to(plan.root).as_posix() for path in plan.files}
            self.assertNotIn("not_required/notes/plan.md", carried)
            self.assertIn("not_required", plan.excluded_dirs)
            self.assertNotIn("not_required", plan.skipped_dirs)


class ArchiveTests(unittest.TestCase):
    def test_the_zip_holds_one_folder_named_like_itself(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tacu"
            root.mkdir()
            build_working_copy(root)
            archive = Path(directory) / "tacu_1658_IST_06_Sep_2026_test.zip"
            plan = migrate.plan_migration(root, archive)
            migrate.write_archive(plan)
            with zipfile.ZipFile(archive) as bundle:
                names = bundle.namelist()
            tops = {name.split("/", 1)[0] for name in names}
            self.assertEqual(tops, {"tacu_1658_IST_06_Sep_2026_test"})
            self.assertIn("tacu_1658_IST_06_Sep_2026_test/pyproject.toml", names)

    def test_the_archive_is_owner_only(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX permissions only")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tacu"
            root.mkdir()
            build_working_copy(root)
            archive = Path(directory) / "out.zip"
            migrate.write_archive(migrate.plan_migration(root, archive))
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)

    def test_extracting_gives_back_the_same_working_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tacu"
            root.mkdir()
            build_working_copy(root)
            archive = Path(directory) / "out.zip"
            migrate.write_archive(migrate.plan_migration(root, archive))
            landing = Path(directory) / "landing"
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(landing)
            restored = landing / "out"
            self.assertEqual((restored / "src" / "tacu" / "cli.py").read_text(encoding="utf-8"),
                             "print('hi')\n")
            self.assertEqual(
                (restored / "not_required" / "notes" / "plan.md").read_text(encoding="utf-8"),
                "local plan\n")
            self.assertFalse((restored / "node_modules").exists())


class CommandTests(unittest.TestCase):
    def test_the_default_destination_is_one_directory_above(self) -> None:
        self.assertEqual(migrate.default_destination(Path("/a/b/tacu")), Path("/a/b"))

    def test_dry_run_writes_nothing_and_says_what_would_travel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            root = Path(directory) / "work" / "tacu"
            root.mkdir(parents=True)
            build_working_copy(root)
            shown = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), redirect_stdout(shown):
                self.assertEqual(cli.main(["migrate", "--root", str(root), "--dry-run",
                                           "a", "quick", "check"]), 0)
            body = shown.getvalue()
            self.assertIn("DRY RUN", body)
            self.assertIn("a-quick-check", body)
            # The credential warning is not optional.
            self.assertIn(".env", body)
            self.assertEqual(list(Path(directory, "work").glob("*.zip")), [])

    def test_the_archive_lands_beside_the_working_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            root = Path(directory) / "work" / "tacu"
            root.mkdir(parents=True)
            build_working_copy(root)
            shown = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), redirect_stdout(shown):
                self.assertEqual(cli.main(["migrate", "--root", str(root), "moving", "house"]), 0)
            written = list(Path(directory, "work").glob("*.zip"))
            self.assertEqual(len(written), 1, written)
            self.assertTrue(written[0].name.startswith("tacu_"))
            self.assertTrue(written[0].name.endswith("_moving-house.zip"))
            # Never inside the copy it packaged.
            self.assertEqual(written[0].parent, root.parent)

    def test_an_archive_inside_the_working_copy_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            root = Path(directory) / "tacu"
            root.mkdir()
            build_working_copy(root)
            shown = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), redirect_stdout(shown):
                code = cli.main(["migrate", "--root", str(root), "-o", str(root)])
            self.assertNotEqual(code, 0)


class ReleaseNotesTests(unittest.TestCase):
    """The release workflow publishes whatever this returns, so it is tested."""

    def test_the_section_for_a_version_comes_back_as_written(self) -> None:
        from tacu.core import release_notes

        notes = release_notes("0.3.11")
        self.assertIn("ti migrate", notes)
        self.assertIn("### Added", notes)
        # It must stop at the next release, not run to the end of the file.
        self.assertNotIn("0.3.10", notes)

    def test_a_leading_v_is_accepted_because_tags_carry_one(self) -> None:
        from tacu.core import release_notes

        self.assertEqual(release_notes("v0.3.11"), release_notes("0.3.11"))

    def test_an_unknown_version_returns_nothing_rather_than_guessing(self) -> None:
        from tacu.core import release_notes

        self.assertEqual(release_notes("9.9.9"), "")

    def test_every_released_version_has_notes_to_publish(self) -> None:
        from tacu.core import release_history, release_notes

        for version, _date, _bullets in release_history():
            with self.subTest(version=version):
                self.assertTrue(release_notes(version).strip(), version)

    def test_the_shipped_version_is_documented(self) -> None:
        # The release workflow refuses to publish a tag whose section is missing.
        import tacu
        from tacu.core import release_notes

        self.assertTrue(release_notes(tacu.__version__).strip(),
                        f"CHANGELOG.md has no section for {tacu.__version__}")


if __name__ == "__main__":
    unittest.main()
