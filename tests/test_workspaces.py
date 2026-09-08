"""Several projects, remembered, so a job runs where you are standing.

TACU held one configured workspace. Running `ti code` inside a project it did not
know about worked somewhere else entirely: asked about "the flask app in the
current directory" it reported the directory empty, because it was reading
~/TACU-Workspace while the app sat in ~/Downloads/test_http.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import workspaces


class ProjectDetectionTests(unittest.TestCase):
    def test_a_directory_with_a_project_marker_is_one(self) -> None:
        for marker in ("pyproject.toml", "package.json", "app.py", ".git", "Makefile"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / marker
                target.mkdir() if marker == ".git" else target.write_text("x", encoding="utf-8")
                self.assertTrue(workspaces.looks_like_a_project(Path(directory)), marker)

    def test_a_couple_of_source_files_are_enough(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "one.rb").write_text("x", encoding="utf-8")
            (Path(directory) / "two.rb").write_text("x", encoding="utf-8")
            self.assertTrue(workspaces.looks_like_a_project(Path(directory)))

    def test_an_empty_directory_is_not_a_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(workspaces.looks_like_a_project(Path(directory)))

    def test_home_and_root_are_never_projects(self) -> None:
        # Writing into either because a stray source file sits there would be bad.
        self.assertFalse(workspaces.looks_like_a_project(Path.home()))
        self.assertFalse(workspaces.looks_like_a_project(Path("/")))
        self.assertFalse(workspaces.looks_like_a_project(Path("/tmp")))


class RegistryTests(unittest.TestCase):
    def home(self, stack) -> Path:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        stack.enter_context(patch.dict(os.environ, {"TACU_HOME": str(directory / "home")}))
        return directory

    def test_switching_adds_to_the_set_rather_than_replacing_it(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = self.home(stack)
            first, second = base / "alpha", base / "beta"
            first.mkdir(); second.mkdir()
            workspaces.remember(first)
            workspaces.remember(second)
            known = {item.name for item in workspaces.remembered()}
            self.assertEqual(known, {"alpha", "beta"}, "the earlier workspace must survive")

    def test_forgetting_leaves_the_directory_alone(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = self.home(stack)
            target = base / "gamma"
            target.mkdir()
            (target / "keep.py").write_text("x", encoding="utf-8")
            other = base / "delta"
            other.mkdir()
            workspaces.remember(target)
            workspaces.remember(other)          # switch away before forgetting
            self.assertTrue(workspaces.forget(target))
            self.assertNotIn(target.resolve(), workspaces.remembered())
            self.assertTrue((target / "keep.py").is_file())

    def test_the_workspace_in_use_cannot_be_forgotten(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = self.home(stack)
            target = base / "current"
            target.mkdir()
            workspaces.remember(target)
            with self.assertRaises(workspaces.InUse):
                workspaces.forget(target)

    def test_forgetting_something_unknown_says_so(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = self.home(stack)
            self.assertFalse(workspaces.forget(base / "never-added"))

    def test_standing_inside_a_workspace_finds_it(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = self.home(stack)
            project = base / "project"
            nested = project / "src" / "deep"
            nested.mkdir(parents=True)
            workspaces.remember(project)
            self.assertEqual(workspaces.containing(nested), project.resolve())

    def test_the_closest_workspace_wins(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = self.home(stack)
            outer = base / "outer"
            inner = outer / "inner"
            inner.mkdir(parents=True)
            workspaces.remember(outer)
            workspaces.remember(inner)
            # A project nested inside another belongs to itself.
            self.assertEqual(workspaces.containing(inner), inner.resolve())

    def test_somewhere_unknown_belongs_to_no_workspace(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = self.home(stack)
            workspaces.remember(base / "known")
            stray = base / "stray"
            stray.mkdir()
            self.assertIsNone(workspaces.containing(stray))


class ResolutionTests(unittest.TestCase):
    """Which directory a job actually runs in."""

    def resolve(self, cwd: Path, configured: Path, tty: bool = False) -> Path:
        from tacu.cli import resolve_working_workspace

        with patch("tacu.cli.Path.cwd", return_value=cwd), \
             patch("tacu.cli.configured_workspace", return_value=configured), \
             patch.object(sys.stdin, "isatty", return_value=tty):
            return resolve_working_workspace(None, verb="code")

    def test_an_explicit_workspace_always_wins(self) -> None:
        import contextlib

        from tacu.cli import resolve_working_workspace

        with contextlib.ExitStack() as stack:
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            self.assertEqual(resolve_working_workspace(directory, verb="code"),
                             directory.resolve())

    def test_a_project_directory_is_used_when_nobody_can_be_asked(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            stack.enter_context(patch.dict(os.environ, {"TACU_HOME": str(base / "home")}))
            project, configured = base / "flask_app", base / "elsewhere"
            project.mkdir(); configured.mkdir()
            (project / "app.py").write_text("x", encoding="utf-8")
            self.assertEqual(self.resolve(project, configured), project.resolve())

    def test_a_directory_that_is_not_a_project_leaves_the_workspace_alone(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            base = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            stack.enter_context(patch.dict(os.environ, {"TACU_HOME": str(base / "home")}))
            scratch, configured = base / "scratch", base / "elsewhere"
            scratch.mkdir(); configured.mkdir()
            self.assertEqual(self.resolve(scratch, configured), configured.resolve())


if __name__ == "__main__":
    unittest.main()
