"""Reading a failure and changing something, instead of repeating it."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import diagnose
from tacu.automation import _step_from_capability
from tacu.cli import _step_fingerprint

MISSING_FLASK = (
    "Traceback (most recent call last):\n"
    '  File "app.py", line 1, in <module>\n'
    "    from flask import Flask, request\n"
    "ModuleNotFoundError: No module named 'flask'\n"
)


class RemedyTests(unittest.TestCase):
    def _remedy(self, text: str, workspace: Path, failed=None) -> list[dict]:
        return diagnose.remedy(text, workspace, failed)

    def test_a_missing_module_becomes_isolate_install_retry(self) -> None:
        failed = {"tool": "shell", "operation": "run",
                  "inputs": {"executable": "python3", "args": ["app.py"], "cwd": "."}}
        with tempfile.TemporaryDirectory() as directory:
            steps = self._remedy(MISSING_FLASK, Path(directory), failed)
        commands = [f"{s['inputs']['executable']} {' '.join(s['inputs']['args'])}" for s in steps]
        self.assertIn("-m venv .venv", commands[0])
        self.assertTrue(any("flask" in c for c in commands), commands)
        self.assertTrue(commands[-1].endswith("app.py"), commands)
        self.assertNotIn("python3 app.py", commands, "must not repeat the failing command verbatim")

    def test_the_retry_runs_inside_the_environment_not_the_system_python(self) -> None:
        failed = {"tool": "shell", "operation": "run",
                  "inputs": {"executable": "python3", "args": ["app.py"], "cwd": "."}}
        with tempfile.TemporaryDirectory() as directory:
            steps = self._remedy(MISSING_FLASK, Path(directory), failed)
        self.assertIn(".venv", steps[-1]["inputs"]["executable"])

    def test_activation_is_never_used_because_it_cannot_work_in_a_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            steps = self._remedy(MISSING_FLASK, Path(directory), None)
        rendered = json.dumps(steps)
        self.assertNotIn("activate", rendered)
        self.assertNotIn("source", rendered)

    def test_an_existing_environment_is_reused_rather_than_recreated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / ".venv" / "bin").mkdir(parents=True)
            (workspace / ".venv" / "bin" / "python").write_text("")
            steps = self._remedy(MISSING_FLASK, workspace, None)
        self.assertNotIn("venv", " ".join(steps[0]["inputs"]["args"]))

    def test_the_distribution_name_is_used_when_it_differs_from_the_import(self) -> None:
        for module, package in (("cv2", "opencv-python"), ("yaml", "PyYAML"),
                                ("PIL", "Pillow"), ("flask", "flask")):
            self.assertEqual(diagnose.distribution_for(module), package)

    def test_a_shell_script_is_run_through_a_shell_rather_than_chmodded(self) -> None:
        steps = self._remedy("zsh: permission denied: ./setup_venv.sh", Path("."), None)
        self.assertEqual(steps[0]["inputs"]["executable"], "sh")

    def test_a_bare_pip_becomes_the_interpreter_module(self) -> None:
        steps = self._remedy("line 3: pip: command not found", Path("."), None)
        self.assertIn("-m", steps[0]["inputs"]["args"])
        self.assertIn("pip", steps[0]["inputs"]["args"])

    def test_an_unrecognised_failure_proposes_nothing(self) -> None:
        self.assertEqual(self._remedy("Segmentation fault: 11", Path("."), None), [])
        self.assertEqual(diagnose.explain("Segmentation fault: 11"), "")


class PackageManagerChoiceTests(unittest.TestCase):
    """A lockfile is a decision the project already made."""

    def _workspace(self, *files: str):
        directory = tempfile.TemporaryDirectory()
        workspace = Path(directory.name)
        for name in files:
            (workspace / name).write_text("{}")
        return directory, workspace

    def test_a_node_lockfile_decides_even_when_pnpm_is_installed(self) -> None:
        keep, workspace = self._workspace("package-lock.json")
        with patch("tacu.diagnose.shutil.which", return_value="/usr/bin/pnpm"):
            self.assertEqual(diagnose.node_installer(workspace)["tool"], "npm")
        keep.cleanup()

    def test_pnpm_is_preferred_only_when_nothing_is_pinned(self) -> None:
        keep, workspace = self._workspace()
        with patch("tacu.diagnose.shutil.which", return_value="/usr/bin/pnpm"):
            self.assertEqual(diagnose.node_installer(workspace)["tool"], "pnpm")
        keep.cleanup()

    def test_npm_is_the_fallback_when_pnpm_is_absent(self) -> None:
        keep, workspace = self._workspace()
        with patch("tacu.diagnose.shutil.which", return_value=None):
            self.assertEqual(diagnose.node_installer(workspace)["tool"], "npm")
        keep.cleanup()

    def test_a_python_lockfile_decides_over_uv(self) -> None:
        keep, workspace = self._workspace("uv.lock")
        with patch("tacu.diagnose.shutil.which", return_value="/usr/bin/uv"):
            self.assertEqual(diagnose.python_installer(workspace, None)["tool"], "uv")
        keep.cleanup()
        keep, workspace = self._workspace("poetry.lock")
        with patch("tacu.diagnose.shutil.which", return_value="/usr/bin/poetry"):
            self.assertEqual(diagnose.python_installer(workspace, None)["tool"], "poetry")
        keep.cleanup()

    def test_pip_is_used_when_uv_is_not_installed(self) -> None:
        keep, workspace = self._workspace()
        with patch("tacu.diagnose.shutil.which", return_value=None):
            self.assertEqual(diagnose.python_installer(workspace, None)["tool"], "pip")
        keep.cleanup()


class NoRepeatTests(unittest.TestCase):
    """Repeating a failed action is what made the loop look broken."""

    def _step(self, executable: str, *args: str):
        return _step_from_capability({"tool": "shell", "operation": "run",
                                      "inputs": {"executable": executable, "args": list(args),
                                                 "cwd": "."}, "purpose": "x"})

    def test_the_same_command_has_the_same_fingerprint_whatever_the_wording(self) -> None:
        first = _step_from_capability({"tool": "shell", "operation": "run", "purpose": "run it",
                                       "inputs": {"executable": "python3", "args": ["app.py"], "cwd": "."}})
        second = _step_from_capability({"tool": "shell", "operation": "run", "purpose": "try once more",
                                        "inputs": {"executable": "python3", "args": ["app.py"], "cwd": "."}})
        self.assertEqual(_step_fingerprint(first), _step_fingerprint(second))

    def test_running_inside_the_environment_is_a_different_attempt(self) -> None:
        self.assertNotEqual(_step_fingerprint(self._step("python3", "app.py")),
                            _step_fingerprint(self._step(".venv/bin/python", "app.py")))

    def test_native_steps_compare_by_meaning_not_key_order(self) -> None:
        one = _step_from_capability({"tool": "read_file", "operation": "read", "purpose": "x",
                                     "inputs": {"path": "app.py", "start_line": 1}})
        two = _step_from_capability({"tool": "read_file", "operation": "read", "purpose": "y",
                                     "inputs": {"start_line": 1, "path": "app.py"}})
        self.assertEqual(_step_fingerprint(one), _step_fingerprint(two))

    def test_the_remedy_is_never_the_step_that_just_failed(self) -> None:
        failed = {"tool": "shell", "operation": "run",
                  "inputs": {"executable": "python3", "args": ["app.py"], "cwd": "."}}
        already = _step_fingerprint(_step_from_capability(failed))
        with tempfile.TemporaryDirectory() as directory:
            steps = diagnose.remedy(MISSING_FLASK, Path(directory), failed)
        fingerprints = {_step_fingerprint(_step_from_capability(item)) for item in steps}
        self.assertNotIn(already, fingerprints)


class FailureReadingTests(unittest.TestCase):
    def test_stderr_is_recovered_from_a_failed_step(self) -> None:
        results = [{"result": {"data": {"exit_code": 1, "stderr": MISSING_FLASK}}}]
        self.assertIn("ModuleNotFoundError", diagnose.failure_text(results))

    def test_successful_steps_contribute_nothing(self) -> None:
        results = [{"result": {"data": {"exit_code": 0, "stderr": "warning: noisy"}}}]
        self.assertEqual(diagnose.failure_text(results), "")

    def test_the_failed_command_is_recovered_for_the_retry(self) -> None:
        results = [{"result": {"data": {"exit_code": 1, "stderr": MISSING_FLASK,
                                        "command": ["python3", "app.py"]}}}]
        step = diagnose.last_failed_step(results)
        self.assertEqual(step["inputs"]["executable"], "python3")
        self.assertEqual(step["inputs"]["args"], ["app.py"])


if __name__ == "__main__":
    unittest.main()


class SetupInsteadOfScriptTests(unittest.TestCase):
    """Setting up an environment is work to do, not a script to hand back."""

    def _workspace(self, *files: str):
        keep = tempfile.TemporaryDirectory()
        workspace = Path(keep.name)
        for name in files:
            (workspace / name).write_text("{}")
        return keep, workspace

    def test_a_venv_request_produces_steps_that_run(self) -> None:
        keep, workspace = self._workspace()
        steps = diagnose.setup_steps(
            "please create a virtual environment activate it and then install flask", workspace)
        rendered = json.dumps(steps)
        self.assertTrue(steps)
        self.assertIn("venv", rendered)
        self.assertIn("flask", rendered)
        self.assertNotIn(".sh", rendered, "it must not fall back to writing a script")
        self.assertNotIn("activate", rendered)
        keep.cleanup()

    def test_a_tool_the_user_names_is_the_tool_used(self) -> None:
        keep, workspace = self._workspace("package.json", "pnpm-lock.yaml")
        steps = diagnose.setup_steps("npm install express", workspace)
        self.assertEqual(steps[0]["inputs"]["executable"], "npm",
                         "an explicit choice outranks the lockfile and any preference")
        keep.cleanup()

    def test_an_unclear_ecosystem_proposes_nothing(self) -> None:
        keep, workspace = self._workspace()
        self.assertEqual(diagnose.setup_steps("add lodash to the project", workspace), [])
        keep.cleanup()

    def test_the_project_language_settles_an_unclear_request(self) -> None:
        keep, workspace = self._workspace("package.json")
        steps = diagnose.setup_steps("add lodash to the project", workspace)
        self.assertTrue(steps)
        self.assertIn(steps[0]["inputs"]["executable"], {"npm", "pnpm", "yarn"})
        keep.cleanup()

    def test_a_plain_question_is_not_treated_as_an_install(self) -> None:
        keep, workspace = self._workspace("pyproject.toml")
        self.assertEqual(diagnose.setup_steps("which process is using most cpu", workspace), [])
        keep.cleanup()


class ToolchainDiscoveryTests(unittest.TestCase):
    def test_it_reports_what_is_present_and_what_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            found = diagnose.toolchain(Path(directory))
        self.assertIn("available", found)
        self.assertIn("missing", found)
        self.assertIn("tool", found["python_installer"])
        self.assertIn("tool", found["node_installer"])

    def test_pip_versus_pip3_never_decides_anything(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            steps = diagnose.remedy(MISSING_FLASK, workspace, None)
        rendered = json.dumps(steps)
        self.assertNotIn('"pip3"', rendered)
        self.assertNotIn('"executable": "pip"', rendered)
