"""Contract and safety tests for TACU's core and host harness tools."""

from __future__ import annotations

import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli
from tacu.tools import ToolContext, invoke, specs
from tacu.tools.contracts import ToolFailure


class ToolHarnessTests(unittest.TestCase):
    def context(self, root: Path) -> ToolContext:
        return ToolContext(root, root / ".tacu-state")

    def test_core_and_host_contracts_are_registered(self) -> None:
        expected = ["repo_map", "search_code", "read_file", "inspect_symbol", "edit_file", "write_file",
                    "shell", "diagnostics", "run_tests", "task_state",
                    "process", "network", "system", "application", "ollama", "filesystem", "git", "docker",
                    "service", "package", "security", "forensics", "recon", "email", "verify", "service_process"]
        self.assertEqual([spec.name for spec in specs()], expected)
        self.assertTrue(all(spec.input_schema and spec.output_schema and spec.timeout > 0 for spec in specs()))

    def test_workspace_guard_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ToolFailure): self.context(Path(directory)).guarded_path("../outside.txt")

    def test_non_object_inputs_return_audited_structured_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = invoke("repo_map", [], self.context(Path(directory)))
        self.assertFalse(result.ok)
        self.assertEqual(result.error["code"], "invalid_input")

    def test_repo_read_search_and_symbol_tools_return_compact_structures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "app.py").write_text("def greet(name):\n    return f'hi {name}'\n")
            context = self.context(root)
            mapped = invoke("repo_map", {"root": ".", "depth": 2, "symbols": True}, context)
            read = invoke("read_file", {"path": "app.py", "start_line": 1, "end_line": 1}, context)
            symbol = invoke("inspect_symbol", {"symbol": "greet", "path": "."}, context)
            search = invoke("search_code", {"query": "return", "path": "."}, context)
        self.assertTrue(mapped.ok); self.assertEqual(mapped.data["files"][0]["symbols"], ["greet"])
        self.assertTrue(read.data["content"].startswith("    1 | def greet"))
        self.assertEqual(symbol.data["definitions"][0]["kind"], "function")
        self.assertTrue(search.ok); self.assertEqual(search.data["count"], 1)

    def test_simple_native_cli_maps_finds_searches_and_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": str(Path(directory) / ".state")}):
            root = Path(directory)
            source = root / "src"
            config = root / "config"
            source.mkdir(); config.mkdir()
            (source / "app.py").write_text("def authenticate(user):\n    # TODO validate token\n    # todo lower-case marker\n    return user\n")
            (config / "settings.yaml").write_text("auth: enabled\n")

            def run(arguments: list[str]) -> str:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(cli.main(arguments), 0)
                return output.getvalue()

            mapped = run(["tools", "map", str(root), "--depth", "3"])
            found = run(["tools", "find", "*.yaml", str(root), "--type", "file", "--case-insensitive"])
            directories_exact = run(["tools", "find", "Config", str(root), "--type", "directory", "--case-sensitive"])
            directories_folded = run(["tools", "find", "CONFIG", str(root), "--type", "directory", "--case-insensitive"])
            searched = run(["tools", "search", "TODO", str(root), "--glob", "*.py", "--case-sensitive"])
            read = run(["tools", "read", str(source / "app.py"), "--start", "1", "--end", "2"])
            recipes = run(["tools", "examples"])
        self.assertIn("DIRECTORY MAP", mapped); self.assertIn("settings.yaml", mapped)
        self.assertIn("./config/settings.yaml", found)
        self.assertIn("No matching paths.", directories_exact); self.assertNotIn("./config/", directories_exact)
        self.assertIn("./config/", directories_folded)
        self.assertIn("./src/app.py:2:", searched); self.assertIn("TODO validate token", searched)
        self.assertNotIn("lower-case marker", searched)
        self.assertIn("1 | def authenticate", read); self.assertNotIn("return user", read)
        self.assertIn("NATIVE TOOL RECIPES", recipes); self.assertIn("--depth 3", recipes)

    def test_repo_map_filename_filter_and_search_glob_are_contract_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "a.py").write_text("needle\n"); (root / "b.txt").write_text("needle\n")
            context = self.context(root)
            found = invoke("repo_map", {"root": ".", "depth": 2, "name": "*.py"}, context)
            (root / "Config").mkdir()
            directories = invoke("repo_map", {"root": ".", "depth": 2, "name": "Config",
                                                "kind": "directory", "case_sensitive": True}, context)
            searched = invoke("search_code", {"query": "needle", "path": ".", "glob": "*.py"}, context)
        self.assertTrue(found.ok); self.assertEqual([item["path"] for item in found.data["files"]], ["a.py"])
        self.assertEqual(directories.data["entries"], [{"path": "Config", "type": "directory"}])
        self.assertTrue(searched.ok); self.assertEqual(searched.data["count"], 1)
        self.assertTrue(searched.data["matches"][0]["file"].endswith("a.py"))

    def test_write_and_edit_are_atomic_and_match_guarded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); context = self.context(root)
            created = invoke("write_file", {"path": "note.txt", "content": "alpha\n"}, context)
            refused = invoke("write_file", {"path": "note.txt", "content": "lost\n"}, context)
            empty = invoke("write_file", {"path": "empty.py", "content": ""}, context)
            mismatch = invoke("edit_file", {"path": "note.txt", "old_text": "missing", "new_text": "x"}, context)
            edited = invoke("edit_file", {"path": "note.txt", "old_text": "alpha", "new_text": "beta"}, context)
            (root / "lines.py").write_text("print(1)\nprint(2)\n")
            numbered_read = invoke("read_file", {"path": "lines.py"}, context)
            gutter = invoke("edit_file", {
                "path": "lines.py",
                "old_text": numbered_read.data["content"].splitlines()[0],
                "new_text": "print(0)",
            }, context)
            final = (root / "note.txt").read_text()
            lines = (root / "lines.py").read_text()
        self.assertTrue(created.ok); self.assertEqual(refused.error["code"], "file_exists")
        self.assertEqual(empty.error["code"], "empty_content")
        self.assertEqual(mismatch.error["code"], "match_count")
        self.assertTrue(mismatch.error["retryable"])
        self.assertIn("-alpha", edited.data["diff"]); self.assertEqual(final, "beta\n")
        self.assertTrue(numbered_read.ok)
        self.assertIn("print(1)", numbered_read.data["text"])
        self.assertTrue(gutter.ok, msg=gutter.error)
        self.assertTrue(lines.startswith("print(0)"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = self.context(root)
            (root / "dup.py").write_text("x = 1\nx = 1\n")
            replaced = invoke("edit_file", {
                "path": "dup.py", "old_text": "x = 1", "new_text": "x = 2", "replace_all": True,
            }, context)
            (root / "two.py").write_text("alpha\nbeta\n")
            hunks = invoke("edit_file", {
                "path": "two.py",
                "edits": [
                    {"old_text": "alpha", "new_text": "ALPHA"},
                    {"old_text": "beta", "new_text": "BETA"},
                ],
            }, context)
            ranged = invoke("read_file", {"path": "two.py", "offset": 2, "limit": 1}, context)
        self.assertTrue(replaced.ok, msg=replaced.error)
        self.assertTrue(hunks.ok, msg=hunks.error)
        self.assertEqual(hunks.data["hunks"], 2)
        self.assertTrue(ranged.ok)
        self.assertEqual(ranged.data["start_line"], 2)
        self.assertIn("BETA", ranged.data["text"])

    def test_search_walks_when_ripgrep_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "hit.py").write_text("needle in hay\n")
            (root / "skip.txt").write_text("needle in hay\n")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "lib.js").write_text("needle in hay\n")
            with patch("tacu.tools.search_code.shutil.which", return_value=None):
                searched = invoke("search_code", {"query": "needle", "path": ".", "glob": "*.py"},
                                  self.context(root))
        self.assertTrue(searched.ok)
        self.assertEqual(searched.data["engine"], "walk")
        self.assertEqual(searched.data["count"], 1)
        self.assertTrue(searched.data["matches"][0]["file"].endswith("hit.py"))

    def test_simple_cli_writes_and_edits(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TACU_HOME": str(Path(directory) / ".state")}):
            root = Path(directory)
            nested = root / "src"
            nested.mkdir()

            def run(arguments: list[str]) -> str:
                output = io.StringIO()
                with redirect_stdout(output), patch("tacu.cli.Path.cwd", return_value=root):
                    self.assertEqual(cli.main(arguments), 0)
                return output.getvalue()

            wrote = run(["tools", "write", "src/hello.py", "--content", "print(1)\n"])
            self.assertIn("wrote", wrote)
            self.assertEqual((nested / "hello.py").read_text(), "print(1)\n")
            edited = run(["tools", "edit", str(nested / "hello.py"), "--old", "print(1)", "--new", "print(2)"])
            self.assertIn("edited", edited)
            self.assertEqual((nested / "hello.py").read_text(), "print(2)\n")

    def test_shell_policy_and_diagnostics_are_structured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); context = self.context(root)
            blocked = invoke("shell", {"executable": "rm", "args": ["-rf", "anything"]}, context)
            safe = invoke("shell", {"executable": sys.executable, "args": ["--version"]}, context)
            (root / "broken.py").write_text("def broken(:\n")
            diagnostics = invoke("diagnostics", {"path": "broken.py"}, context)
        self.assertEqual(blocked.error["code"], "approval_required")
        self.assertTrue(safe.ok); self.assertEqual(safe.data["exit_code"], 0)
        self.assertEqual(diagnostics.data["diagnostics"][0]["code"], "python-syntax")

    def test_shell_preserves_raw_artifact_and_audits_yellow_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "writer.py"
            target = root / "result.txt"
            script.write_text(
                "import pathlib,sys\npathlib.Path(sys.argv[1]).write_text('changed')\nprint('complete raw evidence')\n"
            )
            context = ToolContext(root, root / ".tacu-state", policy_level="log",
                                  policy_reasons=("reversible workspace mutation",))
            result = invoke("shell", {
                "executable": sys.executable,
                "args": [str(script), str(target)],
                "cwd": ".",
            }, context)
            artifact = result.data["raw_artifacts"]["streams"]["stdout"]
            artifact_path = Path(artifact["path"])
            artifact_content = artifact_path.read_text().strip()
            artifact_mode = artifact_path.stat().st_mode & 0o777
            audit = result.data["change_audit"]
            with sqlite3.connect(root / ".tacu-state" / "harness.db") as connection:
                metadata = json.loads(connection.execute(
                    "SELECT input_metadata_json FROM tool_audit WHERE call_id=?", (result.call_id,)
                ).fetchone()[0])
        self.assertTrue(result.ok)
        self.assertEqual(artifact_content, "complete raw evidence")
        if os.name != "nt":
            self.assertEqual(artifact_mode, 0o600)
        self.assertEqual(artifact["sha256"], __import__("hashlib").sha256(b"complete raw evidence\n").hexdigest())
        self.assertTrue(any(item["path"] == str(target.resolve()) and not item["exists"] for item in audit["before"]))
        self.assertTrue(any(item["path"] == str(target.resolve()) and item["exists"] for item in audit["after"]))
        self.assertEqual(metadata["policy_level"], "log")
        self.assertEqual(metadata["args"], [str(script), str(target)])

    def test_audit_redacts_secret_argument_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "noop.py"
            script.write_text("pass\n")
            context = ToolContext(root, root / ".tacu-state")
            result = invoke("shell", {
                "executable": sys.executable,
                "args": [str(script), "--token", "top-secret-value"],
            }, context)
            with sqlite3.connect(root / ".tacu-state" / "harness.db") as connection:
                metadata = json.loads(connection.execute(
                    "SELECT input_metadata_json FROM tool_audit WHERE call_id=?", (result.call_id,)
                ).fetchone()[0])
        self.assertEqual(metadata["args"][-2:], ["--token", "[REDACTED]"])

    def test_run_tests_task_state_and_audit_persist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); tests = root / "tests"; tests.mkdir()
            (tests / "test_ok.py").write_text("import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.assertTrue(True)\n")
            context = self.context(root)
            run = invoke("run_tests", {"target": "tests", "framework": "unittest", "timeout": 30}, context)
            added = invoke("task_state", {"operation": "add", "objective": "finish harness", "task_id": "task-1"}, context)
            planned = invoke("task_state", {"operation": "plan", "task_id": "task-1", "items": ["test", "ship"]}, context)
            completed = invoke("task_state", {"operation": "complete", "task_id": "task-1"}, context)
            with sqlite3.connect(root / ".tacu-state" / "harness.db") as connection:
                audits = connection.execute("SELECT COUNT(*) FROM tool_audit").fetchone()[0]
        self.assertTrue(run.ok); self.assertTrue(run.data["passed"])
        self.assertEqual(added.data["task"]["objective"], "finish harness")
        self.assertEqual(planned.data["task"]["plan"], ["test", "ship"])
        self.assertEqual(completed.data["task"]["status"], "complete")
        self.assertEqual(audits, 4)


class ToolRoutingAndExecutionTests(unittest.TestCase):
    """Intent routing plus actual tool execution for the workspace file tools."""

    def test_intents_select_the_matching_native_tool(self) -> None:
        from tacu.routing import native_steps_for_intent

        cases = [
            ("read program.py", "read_file", "read"),
            ("show me the contents of note.txt", "read_file", "read"),
            ('create a python script named hello.py with "print(1)"', "write_file", "write"),
            ("search code for TODO", "search_code", "search"),
            ("map this project", "repo_map", "map"),
            ("find files matching *.py", "repo_map", "find"),
            ("where is function greet defined", "inspect_symbol", "inspect"),
            ("remove the index.html file", "filesystem", "delete"),
            ('create a text file with the following content in it "hello"', "filesystem", "write"),
            ("run program.py", "shell", "run"),
        ]
        for intent, tool, operation in cases:
            with self.subTest(intent=intent):
                native = native_steps_for_intent(intent)
                self.assertTrue(native, msg=intent)
                self.assertEqual(native[0]["tool"], tool, msg=intent)
                self.assertEqual(native[0]["operation"], operation, msg=intent)

    def test_create_plan_executes_each_workspace_tool(self) -> None:
        from tacu.automation import create_plan
        from tacu.tools import ToolContext, invoke

        class NeverProvider:
            model = "fake"
            def chat(self, messages, *, stream):
                raise AssertionError(f"native tool should not call the model: {messages}")
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("def greet(name):\n    return f'hi {name}'\n# TODO marker\n")
            (root / "note.txt").write_text("hello note\n")
            context = ToolContext(root, root / ".tacu-state")

            def run(intent: str) -> dict:
                plan = create_plan(NeverProvider(), intent, root, 3, allow_shell=False)
                step = plan.steps[0]
                result = invoke(step.native_tool, json.loads(step.native_inputs), context)
                self.assertTrue(result.ok, msg=f"{intent}: {result.error}")
                return result.data or {}

            read = run("read app.py")
            self.assertIn("def greet", read["content"])
            written = run('create a python script named hello.py with "print(1)"')
            self.assertEqual((root / "hello.py").read_text(), "print(1)")
            self.assertGreater(written["bytes_written"], 0)
            searched = run("search code for TODO")
            self.assertGreaterEqual(searched["count"], 1)
            mapped = run("map this project")
            paths = {item["path"] for item in mapped["files"]}
            self.assertIn("app.py", paths)
            found = run("find files matching *.py")
            self.assertTrue(any(item["path"].endswith(".py") for item in found["files"] + found["entries"]))
            symbol = run("where is function greet defined")
            self.assertEqual(symbol["definitions"][0]["kind"], "function")
            note = run("show me the contents of note.txt")
            self.assertIn("hello note", note["content"])
            (root / "program.py").write_text("print(1)\n")
            ran = create_plan(NeverProvider(), "run program.py", root, 3, allow_shell=False)
            self.assertEqual(ran.steps[0].executable, "python3")
            self.assertEqual(ran.steps[0].args, ("program.py",))
            self.assertIsNone(ran.steps[0].native_tool)
            from tacu.automation import evaluate_policy
            self.assertEqual(evaluate_policy(ran.steps[0], root).level, "log")

    def test_docker_ollama_git_mutations_require_review_and_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = ToolContext(root, root / ".tacu-state")
            approved = ToolContext(Path(directory), Path(directory) / ".tacu-state", approve_dangerous=True)
            with patch("tacu.tools.docker.which", return_value="/usr/bin/docker"):
                docker_rm = invoke("docker", {"operation": "rm"}, context)
                self.assertFalse(docker_rm.ok)
                self.assertEqual(docker_rm.error["code"], "approval_required")
                with patch("tacu.tools.docker.run_argv", return_value={
                    "exit_code": 0, "stdout": "", "stderr": "", "command": ["docker", "rm", "demo"],
                }):
                    named = invoke("docker", {"operation": "rm", "name": "demo"}, approved)
                self.assertTrue(named.ok)
                dashed = invoke("docker", {"operation": "rm", "name": "-f"}, approved)
                self.assertFalse(dashed.ok)
                self.assertEqual(dashed.error["code"], "invalid_arguments")
            with patch("tacu.tools.ollama.which", return_value="/usr/bin/ollama"):
                ollama_rm = invoke("ollama", {"operation": "rm", "name": "gemma4:12b-mlx"}, context)
            self.assertFalse(ollama_rm.ok)
            self.assertEqual(ollama_rm.error["code"], "approval_required")
            git_push = invoke("git", {"operation": "push"}, context)
            self.assertFalse(git_push.ok)
            self.assertIn(git_push.error["code"], {"approval_required", "not_a_repo"})


if __name__ == "__main__": unittest.main()
