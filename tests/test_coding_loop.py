"""The coding lane: one step at a time, proved before it is called finished.

Batch planning asks a model to name the arguments of step four before step one
has run, so an edit built on a guess corrupts the file and every later step
compounds it. These tests hold the loop to the three things that replace it — a
standing task list, a guard that will not accept unproven work, and a restore
point taken before the first change.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu.codingguard import CodingGuard, command_verifies, shell_writes_source
from tacu.codingloop import CodingLoop, prune
from tacu.snapshot import Snapshot
from tacu.todo import TodoList


class FakeClient:
    """Replays a scripted sequence of model turns."""

    def __init__(self, turns: list[dict]) -> None:
        self.turns = list(turns)
        self.seen: list[list[dict]] = []

    def chat_tools(self, messages, tools, **kwargs):
        self.seen.append(messages)
        return self.turns.pop(0) if self.turns else {"content": "done", "tool_calls": []}


def call(name: str, **arguments) -> dict:
    return {"content": "", "tool_calls": [{"name": name, "arguments": arguments}]}


class GuardTests(unittest.TestCase):
    def test_the_shell_may_not_rewrite_source(self) -> None:
        for command in ("echo 'x' > app.py", "sed -i 's/a/b/' main.ts",
                        "cat x >> lib/util.js", "rm -f server.go", "tee out.py"):
            with self.subTest(command=command):
                self.assertTrue(shell_writes_source(command), command)

    def test_running_tests_and_linters_is_allowed(self) -> None:
        for command in ("pytest -q tests", "python -m unittest discover",
                        "npm test", "ruff check .", "mypy src", "cargo test"):
            with self.subTest(command=command):
                self.assertFalse(shell_writes_source(command), command)
                self.assertTrue(command_verifies(command), command)

    def test_changed_files_must_be_proved_before_finishing(self) -> None:
        guard = CodingGuard(workspace=Path("/tmp"))
        self.assertIsNone(guard.refuse_completion(), "nothing changed, nothing to prove")
        guard.observe("write_file", {"path": "app.py"}, {"status": "success"})
        self.assertIn("nothing has been run", guard.refuse_completion() or "")
        guard.observe("run_tests", {}, {"status": "success", "exit_code": 0})
        self.assertIsNone(guard.refuse_completion())

    def test_a_change_after_a_clean_run_needs_proving_again(self) -> None:
        guard = CodingGuard(workspace=Path("/tmp"))
        guard.observe("write_file", {"path": "app.py"}, {"status": "success"})
        guard.observe("run_tests", {}, {"status": "success", "exit_code": 0})
        guard.observe("edit_file", {"path": "app.py"}, {"status": "success"})
        self.assertIsNotNone(guard.refuse_completion(), "a stale pass is not proof")

    def test_a_failing_check_is_not_proof(self) -> None:
        guard = CodingGuard(workspace=Path("/tmp"))
        guard.observe("write_file", {"path": "app.py"}, {"status": "success"})
        guard.observe("run_tests", {}, {"status": "error", "exit_code": 1})
        self.assertIn("failed", (guard.refuse_completion() or "").casefold())

    def test_a_file_must_be_read_before_it_is_edited(self) -> None:
        guard = CodingGuard(workspace=Path("/tmp"))
        self.assertIsNotNone(guard.refuse_before("edit_file", {"path": "app.py"}))
        guard.observe("read_file", {"path": "app.py"}, {"status": "success"})
        self.assertIsNone(guard.refuse_before("edit_file", {"path": "app.py"}))


class TodoTests(unittest.TestCase):
    def test_the_list_renders_what_is_being_worked_on(self) -> None:
        todos = TodoList()
        todos.replace([{"id": "1", "task": "read the file", "status": "completed"},
                       {"id": "2", "task": "fix the bug", "status": "in_progress"},
                       {"id": "3", "task": "run the tests", "status": "pending"}])
        rendered = todos.render()
        self.assertIn("[x] 1. read the file", rendered)
        self.assertIn("doing this now", rendered)
        self.assertIn("[ ] 3. run the tests", rendered)

    def test_malformed_entries_are_dropped_not_crashed_on(self) -> None:
        todos = TodoList()
        todos.replace([{"task": ""}, "nonsense", {"id": "2", "task": "real", "status": "bogus"}])
        self.assertEqual([item.task for item in todos.items], ["real"])
        self.assertEqual(todos.items[0].status, "pending")


class LoopTests(unittest.TestCase):
    def workspace(self, stack) -> Path:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        (directory / "calc.py").write_text("def multiply(a, b):\n    return a + b\n",
                                           encoding="utf-8")
        return directory

    def build(self, workspace: Path, turns: list[dict], calls: list, **kwargs) -> CodingLoop:
        def dispatch(name, arguments):
            calls.append((name, arguments))
            if name == "read_file":
                return {"status": "success", "content": (workspace / "calc.py").read_text()}
            if name == "run_tests":
                return {"status": "success", "exit_code": 0, "passed": True}
            return {"status": "success"}

        return CodingLoop(workspace=workspace, goal="fix multiply", client=FakeClient(turns),
                          tools=__import__("tacu.coding", fromlist=["coding_tool_schemas"]).coding_tool_schemas(), dispatch=dispatch, **kwargs)

    def test_a_finish_without_proof_is_refused_and_the_loop_continues(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            workspace = self.workspace(stack)
            calls: list = []
            turns = [
                call("write_file", path="calc.py", content="x"),
                {"content": "All done!", "tool_calls": []},          # refused: nothing proved
                call("run_tests"),
                {"content": "Fixed and tested.", "tool_calls": []},  # now allowed
            ]
            loop = self.build(workspace, turns, calls, max_steps=6)
            outcome = loop.run()
            self.assertTrue(outcome.completed)
            self.assertIn("Fixed and tested", outcome.answer)
            self.assertIn("run_tests", [name for name, _ in calls])

    def test_bookkeeping_does_not_spend_the_action_budget(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            workspace = self.workspace(stack)
            calls: list = []
            todo = call("todo_write", todos=[{"id": "1", "task": "t", "status": "completed"}])
            turns = [todo, todo, todo, todo,
                     {"content": "Nothing needed changing.", "tool_calls": []}]
            loop = self.build(workspace, turns, calls, max_steps=2)
            outcome = loop.run()
            # Four list rewrites did not exhaust a two-action budget.
            self.assertTrue(outcome.completed, outcome.stopped)

    def test_the_shell_is_stopped_before_it_rewrites_source(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            workspace = self.workspace(stack)
            calls: list = []
            turns = [call("shell", executable="bash", args=["-c", "echo x > calc.py"]),
                     {"content": "done", "tool_calls": []}]
            loop = self.build(workspace, turns, calls, max_steps=4)
            loop.run()
            self.assertNotIn("shell", [name for name, _ in calls], "the call must not reach the tool")
            self.assertEqual((workspace / "calc.py").read_text(),
                             "def multiply(a, b):\n    return a + b\n")

    def test_verification_on_the_twentieth_action_can_finish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            calls: list = []
            turns = [call("write_file", path="calc.py", content="x")]
            turns += [call("repo_map", depth=i) for i in range(18)]
            turns += [call("run_tests"),
                      call("todo_write", todos=[{"id": "1", "task": "fix", "status": "completed"}]),
                      {"content": "Fixed and verified.", "tool_calls": []}]
            loop = self.build(Path(directory), turns, calls, max_steps=20)
            outcome = loop.run()
            self.assertTrue(outcome.completed, outcome.stopped)
            self.assertTrue(outcome.verified)
            self.assertEqual(outcome.steps, 20)
            self.assertEqual(len(calls), 20)
            loop.snapshot.discard()

    def test_a_twenty_first_work_action_is_never_dispatched(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            calls: list = []
            turns = [call("repo_map", depth=i) for i in range(21)]
            loop = self.build(Path(directory), turns, calls, max_steps=20)
            outcome = loop.run()
            self.assertFalse(outcome.completed)
            self.assertEqual(outcome.stopped, "step budget")
            self.assertEqual(outcome.steps, 20)
            self.assertEqual(len(calls), 20)

    def test_the_system_prefix_is_identical_on_every_turn(self) -> None:
        import contextlib

        with contextlib.ExitStack() as stack:
            workspace = self.workspace(stack)
            calls: list = []
            turns = [call("read_file", path="calc.py"), call("read_file", path="calc.py"),
                     {"content": "done", "tool_calls": []}]
            loop = self.build(workspace, turns, calls, max_steps=6)
            loop.run()
            prefixes = {messages[0]["content"] for messages in loop.client.seen}
            # A prefix that varies throws away the model's cached attention for it.
            self.assertEqual(len(prefixes), 1, "the system prefix must be byte-stable")


class SnapshotTests(unittest.TestCase):
    def test_a_change_is_undone_and_a_new_file_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            original = workspace / "keep.py"
            original.write_text("print('one')\n", encoding="utf-8")
            snapshot = Snapshot(workspace=workspace)
            snapshot.take()

            original.write_text("print('broken')\n", encoding="utf-8")
            (workspace / "added.py").write_text("junk\n", encoding="utf-8")
            self.assertEqual(set(snapshot.changed()), {"keep.py", "added.py"})

            snapshot.restore()
            self.assertEqual(original.read_text(encoding="utf-8"), "print('one')\n")
            self.assertFalse((workspace / "added.py").exists())
            snapshot.discard()

    def test_heavy_directories_are_not_copied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "app.py").write_text("x\n", encoding="utf-8")
            heavy = workspace / "node_modules" / "pkg"
            heavy.mkdir(parents=True)
            (heavy / "index.js").write_text("y\n", encoding="utf-8")
            snapshot = Snapshot(workspace=workspace)
            snapshot.take()
            self.assertIn("app.py", snapshot.captured)
            self.assertFalse(any("node_modules" in name for name in snapshot.captured))
            snapshot.discard()


class ToolSurfaceTests(unittest.TestCase):
    def test_only_the_coding_tools_are_offered(self) -> None:
        from tacu.coding import CODING_TOOL_SURFACE, coding_tool_schemas

        names = [schema["function"]["name"] for schema in coding_tool_schemas()]
        self.assertEqual(names, list(CODING_TOOL_SURFACE))
        # The surface stays scoped on purpose: a small model given every tool
        # picks the wrong one. `process` and `network` are in because the lane
        # starts servers and needs to see whether they came up and what holds a
        # port; `system` and the specialised lanes are not.
        for hidden in ("forensics", "pcapread", "docker", "juicy", "system"):
            self.assertNotIn(hidden, names)

    def test_long_results_keep_both_ends_and_say_what_was_dropped(self) -> None:
        text = "\n".join(f"line {index}" for index in range(1, 2_000))
        trimmed = prune(text, limit=400)
        self.assertIn("line 1", trimmed)
        self.assertIn("line 1999", trimmed)
        self.assertIn("omitted", trimmed)


if __name__ == "__main__":
    unittest.main()
