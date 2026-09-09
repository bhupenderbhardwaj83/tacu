"""Real execution, HTTP acceptance and recovery around scripted coding decisions."""

from __future__ import annotations

import io
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, coding
from tacu.codingguard import CodingGuard, command_verifies
from tacu.codingloop import CodingLoop
from tacu.codingpolicy import dispatch_coding
from tacu.codingstate import CodingState
from tacu.execution import run_captured
from tacu.snapshot import Snapshot
from tacu.tools import ToolContext, invoke
from tacu.tools.service_process import execute as service, local_url


def call(tool, **arguments):
    return {"tool_calls": [{"name": tool, "arguments": arguments}]}


class Scripted:
    model = coding.CODING_MODEL

    def __init__(self, replies):
        self.replies = iter(replies)
        self.messages = []

    def chat_tools(self, messages, tools):
        self.messages.append(messages)
        result = next(self.replies, {"content": "Done."})
        if isinstance(result, Exception):
            raise result
        return result


class HarnessFixture(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.workspace = self.root / "project"
        self.workspace.mkdir()
        self.state = self.root / "state"
        self.context = ToolContext(self.workspace, self.state)
        self.stack.enter_context(patch.dict(os.environ, {"TACU_HOME": str(self.state), "TACU_PROVIDER": "ollama"}))
        self.stack.enter_context(patch.object(cli, "migrate_legacy_home", return_value=None))
        self.stack.enter_context(patch.object(coding, "release_other_models", return_value=[]))

    def loop(self, replies, **kwargs):
        return CodingLoop(workspace=self.workspace, goal=kwargs.pop("goal", "fix the application"),
                          client=Scripted(replies), tools=coding.coding_tool_schemas(),
                          dispatch=lambda n, a: dispatch_coding(n, a, self.workspace, self.state, invoke, lambda _: True),
                          **kwargs)

    def run_cli(self, words, replies=()):
        client = Scripted(replies)
        output = io.StringIO()
        with patch.object(cli, "load_provider", return_value=client), redirect_stdout(output), redirect_stderr(output):
            status = cli.main(["code", "--workspace", str(self.workspace), *words])
        return status, output.getvalue(), client

class HarnessTests(HarnessFixture):
    def test_explicit_custom_verification_passes_and_failure_blocks_completion(self):
        (self.workspace / "custom_check.py").write_text("assert 2 + 2 == 4\n")
        result = invoke("verify", {"executable": sys.executable, "args": ["custom_check.py"], "purpose": "arithmetic invariant"}, self.context)
        self.assertTrue(result.data["passed"], result)
        guard = CodingGuard(self.workspace)
        guard.observe("write_file", {"path": "app.py"}, {"status": "success"})
        guard.observe("verify", {}, result.data)
        self.assertIsNone(guard.refuse_completion())
        (self.workspace / "custom_check.py").write_text("assert False, 'broken invariant'\n")
        result = invoke("verify", {"executable": sys.executable, "args": ["custom_check.py"], "purpose": "arithmetic invariant"}, self.context)
        guard.observe("verify", {}, result.data)
        self.assertFalse(result.data["passed"])
        self.assertIsNotNone(guard.refuse_completion())

    def test_diagnostics_with_errors_or_no_files_are_not_proof(self):
        guard = CodingGuard(self.workspace)
        guard.observe("write_file", {"path": "app.py"}, {"status": "success"})
        for result in ({"files_checked": 1, "count": 1}, {"files_checked": 0, "count": 0}):
            guard.observe("diagnostics", {}, result)
            self.assertIsNotNone(guard.refuse_completion())
        self.assertFalse(command_verifies("echo pytest passed"))
        self.assertFalse(command_verifies("python -c 'print(\"pytest\")'"))

    def test_zero_tests_is_not_a_passing_suite(self):
        (self.workspace / "tests").mkdir()
        result = invoke("run_tests", {"framework": "unittest"}, self.context)
        self.assertTrue(result.ok)
        self.assertFalse(result.data["passed"])

    def test_unknown_tool_never_reaches_dispatch(self):
        loop = self.loop([call("docker", operation="rm", name="anything")])
        with patch.object(loop, "dispatch") as dispatch:
            result = loop._run_tool("docker", {"operation": "rm"})
        dispatch.assert_not_called()
        self.assertEqual(result["status"], "error")

    def test_policy_blocks_inline_code_and_reviews_unknown_commands(self):
        with patch("tacu.tools.shell.run_captured") as run:
            for executable in ("python3", str(self.workspace / ".venv/bin/python3")):
                result = dispatch_coding("shell", {"executable": executable, "args": ["-c", "pass"]},
                                         self.workspace, self.state, invoke, lambda _: self.fail("a block cannot be approved"))
                self.assertEqual(result["status"], "error")
            result = dispatch_coding("shell", {"executable": "unknown-program"}, self.workspace,
                                     self.state, invoke, lambda _: False)
            self.assertTrue(result["approval_required"])
            run.assert_not_called()

    def test_hundred_distinct_actions_complete_and_a_101st_cannot_run(self):
        for extra in (False, True):
            replies = [call("read_file", path=f"file{i}.py") for i in range(100 + int(extra))]
            replies.append({"content": "Inspected all files."})
            loop = self.loop(replies)
            executed = []
            loop.dispatch = lambda n, a: executed.append(a) or {"status": "success"}
            outcome = loop.run()
            self.assertEqual(outcome.steps, 100)
            self.assertEqual(len(executed), 100)
            self.assertEqual(outcome.completed, not extra)

    def test_repeated_errors_stop_early_with_the_actual_error(self):
        loop = self.loop([call("read_file", path="missing.py") for _ in range(100)])
        outcome = loop.run()
        self.assertFalse(outcome.completed)
        self.assertEqual(outcome.steps, 3)
        self.assertEqual(outcome.stopped, "repeated failure")
        self.assertIn("missing.py", outcome.answer)

    def test_empty_and_incomplete_answers_are_not_success(self):
        loop = self.loop([{"content": "", "done_reason": "length"}] * 10)
        self.assertEqual(loop.run().stopped, "no progress")
        loop = self.loop([call("todo_write", todos=[{"task": "implement", "status": "pending"}]), {"content": "Done."}])
        self.assertFalse(loop.run().completed)

    def test_resume_and_undo_use_durable_state_and_preserve_other_files(self):
        app = self.workspace / "app.py"
        app.write_text("VALUE = 1\n")
        (self.workspace / "check.py").write_text("from app import VALUE\nassert VALUE == 2\n")
        status, _, _ = self.run_cli(["change VALUE to two"], [call("read_file", path="app.py"),
            call("edit_file", path="app.py", old_text="VALUE = 1", new_text="VALUE = 2"), cli.TacuError("model offline")])
        self.assertEqual(status, 1)
        self.assertIn("VALUE = 2", app.read_text())
        status, output, _ = self.run_cli(["--status"])
        self.assertEqual(status, 0)
        self.assertIn("model error", output)
        # Use python3 without a global explicit path so this reviewed workspace
        # runner does not need a prompt in a noninteractive test invocation.
        status, output, client = self.run_cli(["--resume"], [call("verify", executable="python3", args=["check.py"], purpose="VALUE equals two"), {"content": "Changed and checked."}])
        self.assertEqual(status, 0, output)
        self.assertIn("change VALUE to two", json.dumps(client.messages))
        self.assertIn("app.py", json.dumps(client.messages))
        extra = self.workspace / "unrelated.py"
        extra.write_text("user work\n")
        status, output, _ = self.run_cli(["--undo"])
        self.assertEqual(status, 0, output)
        self.assertEqual(app.read_text(), "VALUE = 1\n")
        self.assertTrue(extra.exists())

    def test_undo_refuses_newer_edits(self):
        app = self.workspace / "app.py"
        app.write_text("x = 1\n")
        self.run_cli(["change x"], [call("read_file", path="app.py"),
                     call("edit_file", path="app.py", old_text="x = 1", new_text="x = 2"), cli.TacuError("offline")])
        app.write_text("x = 3 # user's later edit\n")
        status, output, _ = self.run_cli(["--undo"])
        self.assertEqual(status, 1)
        self.assertIn("newer work", output)
        self.assertIn("x = 3", app.read_text())

    def test_snapshot_tracks_nonstandard_files_and_deletions(self):
        target = self.workspace / ".special"
        target.write_text("original")
        snapshot = Snapshot(self.workspace)
        snapshot.capture(".special")
        target.unlink()
        self.assertEqual(snapshot.changed(), [".special"])
        snapshot.restore(snapshot.fingerprints())
        self.assertEqual(target.read_text(), "original")
        snapshot.discard()

    def test_workspace_checkpoint_lock_prevents_parallel_writers(self):
        state = CodingState(self.workspace, self.state)
        with state.lock():
            with self.assertRaises(cli.TacuError):
                with CodingState(self.workspace, self.state).lock():
                    pass

    @unittest.skipIf(os.name == "nt", "POSIX descriptor inheritance regression")
    def test_foreground_child_cannot_hold_a_capture_pipe_open(self):
        script = self.workspace / "fork.py"
        script.write_text("import os,time\nif os.fork()==0:\n time.sleep(2)\n os._exit(0)\nprint('parent done', flush=True)\n")
        started = time.monotonic()
        code, out, _, _ = run_captured([sys.executable, str(script)], cwd=self.workspace, timeout=1)
        self.assertEqual(code, 0)
        self.assertIn(b"parent done", out)
        self.assertLess(time.monotonic() - started, 1.5)


class ManagedServerTests(HarnessFixture):
    def port(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def start(self, **kwargs):
        port = self.port()
        (self.workspace / "index.html").write_text("<html>READY</html>")
        result = service(self.context, operation="start", executable=sys.executable,
                         args=["-m", "http.server", str(port), "--bind", "127.0.0.1"],
                         health_url=f"http://127.0.0.1:{port}/", contains="READY", timeout=4, **kwargs)
        self.addCleanup(lambda: service(self.context, operation="stop", service_id=result["service_id"]))
        self.assertTrue(result["healthy"], result)
        return result

    def test_server_survives_start_and_can_be_checked_and_stopped(self):
        result = self.start()
        checked = service(self.context, operation="check", service_id=result["service_id"])
        self.assertTrue(checked["healthy"], checked)
        logs = service(self.context, operation="logs", service_id=result["service_id"])
        self.assertIn("GET /", logs["stderr"])
        stopped = service(self.context, operation="stop", service_id=result["service_id"])
        self.assertTrue(stopped["stopped"])
        self.assertFalse(service(self.context, operation="check", service_id=result["service_id"])["healthy"])

    def test_running_server_must_pass_a_fresh_http_check_before_completion(self):
        result = self.start()
        loop = self.loop([], goal="run the web server")
        loop.guard.observe("service_process", {"operation": "start"}, result)
        self.assertIsNone(loop._completion_refusal())
        service(self.context, operation="stop", service_id=result["service_id"])
        self.assertIsNotNone(loop._completion_refusal())

    def test_server_does_not_claim_an_existing_listener(self):
        result = self.start()
        with self.assertRaisesRegex(Exception, "already occupied"):
            service(self.context, operation="start", executable=sys.executable, args=["bad.py"], health_url=result["url"])

    def test_failed_start_reports_logs_and_cleans_up(self):
        port = self.port()
        result = service(self.context, operation="start", executable=sys.executable, args=["missing.py"],
                         health_url=f"http://127.0.0.1:{port}/", timeout=2)
        self.assertFalse(result["healthy"])
        self.assertIn("missing.py", result["stderr"])
        self.assertFalse(service(self.context, operation="check", service_id=result["service_id"])["healthy"])

    def test_only_loopback_urls_and_workspace_service_ids_are_allowed(self):
        for url in ("http://example.com/", "http://127.0.0.1@evil.example/", "file:///tmp/file"):
            with self.assertRaises(Exception):
                local_url(url)
        result = self.start()
        other = self.root / "other"
        other.mkdir()
        with self.assertRaises(Exception):
            service(ToolContext(other, self.state), operation="stop", service_id=result["service_id"])


if __name__ == "__main__":
    unittest.main()
