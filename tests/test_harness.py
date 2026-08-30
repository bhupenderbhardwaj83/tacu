"""Capability harness: shortlist, validate, critique, correct."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu.automation import create_plan, evaluate_policy
from tacu.core import TacuError
from tacu.harness import (
    EDIT_CONTENT_MISMATCH, EDIT_DESTRUCTIVE, EDIT_MISSING, SERVE_NOT_STARTED, WRONG_OPERATION,
    WRITE_CONTENT_MISMATCH, WRITE_MISSING, WRITE_WRONG_NAME,
    correction_from_failure, critique_goal, parse_capability_plan, planner_shortlist,
    validate_capability_step,
)


class HarnessSpineTests(unittest.TestCase):
    def test_shortlist_surfaces_delete_for_remove(self) -> None:
        cards = planner_shortlist("remove the index.html file")
        self.assertTrue(any(item["operation"] == "delete" for item in cards))
        self.assertLessEqual(len(cards), 7)

    def test_remove_intent_is_not_a_write_goal(self) -> None:
        intent = "remove the index.html file"
        wrote = [{"result": {"ok": True, "data": {
            "operation": "write", "path": "/tmp/ws/index.html", "bytes_written": 201, "exit_code": 0,
        }}}]
        self.assertEqual(critique_goal(intent, wrote), WRONG_OPERATION)
        steps = correction_from_failure(intent, WRONG_OPERATION)
        self.assertEqual(steps[0]["operation"], "delete")
        self.assertEqual(steps[0]["inputs"]["name"], "index.html")

    def test_model_delete_plan_for_remove(self) -> None:
        class Provider:
            model = "fake"
            def chat(self, messages, *, stream):
                yield json.dumps({
                    "summary": "remove file",
                    "steps": [{
                        "tool": "filesystem",
                        "operation": "delete",
                        "inputs": {"name": "index.html"},
                        "purpose": "remove index.html",
                    }],
                })
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            plan = create_plan(Provider(), "remove the index.html file", Path(directory), 3)
        self.assertEqual(plan.steps[0].native_operation, "delete")
        self.assertEqual(evaluate_policy(plan.steps[0], Path(directory)).level, "prompt")

    def test_validate_capability_write_step(self) -> None:
        step = validate_capability_step({
            "tool": "filesystem",
            "operation": "write",
            "inputs": {"name": "note.txt", "content": "hello"},
            "purpose": "create note",
        }, index=1)
        self.assertEqual(step["inputs"]["name"], "note.txt")
        self.assertEqual(step["inputs"]["content"], "hello")
        write_file = validate_capability_step({
            "tool": "write_file",
            "operation": "write",
            "inputs": {"path": "src/hello.py", "content": "print(1)\n"},
            "purpose": "create script",
        }, index=1)
        self.assertEqual(write_file["inputs"]["path"], "src/hello.py")
        self.assertNotIn("operation", write_file["inputs"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            abs_write = validate_capability_step({
                "tool": "write_file",
                "operation": "write",
                "inputs": {"path": str(root / "program.py"), "content": "print(1)\n"},
                "purpose": "create script",
            }, index=1, workspace=root)
        self.assertEqual(abs_write["inputs"]["path"], "program.py")
        with self.assertRaises(TacuError):
            validate_capability_step({
                "tool": "write_file",
                "operation": "write",
                "inputs": {"path": "/etc/passwd", "content": "x"},
            }, index=1, workspace=Path("/tmp"))
        with self.assertRaises(TacuError):
            validate_capability_step({
                "tool": "filesystem", "operation": "not_real", "inputs": {},
            }, index=1)

    def test_parse_capability_plan_json(self) -> None:
        raw = json.dumps({
            "schema": "tacu.capability-plan/v1",
            "summary": "write",
            "steps": [{
                "tool": "filesystem",
                "operation": "write",
                "inputs": {"name": "a.txt", "content": "x"},
                "purpose": "write",
            }],
        })
        steps = parse_capability_plan(raw, limit=3)
        self.assertEqual(steps[0]["operation"], "write")

    def test_model_capability_plan_becomes_native_steps(self) -> None:
        class Provider:
            model = "fake"
            def chat(self, messages, *, stream):
                yield json.dumps({
                    "summary": "create file",
                    "steps": [{
                        "tool": "filesystem",
                        "operation": "write",
                        "inputs": {"name": "note.txt", "content": "from model"},
                        "purpose": "write note",
                    }],
                })
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            # Intent with no native hit so the model capability path runs.
            plan = create_plan(Provider(), "do something unusual with files maybe", Path(directory), 3)
        self.assertTrue(plan.steps[0].is_native)
        self.assertEqual(plan.steps[0].native_operation, "write")
        self.assertEqual(evaluate_policy(plan.steps[0], Path(directory)).level, "log")
        payload = json.loads(plan.steps[0].native_inputs)
        self.assertEqual(payload.get("content"), "from model")

    def test_capability_step_coerces_string_integers(self) -> None:
        step = validate_capability_step({
            "tool": "process",
            "operation": "top_cpu",
            "inputs": {"limit": "10"},
            "purpose": "top cpu",
        }, index=1)
        self.assertEqual(step["inputs"]["limit"], 10)
        self.assertIsInstance(step["inputs"]["limit"], int)

    def test_auto_rejects_shell_fallback(self) -> None:
        class Provider:
            model = "fake"
            def chat(self, messages, *, stream):
                yield json.dumps({
                    "summary": "shell",
                    "steps": [{"executable": "rg", "args": ["TODO", "."], "cwd": ".", "purpose": "find"}],
                })
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(TacuError) as ctx:
                create_plan(
                    Provider(),
                    "count the frobnitz widgets on this host",
                    Path(directory),
                    3,
                    allow_shell=False,
                )
            self.assertIn("capability", str(ctx.exception).casefold())

    def test_shortlist_gates_match_native_confidence(self) -> None:
        from tacu.routing import SHORTLIST_MIN_SCORE, shortlist_capabilities

        intent = "which process is consuming most CPU"
        native = shortlist_capabilities(intent)
        cards = planner_shortlist(intent)
        self.assertTrue(native)
        self.assertTrue(all(score >= SHORTLIST_MIN_SCORE for score, _ in native))
        self.assertTrue(all(card["score"] >= SHORTLIST_MIN_SCORE for card in cards))

    def test_catalog_covers_host_spec_operations(self) -> None:
        from collections import defaultdict
        from tacu.routing import CAPABILITIES
        from tacu.tools.registry import HOST_MODULES

        have = defaultdict(set)
        for item in CAPABILITIES:
            have[item.tool].add(item.operation)
        missing = []
        for module in HOST_MODULES:
            name = module.SPEC.name
            props = (module.SPEC.input_schema or {}).get("properties") or {}
            for operation in ((props.get("operation") or {}).get("enum") or []):
                if operation not in have[name]:
                    missing.append(f"{name}.{operation}")
        self.assertEqual(missing, [])

    def test_host_mutate_excluded_from_auto_shortlist(self) -> None:
        cards = planner_shortlist("kill process pid 1234", include_host_mutate=False)
        self.assertFalse(any(item["operation"] == "kill" for item in cards))
        reviewed = planner_shortlist("kill process pid 1234", include_host_mutate=True)
        self.assertTrue(any(item["operation"] == "kill" for item in reviewed))
        from tacu.harness import shortlist_prompt_block
        block = shortlist_prompt_block("brew install wget", include_host_mutate=True)
        self.assertIn('"risk":"host_mutate"', block)
        self.assertIn('"score":', block)

    def test_intent_pins_specialized_tool_family(self) -> None:
        from tacu.harness import shortlist_prompt_block
        from tacu.routing import TOOL_FAMILIES, intent_tool_family

        cases = {
            "read program.py": "read",
            "please edit the file program.py and add a comment": "edit",
            'create a python script named hello.py with "print(1)"': "write",
            "search code for TODO": "search",
            "find files matching *.py": "glob",
            "remove the index.html file": "delete",
            "run program.py": "run",
            "where is function greet defined": "inspect",
        }
        for intent, family in cases.items():
            with self.subTest(intent=intent):
                self.assertEqual(intent_tool_family(intent), family)
                cards = planner_shortlist(intent)
                wanted = {pair[0] for pair in TOOL_FAMILIES[family]}
                self.assertTrue(any(card["tool"] in wanted for card in cards), msg=intent)
        block = shortlist_prompt_block("please edit the file program.py and add a comment")
        self.assertIn('"family":"edit"', block)
        self.assertIn('"when":', block)
        self.assertIn("edit_file", block)

    def test_critique_write_and_serve_goals(self) -> None:
        intent = 'create a text file with the following content in it "hi from TACU"'
        self.assertEqual(critique_goal(intent, []), WRITE_MISSING)
        wrong = [{"result": {"ok": True, "data": {
            "operation": "write", "path": "/tmp/ws/other.txt", "bytes_written": 12, "exit_code": 0,
        }}}]
        self.assertEqual(critique_goal(intent, wrong), WRITE_WRONG_NAME)
        mismatch = [{"result": {"ok": True, "data": {
            "operation": "write", "path": "/tmp/ws/note.txt", "bytes_written": 1, "exit_code": 0,
        }}}]
        self.assertEqual(critique_goal(intent, mismatch), WRITE_CONTENT_MISMATCH)
        ok = [{"result": {"ok": True, "data": {
            "operation": "write", "path": "/tmp/ws/note.txt",
            "bytes_written": len("hi from TACU".encode()), "exit_code": 0,
        }}}]
        self.assertIsNone(critique_goal(intent, ok))
        site = "create index.html website and load it with chrome using python http server"
        from tacu.routing import extract_file_write
        site_spec = extract_file_write(site)
        assert site_spec is not None
        only_write = [{"result": {"ok": True, "data": {
            "operation": "write", "path": "/tmp/ws/index.html",
            "bytes_written": len(site_spec["content"].encode()), "exit_code": 0,
        }}}]
        self.assertEqual(critique_goal(site, only_write), SERVE_NOT_STARTED)
        complete = only_write + [{"result": {"ok": True, "data": {
            "operation": "serve", "url": "http://127.0.0.1:8000/", "pid": 9, "exit_code": 0,
        }}}]
        self.assertIsNone(critique_goal(site, complete))

    def test_correction_from_failure_rebuilds_write(self) -> None:
        intent = 'create a text file with the following content in it "hi from TACU"'
        steps = correction_from_failure(intent, WRITE_MISSING)
        self.assertEqual(steps[0]["operation"], "write")
        self.assertEqual(steps[0]["inputs"]["content"], "hi from TACU")
        serve = correction_from_failure(
            "create index.html and open in chrome with http.server", SERVE_NOT_STARTED)
        self.assertTrue(any(item["operation"] == "serve" for item in serve))

    def test_python_program_without_source_is_not_an_empty_native_write(self) -> None:
        from tacu.routing import extract_file_write, native_steps_for_intent, prefers_coding_write

        intent = "please create a python program file that adds two user supplied numbers"
        spec = extract_file_write(intent)
        self.assertIsNotNone(spec)
        self.assertEqual(spec["name"], "program.py")
        self.assertFalse(spec["content_supplied"])
        self.assertTrue(prefers_coding_write(intent, spec["name"]))
        self.assertFalse(native_steps_for_intent(intent))
        self.assertEqual(correction_from_failure(intent, WRITE_CONTENT_MISMATCH), [])
        empty_txt = [{"result": {"ok": True, "data": {
            "path": "/tmp/ws/note.txt", "bytes_written": 0, "exit_code": 0,
        }}}]
        self.assertEqual(critique_goal(intent, empty_txt), WRITE_WRONG_NAME)
        empty_py = [{"result": {"ok": True, "data": {
            "path": "/tmp/ws/program.py", "bytes_written": 0, "exit_code": 0,
        }}}]
        self.assertEqual(critique_goal(intent, empty_py), WRITE_CONTENT_MISMATCH)
        ok = [{"result": {"ok": True, "data": {
            "path": "/tmp/ws/adder.py", "bytes_written": 64, "exit_code": 0,
        }}}]
        self.assertIsNone(critique_goal(intent, ok))
        with self.assertRaises(TacuError) as ctx:
            validate_capability_step({
                "tool": "write_file",
                "operation": "write",
                "inputs": {"path": "note.txt", "overwrite": True, "create_parents": True},
            }, index=1)
        self.assertIn("non-empty content", str(ctx.exception).casefold())
        cards = planner_shortlist(intent)
        self.assertTrue(any(item["tool"] == "write_file" for item in cards))
        from tacu.harness import shortlist_prompt_block
        block = shortlist_prompt_block(intent)
        self.assertIn('"required":["path","content"]', block)

    def test_directory_map_shell_script_is_a_native_write(self) -> None:
        from tacu.routing import extract_file_write, native_steps_for_intent

        intent = (
            "create a shell script that recursively looks into a directory "
            "and created a map of the directory"
        )
        spec = extract_file_write(intent)
        self.assertIsNotNone(spec)
        self.assertEqual(spec["name"], "script.sh")
        native = native_steps_for_intent(intent)
        self.assertEqual(native[0]["tool"], "write_file")
        self.assertEqual(native[0]["inputs"]["path"], "script.sh")
        self.assertIn("find ", native[0]["inputs"]["content"])
        self.assertFalse(any(item["tool"] == "repo_map" for item in native))

        class NeverProvider:
            model = "fake"
            def chat(self, messages, *, stream):
                raise AssertionError("directory-map script should not need the model")
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            plan = create_plan(NeverProvider(), intent, Path(directory), 3, allow_shell=False)
        self.assertEqual(plan.raw, "native-capability")
        self.assertEqual(plan.steps[0].native_tool, "write_file")
        payload = json.loads(plan.steps[0].native_inputs)
        self.assertTrue(payload["content"].strip())

    def test_edit_intent_uses_model_and_quoted_replace_stays_native(self) -> None:
        from tacu.routing import apply_known_file_edit, intent_is_file_edit, native_steps_for_intent

        intent = (
            "please edit the file program.py and add user greeting at the top of the "
            "existing code block with user instruction."
        )
        self.assertTrue(intent_is_file_edit(intent))
        self.assertFalse(native_steps_for_intent(intent))
        self.assertIsNone(apply_known_file_edit(intent, "program.py", "print(1)\n"))
        self.assertEqual(native_steps_for_intent("read program.py")[0]["tool"], "read_file")
        only_read = [{"result": {"ok": True, "data": {
            "path": "/tmp/ws/program.py", "content": "1 | print(1)", "line_count": 1, "exit_code": 0,
        }}}]
        self.assertEqual(critique_goal(intent, only_read), EDIT_MISSING)
        self.assertEqual(correction_from_failure(intent, EDIT_MISSING), [])
        wrote = [{"result": {"ok": True, "data": {
            "path": "/tmp/ws/program.py", "bytes_written": 80, "changed": True, "exit_code": 0,
        }}}]
        self.assertIsNone(critique_goal(intent, wrote))

        original = "num1 = float(input('Enter first number: '))\nprint(num1)\n"
        greeting = 'name = input("Enter your name: ")\nprint(f"Hello, {name}!")\n'
        updated = greeting + original
        test = self

        class EditProvider:
            model = "fake"
            def chat(self, messages, *, stream):
                blob = messages[-1]["content"]
                test.assertIn("num1 = float", blob)
                test.assertIn("Current file", blob)
                yield json.dumps({
                    "schema": "tacu.capability-plan/v1",
                    "summary": "prepend greeting",
                    "steps": [{
                        "tool": "write_file",
                        "operation": "write",
                        "inputs": {"path": "program.py", "content": updated, "overwrite": True},
                        "purpose": "edit program.py",
                    }],
                })
            def models(self):
                return [self.model]

        class NeverProvider:
            model = "fake"
            def chat(self, messages, *, stream):
                raise AssertionError("quoted replace should not need the model")
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "program.py"
            path.write_text(original)
            plan = create_plan(EditProvider(), intent, Path(directory), 3, allow_shell=False)
            self.assertEqual(plan.steps[0].native_tool, "write_file")
            payload = json.loads(plan.steps[0].native_inputs)
            self.assertTrue(payload["content"].startswith("name = input("))
            self.assertIn("num1 = float(input", payload["content"])
            swap = 'replace "print(num1)" with "print(num1 * 2)" in program.py'
            swapped = create_plan(NeverProvider(), swap, Path(directory), 3, allow_shell=False)
            swapped_payload = json.loads(swapped.steps[0].native_inputs)
            self.assertIn("print(num1 * 2)", swapped_payload["content"])
            self.assertNotIn("print(num1)\n", swapped_payload["content"])

    def test_edit_critic_checks_quoted_text_and_does_not_invent_source(self) -> None:
        from tacu.automation import CommandStep
        from tacu.harness import format_critic_evidence, snapshot_edit_targets
        from tacu.routing import apply_known_file_edit

        original = (
            'name = input("Enter your name: ")\n'
            'print(f"Hello, {name}!")\n'
            "num1 = float(input('Enter first number: '))\n"
            "num2 = float(input('Enter second number: '))\n"
            "print(f'The sum is: {num1 + num2}')\n"
        )
        quoted = (
            'please edit the file program.py and add "thanks to {name}" at the bottom '
            "of the existing code block to greet thanks to user."
        )
        self.assertIsNone(apply_known_file_edit(quoted, "program.py", original))
        good = original + 'print(f"thanks to {name}")\n'
        dropped = 'print(f"thanks to {name}")\n'
        test = self

        class AppendProvider:
            model = "fake"
            def chat(self, messages, *, stream):
                blob = messages[-1]["content"]
                test.assertIn("Current file", blob)
                test.assertIn("num1 = float", blob)
                yield json.dumps({
                    "schema": "tacu.capability-plan/v1",
                    "summary": "append thanks",
                    "steps": [{
                        "tool": "write_file",
                        "operation": "write",
                        "inputs": {"path": "program.py", "content": good, "overwrite": True},
                        "purpose": "edit program.py",
                    }],
                })
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "program.py"
            path.write_text(original)
            before = snapshot_edit_targets(quoted, root)
            plan = create_plan(AppendProvider(), quoted, root, 3, allow_shell=False)
            payload = json.loads(plan.steps[0].native_inputs)
            self.assertEqual(payload["content"].count("name = input("), 1)
            self.assertTrue(payload["content"].rstrip().endswith('print(f"thanks to {name}")'))
            path.write_text(payload["content"])
            wrote = [{"result": {"ok": True, "data": {
                "path": str(path), "bytes_written": len(payload["content"]), "changed": True, "exit_code": 0,
            }}}]
            self.assertIsNone(critique_goal(quoted, wrote, workspace=root, before=before))
            path.write_text(dropped)
            self.assertEqual(
                critique_goal(quoted, wrote, workspace=root, before=before),
                EDIT_DESTRUCTIVE,
            )
            path.write_text(original + "print('hello again')\n")
            self.assertEqual(
                critique_goal(quoted, wrote, workspace=root, before=before),
                EDIT_CONTENT_MISMATCH,
            )
            evidence = format_critic_evidence(quoted, wrote, root)
            self.assertIn("program.py", evidence)

        shown = CommandStep(
            "edit_file", ("edit",), ".", "edit",
            native_tool="edit_file", native_operation="edit",
            native_inputs=json.dumps({
                "path": "program.py",
                "expected_matches": 1,
                "old_text": 'print(f"Hello, {name}!")',
                "new_text": 'print(f"Hello, {name}!")\nprint(f"thanks to {name}")',
            }),
        ).display
        self.assertNotIn("Hello", shown)
        self.assertIn("old_text=", shown)
        self.assertIn("bytes", shown)

    def test_malformed_and_shell_plans_salvage_write_file(self) -> None:
        intent = "please create a python program file that adds two user supplied numbers"
        source = "a = int(input())\nb = int(input())\nprint(a + b)\n"

        class FencedProvider:
            model = "fake"
            def chat(self, messages, *, stream):
                yield "Sure:\n```python\n" + source + "```\n"
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            plan = create_plan(FencedProvider(), intent, Path(directory), 3, allow_shell=False)
        payload = json.loads(plan.steps[0].native_inputs)
        self.assertEqual(plan.steps[0].native_tool, "write_file")
        self.assertIn("print(a + b)", payload["content"])

        class ShellThenBody:
            model = "fake"
            def __init__(self):
                self.calls = 0
            def chat(self, messages, *, stream):
                self.calls += 1
                if self.calls == 1:
                    yield json.dumps({
                        "summary": "map dir",
                        "steps": [{"executable": "find", "args": [".", "-print"], "cwd": ".", "purpose": "map"}],
                    })
                else:
                    yield json.dumps({"path": "adder.py", "content": source})
            def models(self):
                return [self.model]

        provider = ShellThenBody()
        with tempfile.TemporaryDirectory() as directory:
            plan = create_plan(provider, intent, Path(directory), 3, allow_shell=False)
        self.assertEqual(plan.steps[0].native_tool, "write_file")
        payload = json.loads(plan.steps[0].native_inputs)
        self.assertEqual(payload["path"], "adder.py")
        self.assertEqual(payload["content"], source)
        self.assertNotIn("ti ask", str(plan.summary).casefold())

    def test_capability_json_tolerates_fences_commas_and_unwrapped_steps(self) -> None:
        raw = (
            "Here is the plan:\n```json\n"
            '{"tool":"write_file","operation":"write",'
            '"inputs":{"path":"ok.py","content":"print(1)\\n",},}\n'
            "```\n"
        )
        steps = parse_capability_plan(raw, limit=3)
        self.assertEqual(steps[0]["tool"], "write_file")
        self.assertEqual(steps[0]["inputs"]["path"], "ok.py")
        compact = parse_capability_plan(
            json.dumps({"path": "ok.sh", "content": "#!/bin/sh\necho hi\n"}),
            limit=3,
        )
        self.assertEqual(compact[0]["tool"], "write_file")
        self.assertEqual(compact[0]["inputs"]["path"], "ok.sh")

    def test_model_write_file_plan_supplies_program_body(self) -> None:
        source = "a=int(input())\nb=int(input())\nprint(a+b)\n"

        captured: list[str] = []

        class Provider:
            model = "fake"
            def chat(self, messages, *, stream):
                captured.append(messages[0]["content"] + messages[1]["content"])
                yield json.dumps({
                    "schema": "tacu.capability-plan/v1",
                    "summary": "create adder",
                    "steps": [{
                        "tool": "write_file",
                        "operation": "write",
                        "inputs": {"path": "adder.py", "content": source},
                        "purpose": "create python adder",
                    }],
                })
            def models(self):
                return [self.model]

        with tempfile.TemporaryDirectory() as directory:
            plan = create_plan(
                Provider(),
                "please create a python program file that adds two user supplied numbers",
                Path(directory),
                3,
            )
        self.assertTrue(captured)
        self.assertIn("write_file", captured[0])
        self.assertIn("non-empty", captured[0].casefold())
        self.assertIn("relative", captured[0].casefold())
        self.assertEqual(plan.steps[0].native_tool, "write_file")
        payload = json.loads(plan.steps[0].native_inputs)
        self.assertEqual(payload["path"], "adder.py")
        self.assertEqual(payload["content"], source)
        self.assertNotIn("operation", payload)
        self.assertIn("path=adder.py", plan.steps[0].display)
        self.assertNotIn("write_file(write", plan.steps[0].display)

    def test_docker_domain_is_not_pinned_to_inspect_symbol(self) -> None:
        cards = planner_shortlist(
            "let me know which docker container is running and inspect its code"
        )
        self.assertTrue(any(item["tool"] == "docker" for item in cards))
        self.assertFalse(any(item["tool"] == "inspect_symbol" for item in cards))


if __name__ == "__main__":
    unittest.main()
