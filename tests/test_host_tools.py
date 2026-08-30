"""Native host tools, parsers, capability routing, and GNU-command rewrite."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu.automation import CommandStep, create_plan, evaluate_policy, native_instead_of_shell, _rewrite_incompatible_step
from tacu.companion import exact_answer, exact_host_answer, extract_facts
from tacu.core import terminal_result
from tacu.host_parsers import parse_lsof_network, parse_netstat, parse_ps, summarize_destination_ports
from tacu.routing import native_steps_for_intent
from tacu.tools import ToolContext, invoke, specs


PS_BSD = """  PID  PPID USER             %CPU %MEM    RSS COMMAND
  312     1 _windowserver     18.4  1.2  180224 /System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer
 1040     1 bhupender          4.1  6.2 1887436 /Applications/Cursor.app/Contents/MacOS/Cursor
   89     1 root               0.1  0.3   42112 /usr/libexec/logd
"""

LSOF = """COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Google    501 bob    32u  IPv4 0xabc           0t0  TCP 192.168.1.19:55528->142.250.72.78:443 (ESTABLISHED)
Google    501 bob    33u  IPv4 0xabd           0t0  TCP 192.168.1.19:55512->142.250.72.78:443 (ESTABLISHED)
Cursor    880 bob    12u  IPv4 0xabe           0t0  TCP 127.0.0.1:5000 (LISTEN)
"""

NETSTAT = """Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  192.168.1.19.55528     142.250.72.78.443      ESTABLISHED
tcp4       0      0  192.168.1.19.55512     1.1.1.1.443            ESTABLISHED
tcp4       0      0  192.168.1.19.55483     9.9.9.9.443            ESTABLISHED
tcp4       0      0  127.0.0.1.5000         *.*                    LISTEN
"""


class ParserTests(unittest.TestCase):
    def test_ps_parser_ranks_cpu_and_memory(self) -> None:
        processes = parse_ps(PS_BSD)
        self.assertEqual(processes[0]["pid"], 312)
        self.assertEqual(processes[1]["rss_bytes"], 1887436 * 1024)
        from tacu.host_parsers import sort_processes
        self.assertEqual(sort_processes(processes, key="cpu", limit=1)[0]["pid"], 312)
        self.assertEqual(sort_processes(processes, key="memory", limit=1)[0]["pid"], 1040)

    def test_lsof_and_netstat_rank_destination_ports(self) -> None:
        lsof = parse_lsof_network(LSOF)
        self.assertEqual(lsof[0]["remote_port"], 443)
        self.assertEqual(lsof[2]["state"], "LISTEN")
        ranked = summarize_destination_ports(lsof)
        self.assertEqual(ranked[0]["port"], 443)
        self.assertEqual(ranked[0]["count"], 2)
        netstat = parse_netstat(NETSTAT)
        ranked = summarize_destination_ports(netstat)
        self.assertEqual(ranked[0]["port"], 443)
        self.assertEqual(ranked[0]["count"], 3)


class RoutingTests(unittest.TestCase):
    def test_screenshot_intents_select_native_tools_not_shell(self) -> None:
        cpu_ram = native_steps_for_intent("tell me the top process consuming highest cpu and ram")
        self.assertEqual({item["operation"] for item in cpu_ram}, {"top_cpu", "top_memory"})
        dest = native_steps_for_intent("show me those top destinations please")
        self.assertEqual(dest[0]["tool"], "network")
        self.assertEqual(dest[0]["operation"], "connections")
        ports = native_steps_for_intent("tell me the top tcp outbound established connection destination ports")
        self.assertEqual(ports[0]["tool"], "network")
        todo = native_steps_for_intent("map this project and find TODO markers")
        self.assertTrue(any(item["tool"] == "search_code" for item in todo))
        self.assertEqual(todo[0]["inputs"].get("query"), "TODO")
        code_search = native_steps_for_intent("search code for TODO")
        self.assertEqual(code_search[0]["tool"], "search_code")
        self.assertNotIn("operation", code_search[0]["inputs"])
        py_write = native_steps_for_intent('create a python script named hello.py with "print(1)"')
        self.assertEqual(py_write[0]["tool"], "write_file")
        self.assertEqual(py_write[0]["inputs"]["path"], "hello.py")
        self.assertEqual(py_write[0]["inputs"]["content"], "print(1)")
        self.assertNotIn("operation", py_write[0]["inputs"])
        mapped = native_steps_for_intent(
            "create a shell script that recursively looks into a directory and created a map of the directory"
        )
        self.assertEqual(mapped[0]["tool"], "write_file")
        self.assertEqual(mapped[0]["inputs"]["path"], "script.sh")
        self.assertIn("find ", mapped[0]["inputs"]["content"])
        self.assertFalse(native_steps_for_intent(
            "please create a python program file that adds two user supplied numbers"
        ))
        self.assertFalse(native_steps_for_intent(
            "please edit the file program.py and add user greeting at the top of the existing code"
        ))
        self.assertEqual(native_steps_for_intent("read program.py")[0]["tool"], "read_file")
        compared = native_steps_for_intent(
            "read README.txt and src/sample.py and confirm whether they contain the same marker"
        )
        self.assertEqual([item["tool"] for item in compared], ["read_file", "read_file"])
        self.assertEqual(
            [item["inputs"]["path"] for item in compared],
            ["README.txt", "src/sample.py"],
        )
        cwd = native_steps_for_intent("please share the full path of the current directory")
        self.assertEqual(cwd[0]["tool"], "system")
        self.assertEqual(cwd[0]["operation"], "cwd")
        listing = native_steps_for_intent("tell me how many files and folders we have in current directory")
        self.assertEqual(listing[0]["operation"], "listing")
        lsof = native_steps_for_intent("using lsof tell me which destinations have connections established on tcp 443")
        self.assertEqual(lsof[0]["tool"], "network")
        self.assertEqual(lsof[0]["inputs"].get("port"), 443)
        cpu = native_steps_for_intent("tell me the top process running most cpu")
        self.assertEqual(cpu[0]["operation"], "top_cpu")
        processing = native_steps_for_intent(
            "please tell me top ten processes consuming most processing")
        self.assertEqual(processing[0]["operation"], "top_cpu")
        self.assertEqual(processing[0]["inputs"]["limit"], 10)
        identity = native_steps_for_intent("what is my system name and ip address")
        self.assertTrue(any(item["operation"] == "hostname" for item in identity))
        self.assertTrue(any(item["tool"] == "network" and item["operation"] == "interfaces" for item in identity))
        remote_host = native_steps_for_intent(
            "how do i know which hostname does 45.60.16.77 resolve to ?"
        )
        self.assertTrue(remote_host)
        self.assertFalse(any(item["tool"] == "system" and item["operation"] == "hostname" for item in remote_host))
        self.assertEqual(remote_host[0]["tool"], "network")
        self.assertEqual(remote_host[0]["operation"], "resolve")
        self.assertEqual(remote_host[0]["inputs"].get("host"), "45.60.16.77")
        self.assertTrue(any(item["operation"] == "hostname" for item in native_steps_for_intent("what is my hostname")))
        public = native_steps_for_intent("which public ip i am using when going on internet traffic")
        self.assertEqual(public[0]["tool"], "network")
        self.assertEqual(public[0]["operation"], "public_ip")
        self.assertFalse(any(item["operation"] == "interfaces" for item in public))
        not_est = native_steps_for_intent(
            "tell me all the tcp 443 connection in other state than Established meaning not Established")
        self.assertEqual(not_est[0]["tool"], "network")
        self.assertEqual(not_est[0]["inputs"].get("state"), "NOT_ESTABLISHED")
        self.assertEqual(not_est[0]["inputs"].get("port"), 443)
        images = native_steps_for_intent("find all images on Desktop folder")
        self.assertEqual(images[0]["tool"], "filesystem")
        self.assertEqual(images[0]["operation"], "find")
        self.assertEqual(images[0]["inputs"].get("glob"), "images")
        self.assertTrue(str(images[0]["inputs"].get("root", "")).endswith("Desktop"))
        top_run = native_steps_for_intent("tell me top running processes")
        self.assertEqual(top_run[0]["operation"], "top_cpu")
        mem = native_steps_for_intent("tell me top 5 running processes as per memory")
        self.assertEqual(mem[0]["operation"], "top_memory")
        self.assertEqual(mem[0]["inputs"]["limit"], 5)
        mem2 = native_steps_for_intent("tell me top 5 running memory consuming processes")
        self.assertEqual(mem2[0]["operation"], "top_memory")
        from tacu.routing import is_shell_cd_intent
        self.assertTrue(is_shell_cd_intent("cd me into Desktop directory"))
        self.assertFalse(is_shell_cd_intent("find all images on Desktop folder"))
        installed = native_steps_for_intent("when was Falcon installed")
        self.assertTrue(any(item["tool"] == "application" and item["inputs"].get("name", "").lower() == "falcon"
                            for item in installed))
        rewritten = native_instead_of_shell("what is my system name and ip address", ["ifconfig", "all"])
        self.assertTrue(rewritten.is_native)
        self.assertEqual(rewritten.native_operation, "interfaces")
        html_intent = (
            "please crearte a simple index.html file with basic website and load it with chrome using python http server")
        printf = native_instead_of_shell(html_intent, ["printf", "<html>"])
        self.assertIsNotNone(printf)
        self.assertEqual(printf.native_operation, "write")
        server = native_instead_of_shell(html_intent, ["python3", "-m", "http.server", "8000"])
        self.assertIsNotNone(server)
        self.assertEqual(server.native_operation, "serve")
        note_intent = 'create a text file with the following content in it "hi from TACU"'
        tee = native_instead_of_shell(note_intent, ["tee", "message.txt"])
        self.assertIsNotNone(tee)
        self.assertEqual(tee.native_operation, "write")
        import json
        self.assertEqual(json.loads(tee.native_inputs).get("content"), "hi from TACU")
        self.assertEqual(json.loads(tee.native_inputs).get("name"), "note.txt")
        echo = native_instead_of_shell(note_intent, ["echo", "hi from TACU"])
        self.assertEqual(echo.native_operation, "write")
        grep_todo = native_instead_of_shell("search code for TODO", ["rg", "TODO", "."])
        self.assertIsNotNone(grep_todo)
        self.assertEqual(grep_todo.native_tool, "search_code")
        self.assertEqual(json.loads(grep_todo.native_inputs).get("query"), "TODO")
        self.assertNotIn("operation", json.loads(grep_todo.native_inputs))
        named = native_instead_of_shell("find the folder named myness on this computer", ["find", Path.home().as_posix(), "-name", "myness"])
        if named is not None:
            self.assertNotEqual(named.native_tool, "search_code")
        py_intent = 'create a python script named hello.py with "print(1)"'
        py_echo = native_instead_of_shell(py_intent, ["echo", "print(1)"])
        self.assertEqual(py_echo.native_tool, "write_file")
        self.assertEqual(json.loads(py_echo.native_inputs).get("path"), "hello.py")
        cat_read = native_instead_of_shell("read the source of app.py", ["cat", "app.py"])
        self.assertEqual(cat_read.native_tool, "read_file")
        self.assertEqual(json.loads(cat_read.native_inputs).get("path"), "app.py")
        top3 = native_steps_for_intent("top 3 processes is are consuming most CPU")
        self.assertEqual(top3[0]["inputs"]["limit"], 3)
        docker = native_steps_for_intent("show running docker containers")
        self.assertEqual(docker[0]["tool"], "docker")
        ollama_list = native_steps_for_intent(
            "please let me know which ollama models are there in the machine i am working on"
        )
        self.assertTrue(ollama_list)
        self.assertEqual(ollama_list[0]["tool"], "ollama")
        self.assertEqual(ollama_list[0]["operation"], "installed_models")
        cpu_not_ollama = native_steps_for_intent("which process is consuming most CPU")
        self.assertNotEqual(cpu_not_ollama[0]["tool"], "ollama")
        git_here = native_steps_for_intent("is current directory a git directory")
        self.assertEqual(git_here[0]["operation"], "is_repo")
        apps = native_steps_for_intent("tell me installed apps in Applications folder and is there any app that contain falcon in its name")
        self.assertTrue(any(item["tool"] == "application" and item["operation"] == "find"
                            and item["inputs"].get("name") == "falcon" for item in apps))
        self.assertTrue(any(item["tool"] == "application" and item["operation"] == "list"
                            and not item["inputs"].get("name") for item in apps))
        snake = native_steps_for_intent("tell me the full path of 'Snake_game.py'")
        self.assertEqual(snake[0]["tool"], "filesystem")
        self.assertEqual(snake[0]["inputs"].get("name"), "Snake_game.py")
        self.assertFalse(native_steps_for_intent("find the folder named myness on this computer"))
        brew = native_steps_for_intent("show outdated brew packages")
        self.assertEqual(brew[0]["tool"], "package")
        self.assertEqual(brew[0]["operation"], "outdated")
        services = native_steps_for_intent("list launchctl services")
        self.assertEqual(services[0]["tool"], "service")
        disk = native_steps_for_intent("how much disk space is free")
        self.assertEqual(disk[0]["operation"], "storage")
        gate = native_steps_for_intent("what is the gatekeeper status")
        self.assertEqual(gate[0]["tool"], "security")
        site_ask = (
            "please crearte a simple index.html file with basic website and load it with chrome using python http server")
        self.assertFalse(native_steps_for_intent(site_ask))
        text_ask = (
            'create a text file with the following content in it" hi this is a text file created by Tico, '
            'which is your Terminal Ally & Companion Unit"')
        note_native = native_steps_for_intent(text_ask)
        self.assertEqual(note_native[0]["tool"], "filesystem")
        self.assertEqual(note_native[0]["operation"], "write")
        remove_ask = "remove the index.html file"
        remove_native = native_steps_for_intent(remove_ask)
        self.assertEqual(remove_native[0]["tool"], "filesystem")
        self.assertEqual(remove_native[0]["operation"], "delete")
        from tacu.routing import extract_file_delete, extract_file_write, intent_writes_or_serves
        self.assertIsNone(extract_file_write(remove_ask))
        self.assertEqual(extract_file_delete(remove_ask), {"name": "index.html"})
        self.assertTrue(intent_writes_or_serves(
            'create a text file with the following content in it "hello"'))
        images = native_steps_for_intent("find all images on Desktop")
        self.assertEqual(images[0]["operation"], "find")
        self.assertFalse(any(item["operation"] in {"write", "serve", "delete"} for item in images))

    def test_create_plan_uses_native_recipe_without_calling_the_model(self) -> None:
        class NeverProvider:
            model = "must-not-run"
            def chat(self, *args, **kwargs):
                raise AssertionError("model should not plan host recipes")
            def models(self):
                return []
        with tempfile.TemporaryDirectory() as directory:
            plan = create_plan(NeverProvider(), "which process is consuming most CPU", Path(directory), 3)
            self.assertTrue(plan.steps[0].is_native)
            self.assertEqual(plan.steps[0].native_tool, "process")
            self.assertEqual(plan.steps[0].native_operation, "top_cpu")
            self.assertEqual(evaluate_policy(plan.steps[0], Path(directory)).level, "allow")
            self.assertIn("process(top_cpu", plan.steps[0].display)
            public = create_plan(NeverProvider(), "which public ip i am using when going on internet traffic",
                                 Path(directory), 3)
            self.assertEqual(public.steps[0].native_operation, "public_ip")
            self.assertEqual(evaluate_policy(public.steps[0], Path(directory)).level, "allow")

    def test_gnu_ps_pipeline_and_invalid_mdfind_are_rewritten(self) -> None:
        ps = CommandStep("ps", ("aux", "--sort=-%cpu", "|", "head", "10"), ".", "cpu")
        rewritten = _rewrite_incompatible_step(ps, "top cpu process")
        self.assertTrue(rewritten.is_native)
        self.assertEqual(rewritten.native_operation, "top_cpu")
        mdfind = CommandStep("mdfind", ('-t q -q """kMDItemKind == "Trash""""',), ".", "search")
        rewritten = _rewrite_incompatible_step(mdfind, "show me those top destinations please")
        self.assertEqual(rewritten.native_tool, "network")
        netstat = CommandStep("netstat", ("-an", "tcp", "ESTABLISHED", "outbound"), ".", "connections")
        rewritten = _rewrite_incompatible_step(netstat, "top tcp outbound destination ports")
        self.assertEqual(rewritten.native_tool, "network")
        lsof = CommandStep("lsof", ("-i", "tcp:443", "ESTABLISHED"), ".", "https")
        rewritten = _rewrite_incompatible_step(
            lsof, "using lsof tell me which destinations have connections established on tcp 443")
        self.assertEqual(rewritten.native_tool, "network")
        self.assertTrue(native_instead_of_shell("top process running most cpu", ["ps", "aux"]).is_native)
        docker = CommandStep("docker", ("ps", "", "--format", "{{.Names}}"), ".", "containers")
        rewritten = _rewrite_incompatible_step(docker, "list the running boxes in the engine")
        self.assertEqual(rewritten.native_tool, "docker")
        self.assertEqual(rewritten.native_operation, "ps")
        self.assertNotIn("", rewritten.args)

    def test_empty_docker_argv_from_the_model_is_stripped(self) -> None:
        class Provider:
            model = "mock"
            def chat(self, *args, **kwargs):
                return '{"summary":"docker","steps":[{"executable":"docker","args":["ps","","--format","{{.Names}}"],"cwd":".","purpose":"ps"}]}'
            def models(self):
                return []
        with tempfile.TemporaryDirectory() as directory:
            plan = create_plan(Provider(), "list the running boxes in the engine", Path(directory), 1,
                               allow_shell=True)
        self.assertTrue(plan.steps[0].is_native)
        self.assertEqual(plan.steps[0].native_tool, "docker")

    def test_macos_ps_aux_is_parsed_without_sending_raw_table_to_a_model(self) -> None:
        sample = """USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
bhupender         1040  12.4  6.2  4123456 1887436   ??  S    10:23AM   1:02.11 /Applications/Cursor.app/Contents/MacOS/Cursor
root                89   0.1  0.3   412000   42112   ??  Ss   25Aug26   0:01.02 /usr/libexec/logd
"""
        facts = extract_facts(sample, "ps aux")
        self.assertEqual(facts["kind"], "processes")
        self.assertEqual(facts["top_cpu"]["pid"], 1040)
        evidence = terminal_result(source="test", display_command="ps aux", stdout=sample.encode(), exit_code=0)
        answer = exact_answer("tell me the top process running most cpu", evidence)
        self.assertIn("Cursor", answer)


class CompanionHostAnswerTests(unittest.TestCase):
    def test_ps_and_netstat_questions_are_answered_natively(self) -> None:
        facts = extract_facts(PS_BSD, "ps -Ao pid,ppid,user,%cpu,%mem,rss,command")
        self.assertEqual(facts["kind"], "processes")
        evidence = terminal_result(source="test", display_command="ps", stdout=PS_BSD.encode(), exit_code=0)
        answer = exact_answer("which process is consuming most CPU", evidence)
        self.assertIn("WindowServer", answer)
        top3 = exact_answer("which top 3 process are consuming most CPU", evidence)
        self.assertIn("Top 3 processes by CPU", top3)
        self.assertIn("WindowServer", top3)
        self.assertIn("Cursor", top3)
        self.assertIn("logd", top3)
        net_facts = extract_facts(NETSTAT, "netstat -an")
        self.assertEqual(net_facts["destination_ports"][0]["port"], 443)
        evidence = terminal_result(source="test", display_command="netstat -an", stdout=NETSTAT.encode(), exit_code=0)
        answer = exact_answer("top tcp outbound destination ports", evidence)
        self.assertIn("443", answer)
        self.assertIn("3 established", answer)

    def test_exact_host_answer_combines_cpu_and_ram_tool_results(self) -> None:
        results = [
            {"result": {"data": {"operation": "top_cpu", "processes": parse_ps(PS_BSD)[:1],
                                 "top": parse_ps(PS_BSD)[0]}}},
            {"result": {"data": {"operation": "top_memory", "processes": [parse_ps(PS_BSD)[1]],
                                 "top": parse_ps(PS_BSD)[1]}}},
        ]
        answer = exact_host_answer("top process consuming highest cpu and ram", results)
        self.assertIn("Highest CPU", answer)
        self.assertIn("Highest RAM", answer)
        self.assertIn("Cursor", answer)

    def test_hostname_and_primary_ip_are_answered_without_a_model(self) -> None:
        results = [
            {"result": {"data": {"operation": "hostname", "system": {"hostname": "MACN-BHBHA-SB"}}}},
            {"result": {"data": {"operation": "interfaces",
                                 "primary": {"name": "en0", "ipv4": ["192.168.1.19"]}}}},
        ]
        answer = exact_host_answer("what is my system name and ip address", results)
        self.assertIn("MACN-BHBHA-SB", answer)
        self.assertIn("192.168.1.19", answer)
        self.assertIn("en0", answer)
        reverse = exact_host_answer(
            "how do i know which hostname does 45.60.16.77 resolve to ?",
            [{"result": {"data": {
                "operation": "hostname", "system": {"hostname": "MACN-BHBHA-SB"},
            }}}, {"result": {"data": {
                "operation": "resolve", "host": "45.60.16.77", "records": "", "reverse": True,
            }}}],
        )
        self.assertNotIn("MACN-BHBHA-SB", reverse or "")
        self.assertIn("45.60.16.77", reverse or "")
        self.assertIn("PTR", reverse or "")

    def test_public_ip_is_answered_without_a_model(self) -> None:
        results = [{"result": {"data": {
            "operation": "public_ip", "public_ip": "203.0.113.10", "source": "https://api.ipify.org",
        }}}]
        answer = exact_host_answer("which public ip i am using when going on internet traffic", results)
        self.assertIn("203.0.113.10", answer)
        self.assertNotIn("192.168.1.19", answer or "")

    def test_non_established_connections_are_not_described_as_established(self) -> None:
        results = [{"result": {"data": {
            "operation": "connections", "state": "NOT_ESTABLISHED", "port": 443,
            "connections": [{"state": "LISTEN", "local_port": 443, "command": "nginx", "remote_host": None}],
            "connection_count": 1, "destination_ports": [],
        }}}]
        answer = exact_host_answer("tcp 443 connection in other state than Established", results)
        self.assertIn("other than ESTABLISHED", answer)
        self.assertIn("LISTEN", answer)

    def test_app_install_answer_uses_mdls_creation_date(self) -> None:
        results = [{"result": {"data": {
            "operation": "metadata", "query": "Falcon",
            "applications": [{
                "name": "Falcon", "display_name": "Falcon",
                "path": "/Applications/Falcon.app",
                "fs_creation_date": "2026-05-06 23:27:53 +0000",
                "date_added": "2026-08-19 16:52:10 +0000",
            }],
        }}}]
        answer = exact_host_answer("when was Falcon installed", results)
        self.assertIn("2026-05-06 23:27:53 +0000", answer)
        self.assertIn("2026-08-19 16:52:10 +0000", answer)
        self.assertIn("Falcon", answer)


class CognitiveLoopTests(unittest.TestCase):
    def test_language_tasks_skip_the_loop_and_failed_state_filters_retry(self) -> None:
        from tacu.loop import (
            answer_needs_refine, correction_steps, is_language_fast_path, is_safety_refusal,
            mismatch_reason, wants_validation_loop,
        )
        self.assertTrue(is_language_fast_path("translate hello to French"))
        self.assertTrue(is_language_fast_path("translate this into polite language"))
        self.assertTrue(is_language_fast_path("explain why DNS records have a TTL"))
        self.assertTrue(is_language_fast_path("make this more polite"))
        self.assertFalse(is_language_fast_path("which process is consuming most CPU"))
        self.assertTrue(wants_validation_loop("run twice and validate the output"))
        self.assertEqual(
            answer_needs_refine("translate this into polite language", "Translate this into polite language."),
            "did not complete the language task",
        )
        self.assertIsNone(answer_needs_refine(
            "translate this into polite language",
            "I cannot translate that phrase because it is abusive.",
        ))
        self.assertTrue(is_safety_refusal("I cannot help with that request."))
        self.assertEqual(
            answer_needs_refine("summarize this output", "I did not inspect the disk.", {"result": {}}),
            "claimed no inspection despite tool evidence",
        )
        wrong = [{"command": ["network", "connections"], "result": {"data": {
            "operation": "connections", "state": "ESTABLISHED", "exit_code": 0,
            "connections": [{"state": "ESTABLISHED", "remote_port": 443, "remote_host": "1.1.1.1"}],
        }}}]
        intent = "tell me all the tcp 443 connection in other state than Established"
        reason = mismatch_reason(intent, wrong)
        self.assertEqual(reason, "connections_wrong_state")
        retry = correction_steps(intent, wrong, reason or "")
        self.assertEqual(retry[0]["inputs"]["state"], "NOT_ESTABLISHED")
        self.assertIsNone(mismatch_reason("which process is consuming most CPU", [{
            "result": {"data": {"operation": "top_cpu", "processes": parse_ps(PS_BSD), "exit_code": 0}},
        }]))
        self.assertEqual(
            correction_steps("cd me into Desktop directory",
                             [{"result": {"data": {"exit_code": 1}}}], "exit_nonzero"),
            [],
        )


class HostToolContractTests(unittest.TestCase):
    def test_host_tools_are_registered_beside_core_contracts(self) -> None:
        names = [spec.name for spec in specs()]
        self.assertEqual(names[:10], ["repo_map", "search_code", "read_file", "inspect_symbol", "edit_file",
                                      "write_file", "shell", "diagnostics", "run_tests", "task_state"])
        self.assertEqual(names[10:], ["process", "network", "system", "application", "ollama",
                                      "filesystem", "git", "docker", "service", "package", "security"])

    def test_process_top_cpu_returns_structured_rows(self) -> None:
        raw = {"exit_code": 0, "stdout": PS_BSD, "stderr": "", "command": ["/bin/ps"]}
        with tempfile.TemporaryDirectory() as directory, \
             patch("tacu.tools.process.run_argv", return_value=raw):
            result = invoke("process", {"operation": "top_cpu", "limit": 5},
                            ToolContext(Path(directory), Path(directory) / ".state"))
        self.assertTrue(result.ok)
        self.assertEqual(result.data["status"], "success")
        self.assertEqual(result.data["top"]["pid"], 312)
        self.assertLessEqual(len(result.data["processes"]), 5)

    def test_public_ip_uses_allowlisted_echo_service(self) -> None:
        class FakeResponse:
            def read(self, _size: int) -> bytes:
                return b"203.0.113.10\n"
            def __enter__(self) -> "FakeResponse":
                return self
            def __exit__(self, *_args: object) -> None:
                return None

        with tempfile.TemporaryDirectory() as directory, \
             patch("tacu.tools.network.urllib.request.urlopen", return_value=FakeResponse()):
            result = invoke("network", {"operation": "public_ip"},
                            ToolContext(Path(directory), Path(directory) / ".state"))
        self.assertTrue(result.ok)
        self.assertEqual(result.data["public_ip"], "203.0.113.10")
        self.assertEqual(result.data["source"], "https://api.ipify.org")

    def test_filesystem_write_fills_html_and_blocks_os_critical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = ToolContext(root, root / ".state")
            written = invoke("filesystem", {
                "operation": "write", "name": "index.html", "overwrite": True,
            }, context)
            self.assertTrue(written.ok)
            self.assertGreater(written.data["bytes_written"], 0)
            self.assertIn("Hello World", (root / "index.html").read_text())
            note = invoke("filesystem", {
                "operation": "write", "name": "note.txt",
                "content": "hi from TACU", "overwrite": True,
            }, context)
            self.assertTrue(note.ok)
            self.assertEqual((root / "note.txt").read_text(), "hi from TACU")
            removed = invoke("filesystem", {"operation": "delete", "name": "note.txt"}, context)
            self.assertTrue(removed.ok)
            self.assertTrue(removed.data["deleted"])
            self.assertFalse((root / "note.txt").exists())
            with patch("tacu.automation.os_critical_path", return_value=True):
                refused = invoke("filesystem", {
                    "operation": "write", "name": "passwd", "content": "nope", "overwrite": True,
                }, context)
            self.assertFalse(refused.ok)
            self.assertEqual(refused.error["code"], "os_critical")

    def test_filesystem_serve_detaches_without_waiting(self) -> None:
        class FakeProc:
            pid = 4242
            def poll(self):
                return None

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = ToolContext(root, root / ".state", approve_dangerous=True)
            with patch("tacu.tools.filesystem.subprocess.Popen", return_value=FakeProc()) as popped, \
                 patch("tacu.tools.filesystem.time.sleep"), \
                 patch("tacu.tools.filesystem.run_argv", return_value={"exit_code": 0}):
                result = invoke("filesystem", {
                    "operation": "serve", "port": 8000, "open_browser": True,
                }, context)
            self.assertTrue(result.ok)
            self.assertEqual(result.data["pid"], 4242)
            self.assertTrue(str(result.data["url"]).startswith("http://127.0.0.1:"))
            self.assertTrue(popped.called)
            kwargs = popped.call_args.kwargs
            self.assertTrue(kwargs.get("start_new_session"))
            denied = invoke("filesystem", {"operation": "serve", "port": 8000},
                            ToolContext(root, root / ".state", approve_dangerous=False))
            self.assertFalse(denied.ok)
            self.assertEqual(denied.error["code"], "approval_required")

    def test_exact_host_answer_reports_write_and_serve(self) -> None:
        results = [
            {"result": {"data": {
                "operation": "write", "path": "/tmp/demo/index.html", "bytes_written": 120,
            }}},
            {"result": {"data": {
                "operation": "serve", "url": "http://127.0.0.1:8000/", "pid": 99,
                "opened": True, "browser": "Google Chrome",
            }}},
        ]
        answer = exact_host_answer("create index.html and open in chrome", results)
        self.assertIn("Created `/tmp/demo/index.html`", answer)
        self.assertIn("120 bytes", answer)
        self.assertIn("http://127.0.0.1:8000/", answer)
        self.assertIn("Google Chrome", answer)
        self.assertIn("kill 99", answer)


class DockerOllamaGitCatalogTests(unittest.TestCase):
    def test_docker_inspect_intent_does_not_become_a_code_symbol(self) -> None:
        from tacu.harness import WRONG_OPERATION, correction_from_failure, critique_goal
        from tacu.routing import intent_host_domain, native_steps_for_intent, _symbol_from_intent

        intent = ("let me know which docker container is running and inspect its code "
                  "to determine its network, name and base image")
        self.assertEqual(intent_host_domain(intent), "docker")
        self.assertIsNone(_symbol_from_intent(intent))
        steps = native_steps_for_intent(intent)
        self.assertTrue(steps)
        self.assertTrue(all(item["tool"] == "docker" for item in steps))
        self.assertTrue(any(item["operation"] in {"ps", "inspect"} for item in steps))
        wrong = [{"result": {"tool": "inspect_symbol", "ok": True, "data": {"definitions": []}}}]
        self.assertEqual(critique_goal(intent, wrong), WRONG_OPERATION)
        retry = correction_from_failure(intent, WRONG_OPERATION)
        self.assertTrue(retry)
        self.assertEqual(retry[0]["tool"], "docker")

    def test_ollama_memory_does_not_route_to_system_top_memory(self) -> None:
        from tacu.routing import native_steps_for_intent

        steps = native_steps_for_intent(
            "please tell me which ollama model is currently running and how much memory it is allocated to take"
        )
        self.assertTrue(steps)
        self.assertEqual(steps[0]["tool"], "ollama")
        self.assertEqual(steps[0]["operation"], "running_models")
        self.assertFalse(any(item["tool"] == "process" for item in steps))

    def test_git_project_question_is_only_is_repo(self) -> None:
        from tacu.companion import exact_host_answer
        from tacu.routing import native_steps_for_intent

        steps = native_steps_for_intent("is the current directory a git project ?")
        self.assertTrue(steps)
        self.assertEqual(steps[0]["tool"], "git")
        self.assertEqual(steps[0]["operation"], "is_repo")
        self.assertFalse(any(item["operation"] != "is_repo" for item in steps))
        answer = exact_host_answer("is the current directory a git project ?", [{
            "result": {"data": {"operation": "is_repo", "root": "/tmp/tacu", "is_repo": True}},
        }])
        self.assertIn("is a Git repository", answer)
        self.assertNotIn("Next:", answer)
        self.assertNotIn("workspace", answer.casefold())

    def test_exact_answers_include_docker_network_and_ollama_size(self) -> None:
        from tacu.companion import exact_host_answer

        docker = exact_host_answer("inspect the running docker container", [{
            "result": {"data": {
                "operation": "inspect",
                "containers": [{"name": "tacu-searxng", "image": "searxng/searxng:latest",
                                "status": "running", "network": "bridge=172.17.0.2"}],
            }},
        }])
        self.assertIn("tacu-searxng", docker)
        self.assertIn("searxng/searxng:latest", docker)
        self.assertIn("bridge=172.17.0.2", docker)
        ollama = exact_host_answer("which ollama model is running and how much memory", [{
            "result": {"data": {
                "operation": "running_models",
                "models": [{"name": "gemma4:12b-mlx", "size": "7.4 GB"}],
            }},
        }])
        self.assertIn("gemma4:12b-mlx", ollama)
        self.assertIn("7.4 GB", ollama)
        self.assertNotIn("Cursor", ollama)

    def test_named_docker_stop_is_reviewed_not_a_listing(self) -> None:
        from tacu.core import TacuError
        from tacu.routing import docker_target_from_intent, intent_wants_host_mutate

        intent = "stop myness-searxng container"
        self.assertTrue(intent_wants_host_mutate(intent))
        self.assertEqual(docker_target_from_intent(intent), "myness-searxng")
        self.assertFalse(any(
            item["operation"] == "stop" for item in native_steps_for_intent(intent)
        ))
        steps = native_steps_for_intent(intent, include_host_mutate=True)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["tool"], "docker")
        self.assertEqual(steps[0]["operation"], "stop")
        self.assertEqual(steps[0]["inputs"].get("name"), "myness-searxng")
        quoted = 'i want you to stop the container named "myness-searxng"'
        self.assertEqual(docker_target_from_intent(quoted), "myness-searxng")
        unnamed = native_steps_for_intent("stop the container", include_host_mutate=True)
        self.assertFalse(any(item["operation"] == "stop" for item in unnamed))

        class NeverProvider:
            model = "must-not-run"
            def chat(self, *args, **kwargs):
                raise AssertionError("model should not plan host recipes")
            def models(self):
                return []

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = create_plan(NeverProvider(), intent, root, 3, allow_host_mutate=True)
            self.assertEqual(plan.steps[0].native_tool, "docker")
            self.assertEqual(plan.steps[0].native_operation, "stop")
            with self.assertRaises(TacuError) as raised:
                create_plan(NeverProvider(), quoted, root, 3, allow_host_mutate=False)
            self.assertIn("Reviewed execution", str(raised.exception))
            self.assertIn("ti do", str(raised.exception))

    def test_running_docker_intent_does_not_list_stopped_containers(self) -> None:
        steps = native_steps_for_intent(
            "tell me what all docker containers are running on my computer ?"
        )
        self.assertTrue(steps)
        self.assertEqual([item["operation"] for item in steps], ["ps"])

    def test_exact_docker_stop_is_not_duplicated_as_ollama(self) -> None:
        answer = exact_host_answer("stop the container named myness-searxng", [{
            "result": {
                "tool": "docker",
                "data": {"operation": "stop", "name": "myness-searxng", "exit_code": 0},
            },
        }])
        self.assertEqual(answer.count("Stopped"), 1)
        self.assertIn("myness-searxng", answer)
        self.assertNotIn("Ollama", answer)


if __name__ == "__main__":
    unittest.main()


class LocalClockCapabilityTests(unittest.TestCase):
    """`ti auto` / `ti do` answer date and time from the clock, never from the model."""

    def test_date_and_time_intents_route_to_the_clock_capability(self) -> None:
        for question in ("what is current date and time", "what date is today",
                         "what time is it", "what day of the week is it", "what year is it",
                         "todays date", "current time"):
            steps = native_steps_for_intent(question)
            self.assertTrue(steps, f"no native step for {question!r}")
            self.assertEqual((steps[0]["tool"], steps[0]["operation"]), ("system", "datetime"),
                             f"{question!r} did not route to the clock")

    def test_neighbouring_host_intents_are_not_hijacked(self) -> None:
        unaffected = {
            "how long has the system been up": ("system", "uptime"),
            "what is the boot time": ("system", "uptime"),
            "how much disk space is free": ("system", "storage"),
            "how much battery is left": ("system", "power"),
            "what is my system name": ("system", "hostname"),
            "which process is consuming most CPU": ("process", "top_cpu"),
        }
        for question, expected in unaffected.items():
            steps = native_steps_for_intent(question)
            self.assertTrue(steps, f"no native step for {question!r}")
            self.assertEqual((steps[0]["tool"], steps[0]["operation"]), expected,
                             f"{question!r} was hijacked by the clock capability")

    def test_clock_tool_reports_local_and_utc_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = ToolContext(workspace=Path(directory), state_dir=Path(directory))
            result = invoke("system", {"operation": "datetime"}, context)
        self.assertTrue(result.ok)
        facts = result.data["system"]
        for field in ("local_datetime", "local_date", "local_time", "day_of_week",
                      "utc_datetime", "readable"):
            self.assertIn(field, facts)
        self.assertTrue(facts["local_datetime"].startswith(facts["local_date"]))

    def test_clock_answer_is_deterministic_and_readable(self) -> None:
        results = [{"result": {"data": {
            "operation": "datetime",
            "system": {"readable": "Sunday, 30 August 2026 at 21:01", "timezone": "IST",
                       "utc_offset": "UTC+05:30",
                       "local_datetime": "2026-08-30T21:01:00+05:30"}}}}]
        answer = exact_host_answer("what is current date and time", results)
        self.assertIsNotNone(answer)
        self.assertIn("Sunday, 30 August 2026 at 21:01", answer)
        self.assertIn("IST", answer)
        self.assertIn("UTC+05:30", answer)
