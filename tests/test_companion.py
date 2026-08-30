"""Exact-answer companion behavior for intentionally verbose command output."""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, companion, core

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
    inet 127.0.0.1 netmask 0xff000000
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    ether 7a:d0:1f:40:9a:fb
    status: inactive
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    ether be:ac:7d:15:d1:5b
    inet 192.168.1.19 netmask 0xffffff00 broadcast 192.168.1.255
    status: active
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
    inet 10.8.0.2 netmask 0xffffff00
"""

DOCKER_INSPECT = """[{"Id":"abc123","Name":"/myness-searxng","State":{"Status":"running","Running":true},
"Image":"sha256:deadbeef","HostConfig":{"Privileged":false,"RestartPolicy":{"Name":"unless-stopped"}},
"Config":{"Image":"searxng/searxng:latest","Labels":{"org.opencontainers.image.title":"SearXNG","org.opencontainers.image.version":"2026.8.22"}},
"NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"8888"}]},"Networks":{"bridge":{"IPAddress":"172.17.0.2","Gateway":"172.17.0.1"}}},
"ImageManifestDescriptor":{"platform":{"architecture":"arm64","os":"linux"}},"Platform":"linux","Mounts":[]}]"""


class CompanionTests(unittest.TestCase):
    def test_ifconfig_facts_select_active_primary_interface(self) -> None:
        facts = companion.extract_facts(IFCONFIG, "ifconfig")
        self.assertEqual(facts["primary"]["name"], "en0")
        self.assertEqual(facts["primary"]["ipv4"], ["192.168.1.19"])
        self.assertEqual(facts["primary"]["ipv4_networks"], ["192.168.1.0/24"])

    def test_subnet_question_is_native_and_does_not_call_the_model(self) -> None:
        class NeverProvider:
            model = "must-not-run"
            def chat(self, *args, **kwargs): raise AssertionError("model should not be called")
        evidence = core.terminal_result(source="test", display_command="ifconfig", stdout=IFCONFIG.encode(), exit_code=0)
        with tempfile.TemporaryDirectory() as directory, core.HistoryStore(Path(directory) / "history.db") as store,              redirect_stdout(io.StringIO()):
            turn = cli.ask(store=store, client=NeverProvider(), query="what the subnet my computer is on ?",
                           tool_result=evidence, stream=False)
        self.assertTrue(turn.response.startswith(
            "Primary interface: en0\nIPv4 address: 192.168.1.19\nSubnet: 192.168.1.0/24"
        ))
        self.assertIn("Next: Check the gateway and DNS configuration too?", turn.response)
        self.assertEqual(turn.model, "tacu/native")

    def test_network_question_returns_only_human_readable_answer(self) -> None:
        evidence = core.terminal_result(source="test", display_command="ifconfig", stdout=IFCONFIG.encode(), exit_code=0)
        answer = companion.exact_answer("What IP is assigned to the primary interface?", evidence)
        self.assertEqual(answer, "Primary interface: en0\nIPv4 address: 192.168.1.19")

    def test_linux_ip_addr_text_and_json_are_supported(self) -> None:
        text = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.0.2.15/24 brd 10.0.2.255\n"
        facts = companion.extract_facts(text, "ip addr")
        self.assertEqual(facts["primary"]["ipv4"], ["10.0.2.15"])
        self.assertEqual(facts["primary"]["ipv4_networks"], ["10.0.2.0/24"])
        value = [{"ifname": "eth0", "operstate": "UP", "flags": ["UP", "RUNNING"],
                  "addr_info": [{"family": "inet", "local": "10.0.2.15", "prefixlen": 24}]}]
        facts = companion.extract_facts("", "ip -json address", value)
        self.assertEqual(facts["primary"]["name"], "eth0")
        self.assertEqual(facts["primary"]["ipv4_networks"], ["10.0.2.0/24"])

    def test_windows_ipconfig_output_is_supported(self) -> None:
        text = ("Wireless LAN adapter Wi-Fi:\n"
                "   IPv4 Address. . . . . . . . . . . : 192.168.50.4\n"
                "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n")
        facts = companion.extract_facts(text, "ipconfig")
        self.assertEqual(facts["primary"]["ipv4"], ["192.168.50.4"])
        self.assertEqual(facts["primary"]["ipv4_networks"], ["192.168.50.0/24"])

    def test_nslookup_mx_is_answered_natively_without_model_delay(self) -> None:
        output = """Server:  192.168.1.1
Address: 192.168.1.1#53

Non-authoritative answer:
nw18.com mail exchanger = 10 mail.nw18.com.
"""
        evidence = core.content_result(source="stdin", label="piped stdin", data=output.encode())
        self.assertEqual(evidence["facts"]["kind"], "dns_lookup")
        answer = companion.exact_answer("explain the output by sharing key details", evidence)
        self.assertIn("Mail exchangers:", answer)
        self.assertIn("mail.nw18.com (priority 10)", answer)

    def test_nslookup_txt_spf_is_answered_natively(self) -> None:
        output = 'example.com text = "v=spf1 include:_spf.example.com -all"\n'
        evidence = core.terminal_result(source="test", display_command="nslookup -type=TXT example.com",
                                        stdout=output.encode(), exit_code=0)
        answer = companion.exact_answer("show the SPF details", evidence)
        self.assertIn("v=spf1 include:_spf.example.com -all", answer)

    def test_docker_inspect_prefers_configured_image_over_sha(self) -> None:
        evidence = core.terminal_result(source="test", display_command="docker inspect abc123",
                                        stdout=DOCKER_INSPECT.encode(), exit_code=0)
        self.assertEqual(evidence["facts"]["image"], "searxng/searxng:latest")
        self.assertEqual(companion.exact_answer("What image is it using?", evidence),
                         "Docker image: searxng/searxng:latest")
        self.assertEqual(companion.exact_answer("What is the main Docker image detail?", evidence),
                         "Docker image: searxng/searxng:latest")

    def test_embedded_docker_json_in_terminal_transcript_is_found(self) -> None:
        transcript = "user % docker inspect abc123\n" + DOCKER_INSPECT + "\nuser %"
        evidence = core.content_result(source="file", label="transcript", data=transcript.encode())
        answer = companion.exact_answer("Give basic Docker container details", evidence)
        self.assertIn("Image: searxng/searxng:latest", answer)
        self.assertIn("Ports: 127.0.0.1:8888 → 8080/tcp", answer)

    def test_exact_answer_never_calls_model_and_is_stored_as_native(self) -> None:
        class NeverProvider:
            model = "must-not-run"
            def chat(self, *args, **kwargs): raise AssertionError("model should not be called")
        evidence = core.terminal_result(source="test", display_command="ifconfig", stdout=IFCONFIG.encode(), exit_code=0)
        with tempfile.TemporaryDirectory() as directory, core.HistoryStore(Path(directory) / "history.db") as store, \
             redirect_stdout(io.StringIO()):
            turn = cli.ask(store=store, client=NeverProvider(), query="What is the primary IP?",
                           tool_result=evidence, stream=False)
        self.assertEqual(turn.model, "tacu/native")

    def test_language_answer_is_refined_once_and_safety_refusals_are_kept(self) -> None:
        class RefineProvider:
            model = "fake-model"
            def __init__(self) -> None:
                self.calls = 0
            def chat(self, messages, *, stream):
                self.calls += 1
                if self.calls == 1:
                    yield "Translate this into polite language."
                else:
                    yield "Please give me some space. Next: Want a softer version?"

        class RefusalProvider:
            model = "fake-model"
            def __init__(self) -> None:
                self.calls = 0
            def chat(self, messages, *, stream):
                self.calls += 1
                yield "I cannot translate that phrase because it is abusive."

        with tempfile.TemporaryDirectory() as directory:
            refined = RefineProvider()
            refused = RefusalProvider()
            with core.HistoryStore(Path(directory) / "history.db") as store, redirect_stdout(io.StringIO()):
                turn = cli.ask(store=store, client=refined, query="translate this into polite language",
                               tool_result=None, stream=False)
            self.assertEqual(refined.calls, 2)
            self.assertIn("Please give me some space", turn.response)
            with core.HistoryStore(Path(directory) / "history2.db") as store, redirect_stdout(io.StringIO()):
                kept = cli.ask(store=store, client=refused, query="translate this into polite language",
                               tool_result=None, stream=False)
            self.assertEqual(refused.calls, 1)
            self.assertIn("I cannot translate", kept.response)


if __name__ == "__main__": unittest.main()
