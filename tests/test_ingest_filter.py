"""Deterministic pipe ingest → filter tests."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli, core
from tacu.companion import exact_answer
from tacu.ingest_filter import FilterOptions, apply_pipe_filter, exact_filter_answer


class IngestFilterTests(unittest.TestCase):
    def test_json_schema_skips_model(self) -> None:
        payload = {"name": "tacu", "version": 3, "nested": {"ok": True}}
        evidence = core.content_result(
            source="stdin", label="piped stdin", data=json.dumps(payload).encode(),
        )
        filtered = apply_pipe_filter(evidence, "what keys are present", FilterOptions())
        answer = exact_answer("what keys are present", filtered)
        self.assertIsNotNone(answer)
        assert answer is not None
        self.assertIn("name", answer)
        self.assertIn("version", answer)
        self.assertIn("nested", answer)

    def test_json_keys_projection(self) -> None:
        payload = {"name": "tacu", "version": 3, "secret": "nope"}
        evidence = core.content_result(
            source="stdin", label="piped stdin", data=json.dumps(payload).encode(),
        )
        filtered = apply_pipe_filter(
            evidence, "summarize", FilterOptions(keys=["name", "version"]),
        )
        data = filtered["result"]["stdout"]["data"]
        self.assertEqual(data, {"name": "tacu", "version": 3})
        native = exact_filter_answer("show name and version", filtered)
        self.assertIsNotNone(native)

    def test_csv_columns_and_grep(self) -> None:
        csv_text = "host,port,state\n10.0.0.1,22,open\n10.0.0.2,80,closed\n10.0.0.3,443,open\n"
        evidence = core.content_result(source="stdin", label="piped stdin", data=csv_text.encode())
        filtered = apply_pipe_filter(
            evidence, "open ports", FilterOptions(cols=["host", "state"], grep="open"),
        )
        block = filtered["result"]["stdout"]
        self.assertEqual(block["columns"], ["host", "state"])
        self.assertEqual(block["row_count"], 2)
        self.assertEqual(block["rows"][0], ["10.0.0.1", "open"])

    def test_log_grep_head(self) -> None:
        log = "info ok\nERROR boom\ninfo fine\nERROR again\nwarn meh\n"
        evidence = core.content_result(source="stdin", label="piped stdin", data=log.encode())
        filtered = apply_pipe_filter(
            evidence, "errors", FilterOptions(grep="ERROR", head=1),
        )
        text = filtered["result"]["stdout"]["text"]
        self.assertEqual(text, "ERROR boom")
        answer = exact_filter_answer("grep ERROR", filtered)
        self.assertIsNotNone(answer)
        assert answer is not None
        self.assertIn("ERROR boom", answer)

    def test_ifconfig_pipe_keeps_companion_facts(self) -> None:
        sample = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255\n"
        )
        evidence = core.content_result(source="stdin", label="piped stdin", data=sample.encode())
        filtered = apply_pipe_filter(
            evidence, "which interface owns the local address?", FilterOptions(),
        )
        self.assertEqual((filtered.get("facts") or {}).get("kind"), "network_interfaces")
        answer = exact_answer("which interface owns the local address?", filtered)
        self.assertIsNotNone(answer)
        assert answer is not None
        self.assertIn("192.168.1.20", answer)


class IngestCliTests(unittest.TestCase):
    def test_ask_no_ai_json_schema(self) -> None:
        class NeverProvider:
            model = "never"

            def chat(self, messages, *, stream):
                raise AssertionError("model must not be called for --no-ai ingest")

            def models(self):
                return [self.model]

        payload = json.dumps({"alpha": 1, "beta": [1, 2]}).encode()
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            output = io.StringIO()
            with patch.object(cli, "app_home", return_value=home), \
                 patch.object(cli, "load_provider", return_value=NeverProvider()), \
                 patch.object(cli.sys.stdin, "isatty", return_value=False), \
                 patch.object(cli, "capture_piped_input",
                              return_value=(payload, None, cli.CaptureReport(
                                  total_bytes=len(payload), kept_bytes=len(payload)))), \
                 redirect_stdout(output):
                code = cli.main(["ask", "--no-ai", "what", "keys", "are", "present"])
            self.assertEqual(code, 0)
            rendered = output.getvalue()
            self.assertIn("alpha", rendered)
            self.assertIn("beta", rendered)
            self.assertIn("Ingest type: json", rendered)
            with core.HistoryStore(home / "history.db") as store:
                turn = store.get()
                self.assertIsNotNone(turn)
                assert turn is not None
                self.assertEqual(turn.model, "tacu/ingest")


if __name__ == "__main__":
    unittest.main()
