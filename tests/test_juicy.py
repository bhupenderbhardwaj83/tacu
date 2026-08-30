"""Two-layer juicy detector: candidates, validators, confidence, and display."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import core
from tacu.juicy import HIGH_JUICY_KINDS, detect_juicy, meets_confidence
from tacu.theme import PALETTE


JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


class DetectorValidatorTests(unittest.TestCase):
    def _kinds(self, text: str) -> set[str]:
        return {item.kind for item in detect_juicy(text)}

    def _by_kind(self, text: str, kind: str) -> list:
        return [item for item in detect_juicy(text) if item.kind == kind]

    def test_existing_overlap_contract_is_preserved(self) -> None:
        text = (
            "https://admin.example.com 192.168.1.1 bob@example.com "
            "ABCDE1234F 4111 1111 1111 1111 password=s3cret"
        )
        kinds = [item.kind for item in detect_juicy(text)]
        self.assertEqual(kinds, ["url", "ipv4", "email", "pan", "credit-card", "password"])

    def test_checksums_reject_invalid_card_and_aadhaar(self) -> None:
        self.assertNotIn("credit-card", self._kinds("1234 5678 9012 3456"))
        self.assertNotIn("ipv4", self._kinds("999.1.2.3"))
        prefix = "23456789012"
        valid = next(prefix + digit for digit in "0123456789" if core._verhoeff(prefix + digit))
        self.assertTrue(self._by_kind(valid, "aadhaar"))
        invalid = valid[:-1] + str((int(valid[-1]) + 1) % 10)
        self.assertFalse(self._by_kind(invalid, "aadhaar"))

    def test_jwt_requires_a_parseable_header(self) -> None:
        findings = self._by_kind(JWT, "jwt")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "high")
        self.assertEqual(findings[0].value, JWT)
        self.assertFalse(self._by_kind("eyJaaaaaaa.bbbbbbbb.cccccccc", "jwt"))

    def test_cloud_tokens_are_critical_and_unmasked(self) -> None:
        blob = (
            "AKIAIOSFODNN7EXAMPLE "
            "ghp_abcdefghijklmnopqrstuvwxyz012345 "
            "sk_live_abcdefghijklmnopqrstuv "
            "-----BEGIN RSA PRIVATE KEY-----"
        )
        findings = detect_juicy(blob)
        kinds = {item.kind: item for item in findings}
        self.assertEqual(kinds["aws-access-key"].confidence, "critical")
        self.assertEqual(kinds["github-token"].confidence, "critical")
        self.assertEqual(kinds["stripe-key"].confidence, "critical")
        self.assertEqual(kinds["private-key"].confidence, "critical")
        self.assertIn("ghp_abcdefghijklmnopqrstuvwxyz012345", kinds["github-token"].value)
        self.assertNotIn("***", kinds["github-token"].value)

    def test_bearer_and_basic_are_shown_in_the_clear(self) -> None:
        text = "Authorization: Bearer abcdefghijklmnop\nAuthorization: Basic YWRtaW46c2VjcmV0"
        kinds = {item.kind: item for item in detect_juicy(text)}
        self.assertEqual(kinds["bearer"].value, "abcdefghijklmnop")
        self.assertEqual(kinds["basic-auth"].value, "YWRtaW46c2VjcmV0")
        self.assertEqual(kinds["bearer"].confidence, "critical")
        header = detect_juicy(f"Authorization: Bearer {JWT}")
        self.assertIn("bearer", {item.kind for item in header})
        self.assertEqual(header[0].value, JWT)

    def test_secret_nested_in_url_is_kept_beside_the_url(self) -> None:
        url = "https://app.example.com/login?password=hunter2&api_key=abcdefghijkl"
        kinds = [item.kind for item in detect_juicy(url)]
        self.assertIn("url", kinds)
        self.assertIn("secret-in-url", kinds)
        values = [item.value for item in detect_juicy(url) if item.kind == "secret-in-url"]
        self.assertTrue(any("hunter2" in value for value in values))
        self.assertNotIn("[REDACTED", "".join(values))

    def test_url_embedded_credentials_are_critical(self) -> None:
        findings = self._by_kind("https://ada:s3cret@db.internal.example/path", "url")
        self.assertEqual(findings[0].confidence, "critical")
        self.assertIn("s3cret", findings[0].value)

    def test_identity_and_financial_validators(self) -> None:
        text = (
            "pay ada@oksbi on +91 9876543210 "
            "IBAN GB82WEST12345698765432 "
            "passport A1234567 filed on the passport page"
        )
        kinds = self._kinds(text)
        self.assertIn("upi", kinds)
        self.assertIn("indian-phone", kinds)
        self.assertIn("iban", kinds)
        self.assertIn("passport", kinds)
        self.assertEqual(self._by_kind("GB00WEST12345698765432", "iban"), [])

    def test_placeholders_are_not_secrets(self) -> None:
        kinds = self._kinds('password=example api_key=xxxxxxxx token="${password}"')
        self.assertNotIn("password", kinds)
        self.assertNotIn("secret", kinds)

    def test_signals_are_detected_but_not_the_default_analyst_filter(self) -> None:
        text = (
            "SQL syntax error MySQL; Access-Control-Allow-Origin: *; "
            "debug=true; verify_ssl=false; Traceback (most recent call last)"
        )
        kinds = self._kinds(text)
        self.assertIn("sql-error", kinds)
        self.assertIn("cors-wildcard", kinds)
        self.assertIn("debug-enabled", kinds)
        self.assertIn("tls-verify-disabled", kinds)
        self.assertIn("stack-trace", kinds)
        self.assertNotIn("sql-error", HIGH_JUICY_KINDS)
        self.assertNotIn("cors-wildcard", HIGH_JUICY_KINDS)

    def test_colorize_uses_family_colors_and_skips_signals(self) -> None:
        text = f"contact ada@example.com token {JWT}\nAccess-Control-Allow-Origin: *"
        painted = core.colorize_output(text, enabled=True)
        self.assertIn(PALETTE.juicy_id, painted)
        self.assertIn(PALETTE.juicy_auth, painted)
        self.assertIn("ada@example.com", painted)
        self.assertNotIn("***", painted)
        # CORS is a signal — do not paint it in ordinary output.
        cors_only = core.colorize_output("Access-Control-Allow-Origin: *", enabled=True)
        self.assertNotIn(PALETTE.juicy_signal, cors_only)

    def test_confidence_filter(self) -> None:
        finding = detect_juicy("password=s3cret")[0]
        self.assertTrue(meets_confidence(finding, "high"))
        self.assertFalse(meets_confidence(finding, "critical"))

    def test_plain_questions_map_onto_juicy_kinds(self) -> None:
        from tacu.juicy import parse_juicy_question, value_matches_needles
        phones = parse_juicy_question("are there mobile numbers in the file")
        self.assertIsNotNone(phones)
        self.assertTrue(phones.want_model)
        self.assertTrue(phones.kinds & {"indian-phone", "intl-phone"})
        passwords = parse_juicy_question("show me the passwords")
        self.assertIn("password", passwords.kinds)
        self.assertTrue(passwords.want_model)
        jwt = parse_juicy_question("are there JWTs in the table")
        self.assertIn("jwt", jwt.kinds)
        self.assertTrue(jwt.want_model)
        pan = parse_juicy_question("show me PAN values")
        self.assertIn("pan", pan.kinds)
        aws = parse_juicy_question("any aws access keys")
        self.assertIn("aws-access-key", aws.kinds)
        pem = parse_juicy_question("where is the private key")
        self.assertTrue({"private-key", "ssh-key", "pem-certificate"} & pem.kinds)
        from tacu.juicy import wants_juicy
        self.assertTrue(wants_juicy("jcy info"))
        self.assertTrue(wants_juicy("juicy detail"))
        rotate = parse_juicy_question("what should I rotate first")
        self.assertTrue(rotate.want_model)
        self.assertFalse(rotate.kinds)
        self.assertIsNone(parse_juicy_question("which region sold most"))
        self.assertIsNone(parse_juicy_question("how many rows"))
        lookup = parse_juicy_question(
            "is there mobile number 9870000043 in the data juicy information")
        self.assertIsNotNone(lookup)
        self.assertTrue(lookup.want_model)
        self.assertTrue(lookup.kinds & {"indian-phone", "intl-phone"})
        self.assertIn("9870000043", lookup.needles)
        self.assertTrue(value_matches_needles("91 9870000043", lookup.needles))
        self.assertFalse(value_matches_needles("9870000001", lookup.needles))
        bare = parse_juicy_question("is there 9870000043")
        self.assertIsNotNone(bare)
        self.assertTrue(bare.want_model)
        self.assertIn("9870000043", bare.needles)

    def test_report_is_a_compact_inventory_not_an_answer_card(self) -> None:
        from tacu.juicy import exposure_note, format_juicy_report
        rows = [
            ("row 1", "password", "DummyPass-001-X9!Kq", "high"),
            ("row 1", "email", "dummy.user001@example.com", "high"),
        ]
        report = format_juicy_report(rows, title="JUICY", how="scan", enabled=False)
        self.assertIn("DummyPass-001-X9!Kq", report)
        self.assertIn("dummy.user001@example.com", report)
        self.assertNotIn("***", report)
        self.assertNotIn("◆ ANSWER", report)
        self.assertIn("PASSWORD", report)
        self.assertIn("EMAIL", report)
        self.assertIn("row 1", report)
        self.assertIn("high", report)
        self.assertIn("not redacted", report)
        self.assertIn("live login", report)
        self.assertEqual(report.count("live login"), 1)
        self.assertIn("live login", exposure_note("password"))

    def test_html_doctype_loads_as_text_not_burp_xml(self) -> None:
        from tacu.readers import detect_format
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "page.html"
            path.write_text(
                "<!DOCTYPE html><html><body>email ada@example.com password=s3cret</body></html>\n",
                encoding="utf-8",
            )
            self.assertEqual(detect_format(path), "text")

    def test_piped_ask_juicy_skips_the_model_and_shows_the_report(self) -> None:
        from tacu import cli

        class Piped(StringIO):
            def isatty(self) -> bool:
                return False

        payload = "id,email,password\n1,ada@example.com,s3cretPass\n"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("sys.stdin", Piped(payload)), \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["ask", "juicy", "information"]), 0)
            provider.assert_not_called()
            shown = output.getvalue()
            self.assertIn("ada@example.com", shown)
            self.assertIn("s3cretPass", shown)
            self.assertIn("JUICY", shown)
            self.assertIn("EMAIL", shown)
            self.assertIn("PASSWORD", shown)
            self.assertIn("no model", shown.casefold())
            self.assertIn("live login", shown.casefold())
            self.assertNotIn("◆ ANSWER", shown)
            self.assertNotIn("L001", shown)
            self.assertNotIn("[REDACTED", shown)
            self.assertNotIn("Want me to suggest", shown)
        findings = detect_juicy("email ada@example.com AKIAIOSFODNN7EXAMPLE")
        with tempfile.TemporaryDirectory() as directory:
            path = core.export_findings(findings, Path(directory) / "ji.jsonl", "jsonl")
            rows = [json.loads(line) for line in path.read_text().splitlines()]
        values = {row["value"] for row in rows}
        self.assertIn("ada@example.com", values)
        self.assertIn("AKIAIOSFODNN7EXAMPLE", values)
        self.assertTrue(all("***" not in row["value"] for row in rows))

    def test_ask_choke_point_scans_evidence_without_the_model(self) -> None:
        from tacu import cli

        class NeverProvider:
            model = "must-not-run"
            def chat(self, *args, **kwargs):
                raise AssertionError("model should not be called")

        payload = "id,email,password\n1,ada@example.com,s3cretPass\n"
        evidence = core.terminal_result(
            source="stdin", display_command="piped stdin", stdout=payload.encode(),
        )
        with tempfile.TemporaryDirectory() as directory, \
             core.HistoryStore(Path(directory) / "history.db") as store, \
             redirect_stdout(StringIO()) as output:
            turn = cli.ask(
                store=store, client=NeverProvider(), query="juicy information",
                tool_result=evidence, stream=False,
            )
        shown = output.getvalue()
        self.assertEqual(turn.model, "tacu/juicy")
        self.assertIn("ada@example.com", shown)
        self.assertIn("s3cretPass", shown)
        self.assertNotIn("◆ ANSWER", shown)
        self.assertNotIn("Want me to suggest", shown)

    def test_jucy_typo_still_skips_the_model(self) -> None:
        from tacu import cli

        class Piped(StringIO):
            def isatty(self) -> bool:
                return False

        payload = "id,email\n1,ada@example.com\n"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("sys.stdin", Piped(payload)), \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["ask", "jucy", "information"]), 0)
            provider.assert_not_called()
            self.assertIn("ada@example.com", output.getvalue())
            self.assertNotIn("◆ ANSWER", output.getvalue())

    def test_ti_juicy_file_is_extract_first_with_confidence(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            source = Path(directory) / "secrets.csv"
            source.write_text("id,email,password\n1,ada@example.com,s3cretPass\n", encoding="utf-8")
            out = Path(directory) / "findings.csv"
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["juicy", str(source), "-o", str(out)]), 0)
            provider.assert_not_called()
            shown = output.getvalue()
            self.assertIn("ada@example.com", shown)
            self.assertIn("s3cretPass", shown)
            self.assertIn("high", shown)
            self.assertIn("EMAIL", shown)
            self.assertIn("PASSWORD", shown)
            self.assertNotIn("◆ ANSWER", shown)
            self.assertTrue(out.is_file())
            exported = out.read_text(encoding="utf-8")
            self.assertIn("confidence", exported)
            self.assertIn("source file line number", exported)
            self.assertIn("ada@example.com", exported)

    def test_juicy_ask_flag_sends_the_inventory_not_the_raw_file(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            source = Path(directory) / "secrets.csv"
            source.write_text("id,email\n1,ada@example.com\n", encoding="utf-8")
            out = Path(directory) / "findings.csv"
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("tacu.cli.ask") as ask_fn, \
                 redirect_stdout(StringIO()):
                self.assertEqual(
                    cli.main(["juicy", str(source), "-o", str(out),
                              "--ask", "what should I rotate first"]), 0)
            provider.assert_called_once()
            ask_fn.assert_called_once()
            kwargs = ask_fn.call_args.kwargs
            self.assertEqual(kwargs["query"], "what should I rotate first")
            evidence = core.evidence_text(kwargs["tool_result"])
            self.assertIn("ada@example.com", evidence)
            self.assertIn("high", evidence)
            self.assertIn("Source file:", evidence)
            self.assertIn("Extracted findings file:", evidence)
            self.assertNotIn("id,email", evidence)

    def test_unquoted_ask_sends_only_the_filtered_slice_to_the_model(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            source = Path(directory) / "secrets.csv"
            source.write_text(
                "id,phone,email\n1,9876543210,ada@example.com\n", encoding="utf-8")
            out = Path(directory) / "findings.csv"
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("tacu.cli.ask") as ask_fn, \
                 redirect_stdout(output):
                self.assertEqual(
                    cli.main(["juicy", str(source), "-o", str(out),
                              "--ask", "are", "there", "mobile", "numbers", "in", "the", "file"]), 0)
            provider.assert_called_once()
            ask_fn.assert_called_once()
            evidence = core.evidence_text(ask_fn.call_args.kwargs["tool_result"])
            self.assertIn("9876543210", evidence)
            self.assertNotIn("ada@example.com", evidence)
            self.assertIn("Filtered inventory", evidence)
            shown = output.getvalue()
            self.assertIn("9876543210", shown)
            self.assertNotIn("ada@example.com", shown)

    def test_ask_a_specific_email_sends_only_that_hit(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            source = Path(directory) / "people.csv"
            source.write_text(
                "id,phone,email\n"
                "1,9870000001,ada@example.com\n"
                "2,9870000043,bob@example.com\n",
                encoding="utf-8",
            )
            out = Path(directory) / "hits.csv"
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("tacu.cli.ask") as ask_fn, \
                 redirect_stdout(StringIO()):
                self.assertEqual(
                    cli.main(["juicy", str(source), "-o", str(out),
                              "--ask", "tell", "me", "is", "bob@example.com", "in", "the", "data"]), 0)
            provider.assert_called_once()
            ask_fn.assert_called_once()
            evidence = core.evidence_text(ask_fn.call_args.kwargs["tool_result"])
            self.assertIn("bob@example.com", evidence)
            self.assertNotIn("ada@example.com", evidence)
            self.assertNotIn("9870000001", evidence)

    def test_grep_and_kind_filter_a_file_and_a_tree(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            source = Path(directory) / "people.csv"
            source.write_text(
                "id,phone,email\n"
                "1,9870000001,ada@example.com\n"
                "2,9870000043,bob@example.com\n",
                encoding="utf-8",
            )
            out = Path(directory) / "hits.csv"
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 redirect_stdout(output):
                self.assertEqual(
                    cli.main(["juicy", str(source), "-o", str(out), "--grep", "9870000043"]), 0)
            provider.assert_not_called()
            shown = output.getvalue()
            self.assertIn("9870000043", shown)
            self.assertNotIn("9870000001", shown)
            self.assertIn("match", shown.casefold())
            exported = out.read_text(encoding="utf-8")
            self.assertIn("9870000043", exported)
            self.assertNotIn("9870000001", exported)
            self.assertIn("source file", exported.splitlines()[0])

            tree = Path(directory) / "project"
            (tree / "a").mkdir(parents=True)
            (tree / "b").mkdir()
            (tree / "a" / "notes.txt").write_text("call 9870000043 now\n", encoding="utf-8")
            (tree / "b" / "other.txt").write_text("call 9870000001 now\n", encoding="utf-8")
            tree_out = Path(directory) / "tree.csv"
            tree_shown = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 redirect_stdout(tree_shown):
                self.assertEqual(
                    cli.main(["juicy", str(tree), "-o", str(tree_out),
                              "--kind", "phone", "--grep", "9870000043"]), 0)
            provider.assert_not_called()
            body = tree_shown.getvalue()
            self.assertIn("9870000043", body)
            self.assertNotIn("9870000001", body)
            self.assertIn("a/notes.txt", body)

    def test_data_ask_filters_a_specific_phone(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            source = Path(directory) / "people.csv"
            source.write_text(
                "id,phone,email\n"
                "1,9870000001,ada@example.com\n"
                "2,9870000043,bob@example.com\n",
                encoding="utf-8",
            )
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("tacu.cli.ask") as ask_fn, \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["data", "load", str(source), "--name", "dt1"]), 0)
                self.assertEqual(
                    cli.main(["data", "ask", "dt1", "is", "there", "mobile", "number",
                              "9870000043", "in", "the", "data", "juicy", "information"]), 0)
                self.assertEqual(
                    cli.main(["data", "juicy", "dt1", "--grep", "9870000043"]), 0)
            self.assertEqual(provider.call_count, 1)
            ask_fn.assert_called_once()
            evidence = core.evidence_text(ask_fn.call_args.kwargs["tool_result"])
            self.assertIn("9870000043", evidence)
            self.assertNotIn("9870000001", evidence)
            shown = output.getvalue()
            self.assertIn("9870000043", shown)
            self.assertNotIn("9870000001", shown)
            self.assertIn("match", shown.casefold())

    def test_ask_on_a_loaded_extract_uses_kind_not_the_detector(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            source = Path(directory) / "findings.csv"
            source.write_text(
                "kind,category,value,source file,source file line number,confidence\n"
                "username,identity,test_admin,page.html,10,medium\n"
                "password,authentication,Dummy-Passw0rd-Only-For-Testing!,page.html,11,high\n"
                "bearer,authentication,dummyBearerToken_A1B2C3D4E5F6G7H8I9J0,page.html,18,critical\n",
                encoding="utf-8",
            )
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("tacu.cli.ask") as ask_fn, \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["data", "load", str(source), "--name", "dt2"]), 0)
                self.assertEqual(
                    cli.main(["data", "ask", "dt2", "please", "provide", "me", "all",
                              "the", "values", "with", "kind", "password"]), 0)
            provider.assert_called_once()
            ask_fn.assert_called_once()
            evidence = core.evidence_text(ask_fn.call_args.kwargs["tool_result"])
            self.assertIn("Dummy-Passw0rd-Only-For-Testing!", evidence)
            self.assertNotIn("dummyBearerToken", evidence)
            shown = output.getvalue()
            self.assertIn("Dummy-Passw0rd-Only-For-Testing!", shown)
            self.assertNotIn("No juicy values", shown)


class TreeScannerTests(unittest.TestCase):
    def test_should_scan_source_config_ci_and_skip_binaries(self) -> None:
        from tacu.juicyscan import should_scan

        self.assertTrue(should_scan(Path("app.py")))
        self.assertTrue(should_scan(Path("notes.txt")))
        self.assertTrue(should_scan(Path(".env.production")))
        self.assertTrue(should_scan(Path("Dockerfile")))
        self.assertTrue(should_scan(Path("Dockerfile.prod")))
        self.assertTrue(should_scan(Path("docker-compose.yml")))
        self.assertTrue(should_scan(Path("values-prod.yaml")))
        self.assertTrue(should_scan(Path("id_rsa")))
        self.assertTrue(should_scan(Path(".aws") / "credentials"))
        self.assertFalse(should_scan(Path("photo.png")))
        self.assertFalse(should_scan(Path("lib.so")))
        self.assertFalse(should_scan(Path("photo.png"), all_files=True))
        self.assertTrue(should_scan(Path("weird.dat"), all_files=True))

    def test_walk_skips_node_modules_and_keeps_env(self) -> None:
        from tacu.juicyscan import iter_scan_files

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "svc").mkdir()
            (root / "svc" / ".env").write_text("password=s3cretPass\n", encoding="utf-8")
            (root / "svc" / "node_modules").mkdir()
            (root / "svc" / "node_modules" / "leak.js").write_text(
                "email=hidden@example.com\n", encoding="utf-8")
            names = {path.name for path in iter_scan_files(root)}
            self.assertIn(".env", names)
            self.assertNotIn("leak.js", names)

    def test_fingerprint_is_stable_and_preview_hides_the_middle(self) -> None:
        from tacu.juicy import redacted_preview, secret_fingerprint

        key = "AKIAIOSFODNN7EXAMPLE"
        self.assertEqual(secret_fingerprint("aws-access-key", key),
                         secret_fingerprint("aws-access-key", key))
        self.assertNotEqual(secret_fingerprint("aws-access-key", key),
                            secret_fingerprint("password", key))
        preview = redacted_preview(key)
        self.assertTrue(preview.startswith("AKIA"))
        self.assertTrue(preview.endswith("MPLE"))
        self.assertIn("***", preview)
        self.assertLess(len(preview), len(key))

    def test_tree_writes_per_project_reports_and_rotation(self) -> None:
        from tacu import cli
        from tacu.juicyscan import MASTER_SUMMARY_NAME, ROTATION_REPORT_NAME
        from tacu.juicy import secret_fingerprint

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            root = Path(directory) / "source-code"
            pay = root / "payment-service"
            mobile = root / "mobile-app"
            pay.mkdir(parents=True)
            mobile.mkdir()
            (pay / "config.yml").write_text(
                "aws_access_key_id: AKIAIOSFODNN7EXAMPLE\nemail: ada@example.com\n",
                encoding="utf-8",
            )
            (mobile / "App.tsx").write_text(
                "const KEY = 'AKIAIOSFODNN7EXAMPLE';\n",
                encoding="utf-8",
            )
            (root / "node_modules").mkdir()
            (root / "node_modules" / "secret.js").write_text(
                "AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
            out = Path(directory) / "findings.csv"
            shown = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 redirect_stdout(shown):
                self.assertEqual(cli.main(["juicy", str(root), "-o", str(out)]), 0)
            provider.assert_not_called()
            body = shown.getvalue()
            self.assertIn("AKIAIOSFODNN7EXAMPLE", body)
            self.assertIn("payment-service/config.yml", body)
            self.assertNotIn("node_modules", body)
            reports = root / "_juicy_reports"
            self.assertTrue((reports / "payment-service_report.jsonl").is_file())
            self.assertTrue((reports / "payment-service_report.csv").is_file())
            self.assertTrue((reports / "mobile-app_report.jsonl").is_file())
            self.assertTrue((reports / "mobile-app_report.csv").is_file())
            self.assertTrue((reports / MASTER_SUMMARY_NAME).is_file())
            rotation = reports / ROTATION_REPORT_NAME
            self.assertTrue(rotation.is_file())
            rotation_text = rotation.read_text(encoding="utf-8")
            self.assertIn("SECRET_TYPE", rotation_text)
            self.assertIn(secret_fingerprint("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
                          rotation_text)
            self.assertIn("aws-access-key", rotation_text)
            master = (reports / MASTER_SUMMARY_NAME).read_text(encoding="utf-8")
            self.assertIn("PROJECT,FILE,LINE,PACKET,ITEM,CATEGORY,DETECTOR,SEVERITY,CONFIDENCE,"
                          "VALUE,CONTEXT,SHA256_FINGERPRINT",
                          master.splitlines()[0].replace(" ", ""))
            self.assertIn("payment-service", master)
            self.assertIn("AKIAIOSFODNN7EXAMPLE", master)
            jsonl = (reports / "payment-service_report.jsonl").read_text(encoding="utf-8")
            self.assertIn("AKIAIOSFODNN7EXAMPLE", jsonl)
            aws = next(json.loads(line) for line in jsonl.splitlines()
                       if json.loads(line).get("detector") == "aws-access-key")
            self.assertEqual(aws["project"], "payment-service")
            self.assertEqual(aws["file"], "config.yml")
            self.assertEqual(aws["category"], "SECRET")
            self.assertEqual(aws["severity"], "CRITICAL")
            self.assertEqual(aws["confidence"], 98)
            self.assertEqual(aws["value"], "AKIAIOSFODNN7EXAMPLE")
            self.assertIn("packet", aws)
            self.assertIn("item", aws)
            self.assertEqual(aws["fingerprint"],
                             secret_fingerprint("aws-access-key", "AKIAIOSFODNN7EXAMPLE"))
            self.assertIn("AKIAIOSFODNN7EXAMPLE", aws["context"])
            combined = out.read_text(encoding="utf-8")
            self.assertIn("VALUE", combined.splitlines()[0])
            self.assertIn("AKIAIOSFODNN7EXAMPLE", combined)
            self.assertIn("payment-service_report.jsonl", body)

    def test_reports_keep_secrets_in_the_clear(self) -> None:
        from tacu import cli

        key = "AKIAIOSFODNN7EXAMPLE"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            root = Path(directory) / "repos"
            (root / "api").mkdir(parents=True)
            (root / "api" / "keys.env").write_text(f"AWS_KEY={key}\n", encoding="utf-8")
            shown = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider"), \
                 redirect_stdout(shown):
                self.assertEqual(cli.main(["juicy", str(root)]), 0)
            self.assertIn(key, shown.getvalue())
            jsonl = (root / "_juicy_reports" / "api_report.jsonl").read_text(encoding="utf-8")
            csv_text = (root / "_juicy_reports" / "api_report.csv").read_text(encoding="utf-8")
            self.assertIn(key, jsonl)
            self.assertIn(key, csv_text)
            self.assertNotIn("AKIA***MPLE", jsonl)

    def test_help_states_that_juicy_and_extract_are_aliases(self) -> None:
        from tacu import cli
        from tacu.theme import strip_ansi

        extract_out = StringIO()
        with redirect_stdout(extract_out):
            self.assertEqual(cli.main(["help", "extract"]), 0)
        extract_page = strip_ansi(extract_out.getvalue())
        juicy_out = StringIO()
        with redirect_stdout(juicy_out):
            self.assertEqual(cli.main(["help", "juicy"]), 0)
        juicy_page = strip_ansi(juicy_out.getvalue())
        self.assertEqual(extract_page, juicy_page)
        self.assertIn("ti juicy  =  ti extract juicy", extract_page)
        self.assertIn("ti extract ji", extract_page)
        self.assertIn("FILE TYPES", extract_page)
        self.assertIn("packet is the", extract_page)
        self.assertIn("item is 1-based", extract_page)
        self.assertIn("ti juicy --turn", extract_page)


class NativeLocatorTests(unittest.TestCase):
    def test_finding_where_includes_packet_and_item(self) -> None:
        from tacu.juicy import JuicyFinding, finding_where

        finding = JuicyFinding(
            "password", "s3cretPass", 0, 10, 12, "high", "authentication",
            source="history.xml", packet=42, item=7,
        )
        place = finding_where(finding)
        self.assertIn("history.xml:12", place)
        self.assertIn("packet 42", place)
        self.assertIn("item 7", place)

    def test_burp_xml_scan_stamps_item_and_line(self) -> None:
        xml = (
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2026.7.3">\n'
            "  <item><url>https://a.test/</url>"
            "<request>Authorization: Bearer abcdefghijklmnop\n</request></item>\n"
            "  <item><url>https://b.test/</url>"
            "<request>password=s3cretPass\n</request></item>\n"
            "</items>\n"
        )
        from tacu.juicy import finding_where

        scan = core.scan_juicy_stream([xml], source="history.xml")
        by_kind = {item.kind: item for item in scan.findings}
        self.assertIn("bearer", by_kind)
        self.assertIn("password", by_kind)
        self.assertEqual(by_kind["bearer"].item, 1)
        self.assertEqual(by_kind["password"].item, 2)
        self.assertGreater(by_kind["password"].line, by_kind["bearer"].line)
        self.assertIn("item 2", finding_where(by_kind["password"]))

    def test_csv_packet_column_stamps_findings(self) -> None:
        text = "packet,info\n42,password=s3cretPass\n"
        scan = core.scan_juicy_stream([text], source="export.csv")
        secrets = [item for item in scan.findings if item.kind == "password"]
        self.assertTrue(secrets)
        self.assertEqual(secrets[0].packet, 42)
        self.assertEqual(secrets[0].line, 2)

    def test_single_file_csv_keeps_packet_and_item_columns(self) -> None:
        from tacu.juicy import JuicyFinding

        finding = JuicyFinding(
            "email", "ada@example.com", 0, 15, 4, "high", "identity",
            source="frames.csv", packet=9, item=0,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = core.export_findings([finding], Path(directory) / "out.csv", "csv")
            header = path.read_text(encoding="utf-8").splitlines()[0]
            self.assertIn("source file line number", header)
            self.assertIn("packet", header)
            self.assertIn("item", header)
            self.assertIn("9", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
