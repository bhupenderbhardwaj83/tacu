"""Email forensics: nothing executed, nothing visited, every claim tied to evidence.

The fixture is a textbook spoof — a display name borrowing a brand, Reply-To
and Return-Path pointing elsewhere, SPF and DKIM passing for the attacker's own
domain while DMARC fails for the displayed one, a link whose text lies about
its target, and a "PDF" whose first two bytes are MZ.
"""

from __future__ import annotations

import base64
import inspect
import io
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import coding
from tacu.companion import _email_answer, exact_host_answer
from tacu.routing import native_steps_for_intent
from tacu.tools import mailscan, recon
from tacu.tools.mailscan import (analyze_url, defang, domain_age, enrich, inventory_zip, lookalike,
                                 magic_type, parse_message, parse_received, score)


def _zip_with(*names: str) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, "MZ" + "\x00" * 40)
    return base64.encodebytes(buffer.getvalue()).decode()


FIXTURE = f"""Return-Path: <bounce@attacker.example>
Received: from mx1.proofpoint.com (mx1.proofpoint.com [67.231.152.10]) by outlook.office365.com with ESMTP; Tue, 09 Sep 2026 00:12:06 +0000
Received: from mail.attacker.example (mail.attacker.example [203.0.113.7]) by mx1.proofpoint.com with ESMTP id X7; Tue, 09 Sep 2026 00:12:05 +0000
Authentication-Results: spf=pass smtp.mailfrom=attacker.example; dkim=pass header.d=attacker.example header.s=sel1; dmarc=fail action=none header.from=acme-invoices.co; arc=pass
DKIM-Signature: v=1; a=rsa-sha256; d=attacker.example; s=sel1; h=from; bh=x; b=y
From: "Microsoft Billing" <billing@acme-invoices.co>
Reply-To: pay@attacker.example
To: victim@company.com
Subject: Invoice overdue
Date: Tue, 09 Sep 2026 03:12:00 +0300
Message-ID: <abc123@attacker.example>
X-Originating-IP: [203.0.113.7]
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/html; charset="utf-8"

<html><body><p>Pay at <a href="http://203.0.113.9/pay">https://portal.microsoft.com/billing</a> or http://micros0ft-billing.xyz/login</p></body></html>
--B
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--B
Content-Type: application/zip; name="docs.zip"
Content-Disposition: attachment; filename="docs.zip"
Content-Transfer-Encoding: base64

{_zip_with("readme.txt", "invoice.pdf.exe")}
--B--
""".encode()

CLEAN = b"""Received: from mail.example.com (mail.example.com [93.184.216.34]) by mx.company.com; Tue, 09 Sep 2026 10:00:00 +0000
Authentication-Results: spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
From: "Jane" <jane@example.com>
To: you@company.com
Subject: Lunch
Date: Tue, 09 Sep 2026 10:00:00 +0000
Message-ID: <x@example.com>
Content-Type: text/plain

See you at noon.
"""


class BoundaryTests(unittest.TestCase):
    """The two isolation promises, held by the code's shape."""

    def test_the_parser_has_no_way_to_reach_the_network(self) -> None:
        parameters = inspect.signature(parse_message).parameters
        self.assertEqual(list(parameters), ["raw"])
        # And it does not touch the transport while working.
        original = recon.Transport.dns
        calls = []
        recon.Transport.dns = lambda *a, **k: calls.append(a) or []  # type: ignore[assignment]
        try:
            parse_message(FIXTURE)
        finally:
            recon.Transport.dns = original  # type: ignore[assignment]
        self.assertEqual(calls, [])

    def test_the_enricher_receives_strings_and_never_the_message_or_bytes(self) -> None:
        parameters = inspect.signature(enrich).parameters
        self.assertEqual(list(parameters)[0], "iocs")
        self.assertNotIn("message", parameters)
        self.assertNotIn("attachments", parameters)
        self.assertNotIn("raw", parameters)

    def test_nothing_the_mail_names_is_ever_contacted(self) -> None:
        parsed = parse_message(FIXTURE)
        contacted: list[str] = []

        class Recording(recon.Transport):
            def dns(self, name, record, evidence):
                contacted.append(("dns", name))
                return []

            def get_json(self, url, evidence, *, service, headers=None):
                contacted.append(("json", url))
                raise recon.ReconError("offline", code="unreachable")

            def probe(self, host, evidence):
                contacted.append(("probe", host))
                raise AssertionError("probe must never be called from email analysis")

            def tls(self, host, evidence, port=443):
                contacted.append(("tls", host))
                raise AssertionError("tls must never be called from email analysis")

        mailscan._enrich_boundary(parsed, ["203.0.113.9"], Recording(), recon.Evidence())
        # Lookups *about* things (reverse DNS, sender-domain records, Cymru) are
        # fine. A request *to* a URL or IP from the mail is not.
        for kind, target in contacted:
            self.assertNotIn("203.0.113.9/pay", target)
            self.assertNotIn("micros0ft-billing.xyz/login", target)
            self.assertNotEqual(kind, "probe")
            self.assertNotEqual(kind, "tls")


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parsed = parse_message(FIXTURE)

    def test_headers_and_anomalies(self) -> None:
        headers = self.parsed["headers"]
        self.assertEqual(headers["from"]["domain"], "acme-invoices.co")
        self.assertEqual(headers["reply_to"]["domain"], "attacker.example")
        joined = " ".join(headers["anomalies"])
        self.assertIn("Reply-To domain attacker.example differs", joined)
        self.assertIn("Return-Path domain attacker.example differs", joined)
        self.assertIn("display name names 'microsoft'", joined)

    def test_hops_are_oldest_first_with_the_final_receiver_as_its_own_row(self) -> None:
        hops = self.parsed["headers"]["hops"]
        self.assertEqual([h["from"] for h in hops],
                         ["mail.attacker.example", "mx1.proofpoint.com", "outlook.office365.com"])
        self.assertEqual(hops[0]["ip"], "203.0.113.7")
        self.assertFalse(hops[0]["ip_public"], "TEST-NET is not public and must not be looked up")
        self.assertEqual(hops[1]["relay"], "Proofpoint")
        self.assertEqual(hops[2]["relay"], "Microsoft 365")
        self.assertTrue(hops[2].get("final"))

    def test_authentication_says_for_whom(self) -> None:
        auth = self.parsed["auth"]
        self.assertEqual((auth["spf"], auth["dkim"], auth["dmarc"], auth["arc"]), ("pass", "pass", "fail", "pass"))
        self.assertEqual(auth["spf_domain"], "attacker.example")
        self.assertEqual(auth["dkim_domains"], ["attacker.example"])
        self.assertIs(auth["alignment"]["spf_aligned"], False)
        self.assertTrue(any("not for the displayed acme-invoices.co" in n for n in auth["notes"]))

    def test_urls_are_defanged_and_flagged(self) -> None:
        urls = {u["url"]: u["flags"] for u in self.parsed["iocs"]["urls"]}
        self.assertIn("hxxp://203[.]0[.]113[.]9/pay", urls)
        self.assertIn("host is a bare IP address", urls["hxxp://203[.]0[.]113[.]9/pay"])
        xyz = urls["hxxp://micros0ft-billing[.]xyz/login"]
        self.assertTrue(any("resembles microsoft.com" in f for f in xyz))
        for url in urls:
            self.assertNotIn("http://", url)
            self.assertNotIn("https://", url)

    def test_a_link_whose_text_lies_is_called_out(self) -> None:
        findings = [a["finding"] for a in self.parsed["iocs"]["anchors"]]
        self.assertEqual(findings, ["text says portal[.]microsoft[.]com, link goes to 203[.]0[.]113[.]9"])

    def test_html_is_stripped_never_rendered(self) -> None:
        self.assertNotIn("<a", self.parsed["bodies"]["html_as_text"])
        self.assertIn("Pay at", self.parsed["bodies"]["html_as_text"])

    def test_a_pdf_that_is_a_pe_is_caught(self) -> None:
        pdf = next(a for a in self.parsed["attachments"] if a["filename"] == "invoice.pdf")
        self.assertEqual(pdf["actual_label"], "Windows executable (PE)")
        self.assertTrue(pdf["mismatch"])
        self.assertTrue(pdf["executable"])
        self.assertEqual(len(pdf["sha256"]), 64)

    def test_an_archive_is_inventoried_not_opened(self) -> None:
        archive = next(a for a in self.parsed["attachments"] if a["filename"] == "docs.zip")
        names = [e["name"] for e in archive["archive"]["entries"]]
        self.assertEqual(names, ["readme.txt", "invoice.pdf.exe"])
        self.assertIn("archive contains an executable", archive["flags"])
        self.assertTrue(archive["suspicious_archive"])

    def test_a_clean_message_scores_nothing(self) -> None:
        parsed = parse_message(CLEAN)
        self.assertEqual(parsed["headers"]["anomalies"], [])
        self.assertEqual(parsed["auth"]["notes"], [])
        self.assertEqual(score(parsed, None)["score"], 0)


class MagicTests(unittest.TestCase):
    def test_first_bytes_decide(self) -> None:
        self.assertEqual(magic_type(b"MZ\x90\x00")[0], "application/x-dosexec")
        self.assertEqual(magic_type(b"%PDF-1.7")[0], "application/pdf")
        self.assertEqual(magic_type(b"PK\x03\x04")[0], "application/zip")
        self.assertEqual(magic_type(b"\x7fELF")[0], "application/x-elf")
        self.assertEqual(magic_type(b"#!/bin/sh\n")[0], "text/x-script")
        self.assertEqual(magic_type(b"hello world")[0], "text/plain")
        self.assertEqual(magic_type(b"\x00\x01\x02\xff")[0], "application/octet-stream")

    def test_an_encrypted_archive_is_reported(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("x.txt", "x")
        data = bytearray(buffer.getvalue())
        # The inventory reads the central directory, so flip the encryption bit
        # there: the flags sit 8 bytes after the PK\x01\x02 signature.
        central = data.find(b"PK\x01\x02")
        data[central + 8] |= 0x1
        out = inventory_zip(bytes(data))
        self.assertTrue(out["encrypted"])
        self.assertTrue(out["entries"][0]["encrypted"])

    def test_a_bad_zip_fails_loudly_not_silently(self) -> None:
        out = inventory_zip(b"PK\x03\x04not really")
        self.assertIn("note", out)


class LookalikeTests(unittest.TestCase):
    def test_substitutions_edits_and_hyphenated_tokens(self) -> None:
        self.assertIn("substituted", lookalike("micros0ft-billing.xyz", "microsoft.com"))
        self.assertIn("within two edits", lookalike("paypa1.com", "paypal.com"))
        self.assertIn("carries 'paypal'", lookalike("paypal-secure.com", "paypal.com"))

    def test_the_real_thing_and_unrelated_names_are_not_flagged(self) -> None:
        self.assertEqual(lookalike("microsoft.com", "microsoft.com"), "")
        self.assertEqual(lookalike("docs.microsoft.com", "microsoft.com"), "")
        self.assertEqual(lookalike("github.com", "microsoft.com"), "")
        self.assertEqual(lookalike("microsoftonline.com", "microsoft.com"), "")

    def test_url_flags(self) -> None:
        self.assertIn("link shortener hides the destination", analyze_url("https://bit.ly/x", "acme.com")["flags"])
        self.assertIn("credentials embedded before the host", analyze_url("https://user:pw@evil.com/", "acme.com")["flags"])
        self.assertIn("punycode host (internationalised characters)", analyze_url("https://xn--pple-43d.com/", "acme.com")["flags"])
        self.assertEqual(analyze_url("https://acme.com/login", "acme.com")["flags"], [])


class ReceivedTests(unittest.TestCase):
    def test_a_relay_only_row_has_no_ip(self) -> None:
        hops = parse_received(["from a.example ([1.2.3.4]) by mx.google.com; Mon, 1 Sep 2026 00:00:00 +0000"])
        self.assertEqual(hops[0]["ip"], "1.2.3.4")
        self.assertEqual(hops[1]["from"], "mx.google.com")
        self.assertEqual(hops[1]["relay"], "Google")
        self.assertEqual(hops[1]["ip"], "")

    def test_no_received_headers_is_no_hops(self) -> None:
        self.assertEqual(parse_received([]), [])


class ScoreTests(unittest.TestCase):
    def test_the_fixture_is_high_with_every_reason_listed(self) -> None:
        result = score(parse_message(FIXTURE), None)
        self.assertEqual(result["level"], "HIGH")
        factors = {r["factor"] for r in result["reasons"]}
        for expected in ("dmarc_fail", "auth_for_other_identity", "reply_to_mismatch",
                         "display_name_impersonation", "executable_attachment",
                         "extension_mime_mismatch", "suspicious_archive", "link_text_lies", "url_to_bare_ip"):
            self.assertIn(expected, factors)
        for reason in result["reasons"]:
            self.assertTrue(reason["why"])

    def test_the_score_is_capped_at_100(self) -> None:
        self.assertLessEqual(score(parse_message(FIXTURE), None)["score"], 100)

    def test_an_unregistered_sender_domain_counts(self) -> None:
        parsed = parse_message(CLEAN)
        result = score(parsed, {"domain_age": {"domain": "example.com", "registered": False}})
        self.assertTrue(any(r["factor"] == "lookalike_or_new_domain" and "not registered" in r["why"]
                            for r in result["reasons"]))

    def test_bad_hop_reputation_counts_once(self) -> None:
        parsed = parse_message(CLEAN)
        enrichment = {"hops": [{"ip": "1.1.1.1", "reputation": {"abuseipdb": {"confidence": 90, "reports": 5}}},
                               {"ip": "2.2.2.2", "reputation": {"abuseipdb": {"confidence": 95, "reports": 9}}}]}
        result = score(parsed, enrichment)
        self.assertEqual(sum(1 for r in result["reasons"] if r["factor"] == "bad_sender_ip_reputation"), 1)


class DomainAgeTests(unittest.TestCase):
    def test_the_tld_stub_is_not_mistaken_for_the_domain(self) -> None:
        from unittest.mock import patch

        stub = ("domain:       CO\n"
                "created:      1991-12-24\n"
                "changed:      2026-02-17\n"
                "The queried object does not exist: DOMAIN NOT FOUND\n")
        with patch("tacu.tools.mailscan.which", return_value="/usr/bin/whois"), \
                patch("tacu.tools.mailscan.run_argv", return_value={"stdout": stub, "exit_code": 0}):
            out = domain_age("acme-invoices.co", recon.Evidence())
        self.assertIs(out["registered"], False)
        self.assertNotIn("created", out)

    def test_a_date_before_the_domain_line_is_ignored(self) -> None:
        from unittest.mock import patch

        text = ("domain:       COM\ncreated:      1985-01-01\n\n"
                "Domain Name: GITHUB.COM\nCreation Date: 2007-10-09T18:20:50Z\n")
        with patch("tacu.tools.mailscan.which", return_value="/usr/bin/whois"), \
                patch("tacu.tools.mailscan.run_argv", return_value={"stdout": text, "exit_code": 0}):
            out = domain_age("github.com", recon.Evidence())
        self.assertEqual(out["created"], "2007-10-09T18:20:50Z")


class SurfaceAndRoutingTests(unittest.TestCase):
    def test_email_is_offered_to_the_intent_lane_not_the_lookup_lane(self) -> None:
        self.assertIn("email", coding.INTENT_TOOL_SURFACE)
        self.assertNotIn("email", coding.ANSWER_TOOL_SURFACE)

    def test_it_declares_itself_outbound(self) -> None:
        self.assertIn("network:outbound", mailscan.SPEC.permissions)

    def test_questions_naming_a_message_reach_the_tool(self) -> None:
        expect = {"is this email phishing suspicious.eml": "analyze",
                  "check the headers of mail.eml": "headers",
                  "did dkim pass for invoice.eml": "auth",
                  "trace the email in sample.eml": "hops",
                  "extract iocs from bad.eml": "iocs",
                  "is the attachment in report.eml safe": "attachments"}
        for question, operation in expect.items():
            with self.subTest(question=question):
                steps = native_steps_for_intent(question)
                self.assertEqual((steps[0]["tool"], steps[0]["operation"]), ("email", operation))
                self.assertTrue(steps[0]["inputs"]["path"].endswith(".eml"))

    def test_without_a_named_message_nothing_is_read(self) -> None:
        self.assertFalse([s for s in native_steps_for_intent("is this email phishing") if s["tool"] == "email"])


class ReadWhereYouStandTests(unittest.TestCase):
    """A file named in the question is the file in front of the user."""

    def test_a_file_in_the_current_directory_is_recognised(self) -> None:
        import os
        import tempfile
        from tacu.cli import _names_a_file_here

        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "suspicious.eml").write_bytes(CLEAN)
            before = os.getcwd()
            os.chdir(directory)
            try:
                self.assertTrue(_names_a_file_here("is this email phishing suspicious.eml"))
                self.assertFalse(_names_a_file_here("is this email phishing other.eml"))
                self.assertFalse(_names_a_file_here("is this email phishing"))
            finally:
                os.chdir(before)


class AnswerTests(unittest.TestCase):
    def test_the_report_leads_with_the_score_and_says_for_whom_auth_passed(self) -> None:
        parsed = parse_message(FIXTURE)
        data = {"operation": "analyze", "headers": parsed["headers"], "auth": parsed["auth"],
                "iocs": parsed["iocs"], "attachments": parsed["attachments"],
                "risk": score(parsed, None), "enrichment": None, "contacted": [], "message_sha256": "x"}
        text = _email_answer(data)
        self.assertTrue(text.startswith("EMAIL RISK SCORE:"))
        self.assertIn("SEVERITY: HIGH", text)
        self.assertIn("SPF      PASS       for attacker.example", text)
        self.assertIn("DMARC    FAIL       for acme-invoices.co", text)
        self.assertIn("not for the identity the recipient sees", text)
        self.assertIn("Hop  Source IP", text)
        self.assertIn("Microsoft 365", text)
        self.assertIn("hxxp://", text)
        self.assertNotIn("http://203.0.113.9", text, "nothing in the report may be a live link")
        self.assertIn("Contacted: nothing — this was a static read", text)

    def test_the_host_answer_path_hands_email_results_to_the_renderer(self) -> None:
        data = {"operation": "attachments", "message_sha256": "x", "attachments": [], "contacted": []}
        self.assertIn("No attachments.", exact_host_answer("attachments", [{"result": {"tool": "email", "data": data}}]))


if __name__ == "__main__":
    unittest.main()
