"""External recon: every claim tied to evidence, nothing probed that is not public.

The transport is faked throughout, so these run with the network unplugged and
assert on the reasoning rather than on what some server said today.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import coding
from tacu.companion import _recon_answer, exact_host_answer
from tacu.routing import native_steps_for_intent
from tacu.tools import recon
from tacu.tools.recon import (Evidence, ReconError, detect_waf, discover_subdomains, lookup_asn,
                              lookup_reputation, normalise_target, resolve, score_risk, sweep)


class FakeTransport:
    """Answers from a script. Records every call so a test can assert what went out."""

    def __init__(self, *, dns=None, json=None, tls=None, probe=None) -> None:
        self._dns = dns or {}
        self._json = json or {}
        self._tls = tls or {}
        self._probe = probe or {}
        self.calls: list[tuple] = []

    def dns(self, name, record, evidence):
        self.calls.append(("dns", name, record))
        evidence.ran(["dig", name, record])
        return list(self._dns.get((name, record), []))

    def get_json(self, url, evidence, *, service, headers=None):
        self.calls.append(("json", service, url, tuple(sorted((headers or {}).keys()))))
        evidence.contact(service)
        answer = self._json.get(service)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def tls(self, host, evidence, port=443):
        self.calls.append(("tls", host))
        evidence.contact(f"tls://{host}:{port}")
        answer = self._tls.get(host)
        if isinstance(answer, Exception):
            raise answer
        return dict(answer or {})

    def probe(self, host, evidence):
        self.calls.append(("probe", host))
        evidence.contact(f"https://{host}")
        answer = self._probe.get(host)
        if isinstance(answer, Exception):
            raise answer
        return dict(answer or {"url": f"https://{host}/", "status": 200, "headers": [], "cookies": []})


CT_ROWS = [{"name_value": "www.example.com\nexample.com"}, {"name_value": "*.example.com"},
           {"name_value": "api.example.com"}, {"name_value": "evil.other.com"}]


class TargetTests(unittest.TestCase):
    def test_a_url_becomes_its_host(self) -> None:
        self.assertEqual(normalise_target("https://WWW.Example.com/x?y=1"), ("domain", "www.example.com"))

    def test_an_address_is_recognised(self) -> None:
        self.assertEqual(normalise_target("140.82.112.25"), ("ip", "140.82.112.25"))
        self.assertEqual(normalise_target("[2606:4700::1]"), ("ip", "2606:4700::1"))

    def test_nonsense_is_refused_not_guessed(self) -> None:
        with self.assertRaises(ReconError):
            normalise_target("not a domain at all")


class SubdomainTests(unittest.TestCase):
    def test_names_come_with_their_sources(self) -> None:
        transport = FakeTransport(json={"crt.sh": CT_ROWS},
                                  dns={("example.com", "NS"): ["ns1.example.com"],
                                       ("example.com", "MX"): ["10 mail.example.com"]})
        out = discover_subdomains("example.com", transport, Evidence())
        by_name = {item["name"]: item["sources"] for item in out["subdomains"]}
        self.assertIn("certificate transparency", by_name["www.example.com"])
        self.assertIn("NS record", by_name["ns1.example.com"])
        self.assertIn("MX record", by_name["mail.example.com"])
        self.assertNotIn("evil.other.com", by_name, "names outside the domain are dropped")
        self.assertNotIn("*.example.com", by_name, "wildcards are folded, not listed")

    def test_an_empty_ct_answer_is_retried_then_reported(self) -> None:
        transport = FakeTransport(json={"crt.sh": ReconError("empty", code="upstream", retryable=True)})
        evidence = Evidence()
        out = discover_subdomains("example.com", transport, evidence)
        self.assertEqual(sum(1 for c in transport.calls if c[0] == "json"), 2)
        self.assertFalse(out["ct_available"])
        self.assertTrue(any("certificate transparency was not available" in n for n in evidence.notes))

    def test_bruteforce_is_off_unless_asked(self) -> None:
        transport = FakeTransport(json={"crt.sh": []})
        discover_subdomains("example.com", transport, Evidence())
        tried = [c for c in transport.calls if c[0] == "dns" and c[1].startswith("vpn.")]
        self.assertEqual(tried, [])
        discover_subdomains("example.com", transport, Evidence(), bruteforce=True)
        tried = [c for c in transport.calls if c[0] == "dns" and c[1].startswith("vpn.")]
        self.assertTrue(tried)


class ResolveTests(unittest.TestCase):
    def test_private_addresses_are_marked_not_hidden(self) -> None:
        transport = FakeTransport(dns={("intranet.example.com", "A"): ["10.0.0.5"]})
        out = resolve("intranet.example.com", transport, Evidence())
        self.assertEqual(out["addresses"], [{"ip": "10.0.0.5", "public": False}])

    def test_the_cname_chain_is_followed_and_bounded(self) -> None:
        transport = FakeTransport(dns={("www.example.com", "CNAME"): ["www.example.com.edgesuite.net"],
                                       ("www.example.com.edgesuite.net", "CNAME"): ["a1.akamaiedge.net"]})
        out = resolve("www.example.com", transport, Evidence())
        self.assertEqual(out["cname_chain"], ["www.example.com.edgesuite.net", "a1.akamaiedge.net"])


class AsnTests(unittest.TestCase):
    def test_cymru_answers_are_parsed_and_the_most_specific_prefix_kept(self) -> None:
        transport = FakeTransport(dns={
            ("25.112.82.140.origin.asn.cymru.com", "TXT"): [
                '"36459 | 140.82.112.0/20 | US | arin | 2018-04-25"',
                '"36459 | 140.82.112.0/24 | US | arin | 2018-04-25"'],
            ("AS36459.asn.cymru.com", "TXT"): ['"36459 | US | arin | 2012-11-13 | GITHUB - GitHub, Inc., US"'],
        })
        out = lookup_asn("140.82.112.25", transport, Evidence())
        self.assertEqual(out["asn"], "36459")
        self.assertEqual(out["prefix"], "140.82.112.0/24")
        self.assertEqual(out["owner"], "GITHUB - GitHub, Inc., US")

    def test_no_answer_is_said_plainly(self) -> None:
        out = lookup_asn("192.0.2.1", FakeTransport(), Evidence())
        self.assertEqual(out["asn"], "")
        self.assertIn("no origin AS", out["note"])


class WafTests(unittest.TestCase):
    def test_one_header_is_weak(self) -> None:
        out = detect_waf(cname_chain=[], headers=["server: cloudflare"], cookies=[], asn="", issuer="")
        self.assertEqual(out["providers"][0]["confidence"], 40)

    def test_agreeing_indicators_reach_high_confidence_and_are_listed(self) -> None:
        out = detect_waf(cname_chain=["x.cdn.cloudflare.net"],
                         headers=["server: cloudflare", "cf-ray: abc"], cookies=["__cf_bm=zzz"],
                         asn="13335", issuer="")
        top = out["providers"][0]
        self.assertEqual(top["provider"], "Cloudflare")
        self.assertEqual(top["confidence"], 98)
        self.assertEqual({i["kind"] for i in top["indicators"]}, {"cname", "header", "cookie", "asn"})

    def test_akamai_by_cname_alone(self) -> None:
        out = detect_waf(cname_chain=["www.example.com.edgesuite.net"], headers=[], cookies=[], asn="", issuer="")
        self.assertEqual(out["providers"][0]["provider"], "Akamai")

    def test_nothing_seen_says_so(self) -> None:
        self.assertEqual(detect_waf(cname_chain=[], headers=[], cookies=[], asn="", issuer="")["verdict"],
                         "no CDN or WAF indicators seen")

    def test_cookie_values_never_appear_in_evidence(self) -> None:
        out = detect_waf(cname_chain=[], headers=[], cookies=["__cf_bm=SESSIONSECRET"], asn="", issuer="")
        self.assertEqual(out["providers"][0]["indicators"][0]["evidence"], "__cf_bm=…")


class ReputationTests(unittest.TestCase):
    def test_without_keys_nothing_is_contacted_and_that_is_said(self) -> None:
        transport = FakeTransport()
        out = lookup_reputation("203.0.113.10", transport, Evidence(), keys={"abuseipdb": "", "virustotal": ""})
        self.assertEqual([c for c in transport.calls if c[0] == "json"], [])
        self.assertEqual(len(out["not_checked"]), 2)

    def test_keys_travel_in_headers_never_in_the_url(self) -> None:
        transport = FakeTransport(json={"AbuseIPDB": {"data": {"abuseConfidenceScore": 95, "totalReports": 40}},
                                        "VirusTotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}}})
        out = lookup_reputation("203.0.113.10", transport, Evidence(),
                                keys={"abuseipdb": "ABUSEKEY", "virustotal": "VTKEY"})
        for call in transport.calls:
            self.assertNotIn("ABUSEKEY", call[2])
            self.assertNotIn("VTKEY", call[2])
        self.assertEqual(out["abuseipdb"]["confidence"], 95)
        self.assertEqual(out["virustotal"]["malicious"], 3)

    def test_a_failing_source_is_named_not_swallowed(self) -> None:
        transport = FakeTransport(json={"AbuseIPDB": ReconError("rate-limited", code="rate_limited")})
        out = lookup_reputation("203.0.113.10", transport, Evidence(), keys={"abuseipdb": "k", "virustotal": ""})
        self.assertTrue(any("AbuseIPDB" in n and "rate-limited" in n for n in out["not_checked"]))


class RiskTests(unittest.TestCase):
    def test_every_contribution_is_listed(self) -> None:
        out = score_risk(reputation={"virustotal": {"malicious": 7}, "abuseipdb": {"confidence": 95, "reports": 40},
                                     "not_checked": []},
                         asn={"asn": "1", "owner": "Bulletproof Hosting", "allocated": "2026-09-01"},
                         tls=None, waf=None)
        self.assertEqual(out["score"], 80)
        self.assertEqual(out["level"], "HIGH")
        self.assertEqual({c["factor"] for c in out["contributions"]},
                         {"virustotal_malicious", "abuseipdb_high", "recently_registered", "suspicious_asn"})

    def test_a_cdn_lowers_the_score_and_says_why(self) -> None:
        waf = {"providers": [{"provider": "Cloudflare", "confidence": 98, "cdn": True, "indicators": []}]}
        out = score_risk(reputation=None, asn=None, tls=None, waf=waf)
        self.assertEqual(out["score"], -10)
        self.assertIn("unrelated customers", out["contributions"][0]["why"])

    def test_missing_sources_are_a_stated_caveat_not_a_zero(self) -> None:
        out = score_risk(reputation={"not_checked": ["AbuseIPDB: no key"]}, asn=None, tls=None, waf=None)
        self.assertEqual(out["level"], "NONE OBSERVED")
        self.assertIn("AbuseIPDB: no key", out["caveat"])


class SweepTests(unittest.TestCase):
    def test_a_private_subdomain_is_reported_and_never_probed(self) -> None:
        transport = FakeTransport(
            json={"crt.sh": [{"name_value": "intranet.example.com"}], "ipinfo.io": {"country": "US"}},
            dns={("example.com", "A"): ["93.184.216.34"], ("intranet.example.com", "A"): ["10.0.0.5"],
                 ("34.216.184.93.origin.asn.cymru.com", "TXT"): ['"15133 | 93.184.216.0/24 | US | arin | 2010-01-01"']},
            tls={"example.com": {"issuer": "O=DigiCert", "not_before": "2024-01-01T00:00:00+00:00"}})
        report = sweep("example.com", transport, Evidence(), bruteforce=False, limit=10,
                       keys={"abuseipdb": "", "virustotal": ""})
        hosts = {h["host"]: h for h in report["hosts"]}
        self.assertIn("not probed", hosts["intranet.example.com"]["skipped"])
        self.assertNotIn(("probe", "intranet.example.com"), transport.calls)
        self.assertNotIn(("tls", "intranet.example.com"), transport.calls)
        self.assertIn(("probe", "example.com"), transport.calls)

    def test_the_report_says_what_was_contacted(self) -> None:
        transport = FakeTransport(json={"crt.sh": [], "ipinfo.io": {"country": "US"}},
                                  dns={("example.com", "A"): ["93.184.216.34"]})
        evidence = Evidence()
        sweep("example.com", transport, evidence, bruteforce=False, limit=5, keys={"abuseipdb": "", "virustotal": ""})
        self.assertIn("crt.sh", evidence.contacted)
        self.assertIn("ipinfo.io", evidence.contacted)


class GuardTests(unittest.TestCase):
    def test_private_and_loopback_are_never_destinations(self) -> None:
        for host in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "169.254.1.1"):
            with self.subTest(host=host):
                self.assertFalse(recon.is_public_address(host))
                with self.assertRaises(ReconError) as caught:
                    recon._public_endpoints(host, 443)
                self.assertEqual(caught.exception.code, "not_public")

    def test_the_lookup_surface_refuses_an_outbound_tool(self) -> None:
        original = coding.ANSWER_TOOL_SURFACE
        try:
            coding.ANSWER_TOOL_SURFACE = original + ("recon",)
            with self.assertRaises(RuntimeError) as caught:
                coding.answer_tool_schemas()
            self.assertIn("recon", str(caught.exception))
        finally:
            coding.ANSWER_TOOL_SURFACE = original

    def test_the_intent_lane_may_use_it(self) -> None:
        self.assertIn("recon", coding.INTENT_TOOL_SURFACE)

    def test_it_declares_itself_outbound(self) -> None:
        self.assertIn("network:outbound", recon.SPEC.permissions)


class RoutingTests(unittest.TestCase):
    def test_questions_about_something_out_there_reach_recon(self) -> None:
        expect = {
            "what is behind example.com": "sweep",
            "list subdomains of example.com": "subdomains",
            "is github.com behind cloudflare": "waf",
            "who owns the ip 140.82.112.25": "asn",
            "where is 140.82.112.25 located": "geo",
            "is 140.82.112.25 malicious": "reputation",
            "certificate for github.com": "tls",
            "dns records for example.com": "dns",
        }
        for question, operation in expect.items():
            with self.subTest(question=question):
                steps = native_steps_for_intent(question)
                self.assertTrue(steps, question)
                self.assertEqual((steps[0]["tool"], steps[0]["operation"]), ("recon", operation))
                self.assertIn("target", steps[0]["inputs"])

    def test_without_a_named_target_recon_is_never_chosen(self) -> None:
        for question in ("what is behind", "recon", "is it behind cloudflare"):
            with self.subTest(question=question):
                self.assertFalse([s for s in native_steps_for_intent(question) if s["tool"] == "recon"])

    def test_questions_about_this_machine_are_untouched(self) -> None:
        for question, tool in (("am i connected to github.com", "network"),
                               ("what is my primary ip address", "network"),
                               ("am i compromised", "forensics")):
            with self.subTest(question=question):
                self.assertEqual(native_steps_for_intent(question)[0]["tool"], tool)


class AnswerTests(unittest.TestCase):
    def test_a_waf_answer_shows_its_indicators(self) -> None:
        data = {"operation": "waf", "target": "example.com", "kind": "domain",
                "providers": [{"provider": "Cloudflare", "confidence": 98, "cdn": True,
                               "indicators": [{"kind": "header", "evidence": "cf-ray: x", "weight": 45}]}],
                "verdict": "Cloudflare", "contacted": ["https://example.com"]}
        text = _recon_answer(data)
        self.assertIn("98% confidence", text)
        self.assertIn("cf-ray", text)
        self.assertIn("Contacted: https://example.com", text)

    def test_a_reputation_answer_without_keys_says_how_to_add_them(self) -> None:
        data = {"operation": "reputation", "target": "203.0.113.10", "kind": "ip", "ip": "203.0.113.10",
                "abuseipdb": None, "virustotal": None, "not_checked": ["AbuseIPDB: no key"], "contacted": []}
        text = _recon_answer(data)
        self.assertIn("not checked: AbuseIPDB: no key", text)
        self.assertIn("ti config keys", text)

    def test_the_host_answer_path_hands_recon_results_to_the_renderer(self) -> None:
        data = {"operation": "asn", "target": "140.82.112.25", "kind": "ip", "ip": "140.82.112.25",
                "asn": "36459", "prefix": "140.82.112.0/24", "country": "US", "registry": "arin",
                "allocated": "2018-04-25", "owner": "GITHUB", "contacted": ["asn.cymru.com (DNS)"]}
        text = exact_host_answer("who owns 140.82.112.25", [{"result": {"tool": "recon", "data": data}}])
        self.assertIn("AS36459", text)
        self.assertIn("GITHUB", text)


if __name__ == "__main__":
    unittest.main()
