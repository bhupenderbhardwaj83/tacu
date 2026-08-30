import io
import gzip
import json
import socket
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import cli
from tacu.web import (FetchResponse, SearchResponse, SearchResult, SearxngClient,
                      WebError, WebFetcher, _ReadableHTML, _decode_transport, _is_public,
                      _validated_destination, model_evidence)
import ipaddress


class FakeHTTPResponse:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status
    def read(self, size=-1): return self.payload[:size] if size >= 0 else self.payload
    def __enter__(self): return self
    def __exit__(self, *args): return None


class FakeOpener:
    def __init__(self, response): self.response = response
    def open(self, request, timeout):
        if isinstance(self.response, Exception): raise self.response
        return self.response


class FakeProvider:
    model = "fake-model"
    def chat(self, messages, *, stream):
        yield "The verified answer is supported by source [1].\n\nNext: Read another source?"
    def models(self): return [self.model]


class WebSearchTests(unittest.TestCase):
    def test_searxng_maps_bounds_and_marks_truncation(self):
        payload = {"results": [
            {"url": f"https://example.com/{i}", "title": f" Result {i} ",
             "content": " useful   snippet ", "engines": ["test"]}
            for i in range(4)
        ]}
        client = SearxngClient(max_results=2)
        client._opener = FakeOpener(FakeHTTPResponse(json.dumps(payload).encode()))
        result = client.search("  useful   query ")
        self.assertEqual(result.query, "useful query")
        self.assertEqual(len(result.results), 2)
        self.assertTrue(result.truncated)
        self.assertEqual(result.results[0].snippet, "useful snippet")

    def test_search_translates_configuration_failures(self):
        client = SearxngClient()
        client._opener = FakeOpener(urllib.error.HTTPError(client.base_url, 404, "missing", {}, None))
        with self.assertRaisesRegex(WebError, "json") as raised:
            client.search("test")
        self.assertEqual(raised.exception.code, "WEB_SEARCH_FAILED")


class GuardTests(unittest.TestCase):
    def test_literal_private_credentials_and_bad_schemes_are_refused(self):
        for url, code in (("http://127.0.0.1:11434/api", "WEB_BLOCKED_URL"),
                          ("http://user:pass@example.com/", "WEB_BLOCKED_URL"),
                          ("file:///etc/passwd", "WEB_INVALID_URL"),
                          ("http://[::ffff:127.0.0.1]/", "WEB_BLOCKED_URL")):
            with self.subTest(url=url), self.assertRaises(WebError) as raised:
                _validated_destination(url)
            self.assertEqual(raised.exception.code, code)

    def test_dns_result_is_checked_and_pinned(self):
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80))]
        with patch("socket.getaddrinfo", return_value=private), self.assertRaises(WebError) as raised:
            _validated_destination("http://example.test/")
        self.assertEqual(raised.exception.code, "WEB_BLOCKED_URL")
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=public):
            parsed, endpoints = _validated_destination("https://example.test/page")
        self.assertEqual(parsed.hostname, "example.test")
        self.assertEqual(endpoints[0][3][0], "93.184.216.34")

    def test_transition_and_special_addresses_are_not_public(self):
        refused = ("10.0.0.1", "127.0.0.1", "169.254.1.1", "::1",
                   "::ffff:127.0.0.1", "2001::1", "64:ff9b::7f00:1")
        self.assertTrue(all(not _is_public(ipaddress.ip_address(value)) for value in refused))
        self.assertTrue(_is_public(ipaddress.ip_address("1.1.1.1")))


class FetchTests(unittest.TestCase):
    def test_html_extractor_prefers_article_and_drops_active_chrome(self):
        parser = _ReadableHTML()
        parser.feed("<html><head><title>Example</title><script>steal()</script></head>"
                    "<body><nav>menus menus menus</nav><article><h1>Headline</h1><p>" +
                    "Useful evidence. " * 20 + "</p></article><footer>footer</footer></body></html>")
        title, text = parser.result()
        self.assertEqual(title, "Example")
        self.assertIn("Headline", text)
        self.assertNotIn("steal", text)
        self.assertNotIn("menus", text)

    def test_same_origin_redirect_and_page_bounds(self):
        fetcher = WebFetcher(max_chars=1_000)
        calls = []
        def request(parsed, endpoints):
            calls.append(parsed.geturl())
            if len(calls) == 1:
                return 302, {"location": "/article"}, b""
            body = ("<html><title>T</title><article>" + "evidence " * 400 + "</article></html>").encode()
            return 200, {"content-type": "text/html; charset=utf-8"}, body
        fetcher._request_once = request
        endpoint = [(socket.AF_INET, socket.SOCK_STREAM, 6, ("93.184.216.34", 443))]
        def validated(url): return urllib.parse.urlsplit(url), endpoint
        with patch("tacu.web._validated_destination", side_effect=validated):
            result = fetcher.fetch("https://example.com/start")
        self.assertEqual(result.final_url, "https://example.com/article")
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.text), 1_000)

    def test_gzip_is_decoded_with_a_hard_expansion_bound(self):
        body = gzip.compress(b"evidence " * 10_000)
        decoded, truncated = _decode_transport(body, "gzip", 2_000)
        self.assertTrue(truncated)
        self.assertEqual(len(decoded), 2_000)
        self.assertTrue(decoded.startswith(b"evidence"))
        with self.assertRaises(WebError):
            _decode_transport(body, "br", 2_000)

    def test_cross_origin_redirect_is_refused(self):
        fetcher = WebFetcher()
        fetcher._request_once = lambda parsed, endpoints: (302, {"location": "https://evil.example/"}, b"")
        endpoint = [(socket.AF_INET, socket.SOCK_STREAM, 6, ("93.184.216.34", 443))]
        with patch("tacu.web._validated_destination", side_effect=lambda url: (urllib.parse.urlsplit(url), endpoint)):
            with self.assertRaises(WebError) as raised:
                fetcher.fetch("https://good.example/")
        self.assertEqual(raised.exception.code, "WEB_REDIRECT_BLOCKED")

    def test_model_evidence_numbers_sources_and_marks_untrusted(self):
        source = SearchResult("https://example.com", "Title", "Snippet")
        search = SearchResponse("query", (source,), False)
        evidence = model_evidence("query", search, {source.url: WebError("WEB_FETCH_FAILED", "no")}).decode()
        self.assertIn("SOURCE [1]", evidence)
        self.assertIn("untrusted external content", evidence)
        self.assertIn("WEB_FETCH_FAILED", evidence)


class WebCliTests(unittest.TestCase):
    def search(self):
        return SearchResponse("query", (SearchResult("https://example.com/a", "Source", "Snippet"),), False)

    def test_no_ai_lists_sources_without_fetch(self):
        searcher = type("Search", (), {"base_url": "http://127.0.0.1:8888",
                                        "search": lambda inner, query, limit=None: self.search()})()
        out = io.StringIO()
        with patch.object(cli, "SearxngClient", return_value=searcher), \
             patch.object(cli, "ensure_searxng_container", return_value=(True, "ready")), \
             patch.object(cli, "load_provider", return_value=FakeProvider()), \
             patch.object(cli, "WebFetcher") as fetcher, redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = cli.main(["web", "--no-ai", "query"])
        self.assertEqual(code, 0)
        self.assertIn("WEB SOURCES:", out.getvalue())
        fetcher.assert_not_called()

    def test_default_web_reads_and_stores_cited_answer(self):
        search = self.search()
        searcher = type("Search", (), {"base_url": "http://127.0.0.1:8888",
                                        "search": lambda inner, query, limit=None: search})()
        page = FetchResponse(search.results[0].url, search.results[0].url, 200, "text/html",
                             "Source", "Useful evidence", False, 0)
        fetcher = type("Fetch", (), {"fetch": lambda inner, url: page})()
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(cli, "SearxngClient", return_value=searcher), \
             patch.object(cli, "ensure_searxng_container", return_value=(True, "ready")), \
             patch.object(cli, "WebFetcher", return_value=fetcher), \
             patch.object(cli, "load_provider", return_value=FakeProvider()), \
             patch.object(cli, "app_home", return_value=Path(directory)), \
             redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = cli.main(["--no-stream", "web", "query"])
        self.assertEqual(code, 0)
        self.assertIn("[1]", out.getvalue())
        self.assertIn("verified answer", out.getvalue())
        self.assertIn("[1]", out.getvalue())
        self.assertNotIn("host facts", out.getvalue())


class WebAnswerCleanupTests(unittest.TestCase):
    def test_leaked_planning_is_stripped_to_the_cited_answer(self) -> None:
        from tacu.answer_format import normalize_answer_for_storage
        from tacu.loop import answer_needs_refine

        leaked = (
            "*   User Question: \"tell me what is ox-alpha\"\n"
            "*   Constraint 1: Answer only from the numbered TACU web sources.\n"
            "*   For host facts, start with the one-line fact asked for.\n"
            "*   Wait, this is a general instruction for host facts.\n"
            "*   Source [1]: Ox Alpha is an anonymous stealth model.\n"
            "\n"
            "Ox Alpha is an anonymous stealth AI model designed for coding [1, 7].\n"
            "\n"
            "Key details include a 1 million token context window [1].\n"
            "\n"
            "Next: Want a comparison with other stealth models?"
        )
        stored = normalize_answer_for_storage(leaked)
        self.assertTrue(stored.startswith("Ox Alpha is an anonymous stealth AI model"))
        self.assertNotIn("User Question", stored)
        self.assertNotIn("Constraint 1", stored)
        self.assertNotIn("host facts", stored)
        self.assertIn("[1, 7]", stored)
        self.assertIn("Next:", stored)
        self.assertEqual(
            answer_needs_refine("what is ox-alpha", leaked),
            None,
        )
        planning_only = "*   Constraint 1: Answer only from the numbered TACU web sources.\n"
        self.assertEqual(
            answer_needs_refine("what is ox-alpha", planning_only),
            "showed planning instead of the answer",
        )


if __name__ == "__main__": unittest.main()
