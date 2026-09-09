"""A guessed value may order results. It may never delete them.

The arguments a tool is given are derived by regex from how the user phrased
the question, so an empty result says the guess matched nothing — never that
nothing is there. `process.graph` was handed the filter "python servers" and
reported none while six were listening; `filesystem.find` reported no .md files
while twenty-two sat on disk. Both are the same fault, and this is the invariant
that closes it.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import procgraph
from tacu.coding import ANSWER_TOOL_SURFACE, CODING_TOOL_SURFACE
from tacu.companion import _graph_answer
from tacu.tools import filesystem, invoke, process, specs
from tacu.tools.contracts import ToolContext

PY_SERVER = {"runtime": "Python", "entrypoint": "http.server", "label": "Python http.server",
             "role": "server", "command": "/usr/bin/Python -m http.server 8971",
             "executable": "python", "user": "me", "listening": [{"port": 8971}]}
RAPPORTD = {"runtime": "rapportd", "entrypoint": "", "label": "rapportd", "role": "server",
            "command": "/usr/libexec/rapportd", "executable": "rapportd", "user": "me",
            "listening": [{"port": 1}]}


def _context() -> ToolContext:
    return ToolContext(Path.cwd(), Path.home() / ".local/share/tacu")


class PluralTests(unittest.TestCase):
    def test_a_trailing_s_no_longer_decides_the_answer(self) -> None:
        # `"servers" in "…server"` is False as raw text. That one letter is the
        # whole reason six running servers were reported as none.
        self.assertTrue(procgraph.same_word("servers", "server"))
        self.assertTrue(procgraph.same_word("processes", "process"))
        self.assertTrue(procgraph.same_word("boxes", "box"))

    def test_unrelated_words_are_still_unrelated(self) -> None:
        for one, other in (("python", "ruby"), ("go", "gone"), ("s", "server")):
            with self.subTest(pair=(one, other)):
                self.assertFalse(procgraph.same_word(one, other))

    def test_the_reported_query_now_scores(self) -> None:
        self.assertGreater(procgraph.match_score(PY_SERVER, "python servers"), 0)


class NoVetoTests(unittest.TestCase):
    def test_a_stray_word_no_longer_zeroes_a_good_match(self) -> None:
        # "let" and "know" survived the filler list and vetoed the whole query.
        self.assertGreater(procgraph.match_score(PY_SERVER, "let know python servers"), 0)

    def test_the_better_match_still_outranks_the_generic_one(self) -> None:
        self.assertGreater(procgraph.match_score(PY_SERVER, "python http server"),
                           procgraph.match_score(RAPPORTD, "python http server"))

    def test_a_partial_match_reports_which_words_it_answered(self) -> None:
        self.assertEqual(procgraph.answered_words(RAPPORTD, "python servers"), ["servers"])
        self.assertEqual(procgraph.answered_words(PY_SERVER, "python servers"),
                         ["python", "servers"])


class GraphNeverEmptyTests(unittest.TestCase):
    """Processes always exist, so an empty result is always a reporting failure."""

    def test_no_query_however_nonsensical_produces_an_empty_answer(self) -> None:
        for query in ("python servers", "let know flask servers", "zzzz nothing here",
                      "the", "a b c"):
            with self.subTest(query=query):
                result = process.execute(_context(), operation="graph", limit=20, query=query)
                self.assertGreater(result["count"], 0, query)
                self.assertNotEqual(result["status"], "no_results", query)

    def test_a_query_nothing_answers_to_says_so(self) -> None:
        result = process.execute(_context(), operation="graph", limit=20,
                                 query="zzzz-nothing-is-called-this")
        self.assertIn("nothing is named like that", result["widened"])

    def test_a_half_answered_query_names_the_half_it_missed(self) -> None:
        result = process.execute(_context(), operation="graph", limit=20,
                                 query="zzzznotathing servers")
        self.assertIn("zzzznotathing", result["widened"])
        self.assertIn("servers", result["widened"])

    def test_a_fully_answered_query_claims_nothing_extra(self) -> None:
        result = process.execute(_context(), operation="graph", limit=20, query="launchd")
        self.assertEqual(result["widened"], "")


class GraphAnswerTests(unittest.TestCase):
    def test_a_widened_result_announces_itself_instead_of_claiming_a_match(self) -> None:
        facts = {"operation": "graph", "focus": "python servers", "count": 11,
                 "widened": "nothing matches all of “python servers”; these match "
                            "“servers” but nothing here is named “python”",
                 "processes": [RAPPORTD]}
        answer = _graph_answer(facts)
        self.assertIn("nothing here is named", answer)
        self.assertNotIn("11 processes match", answer)

    def test_a_listing_that_does_not_fit_says_what_is_missing(self) -> None:
        facts = {"operation": "graph", "focus": "listening processes", "count": 18,
                 "widened": "", "processes": [dict(RAPPORTD, pid=n) for n in range(18)]}
        answer = _graph_answer(facts)
        self.assertIn("Showing 6 of 18", answer)

    def test_a_complete_listing_makes_no_such_apology(self) -> None:
        facts = {"operation": "graph", "focus": "ollama", "count": 2, "widened": "",
                 "processes": [dict(RAPPORTD, pid=1), dict(RAPPORTD, pid=2)]}
        self.assertNotIn("Showing", _graph_answer(facts))


class FindNeverEmptyTests(unittest.TestCase):
    def test_a_name_that_matches_nothing_returns_what_is_there(self) -> None:
        result = filesystem.execute(_context(), operation="find", root="src/tacu",
                                    name="zzzz-no-such-file", limit=20)
        self.assertGreater(result["count"], 0)
        self.assertIn("nothing here is named like", result["widened"])

    def test_a_name_that_matches_claims_nothing_extra(self) -> None:
        result = filesystem.execute(_context(), operation="find", root="src/tacu",
                                    name="procgraph", limit=20)
        self.assertGreater(result["count"], 0)
        self.assertEqual(result["widened"], "")


class CodingSurfaceTests(unittest.TestCase):
    """The coding lane could not look at the host at all, so it flailed at shell."""

    def test_the_read_only_host_tools_are_reachable(self) -> None:
        for name in ("process", "network"):
            with self.subTest(tool=name):
                self.assertIn(name, CODING_TOOL_SURFACE)

    def test_every_tool_added_only_reads(self) -> None:
        risk = {spec.name: spec.risk_level for spec in specs()}
        for name in ("process", "network"):
            with self.subTest(tool=name):
                self.assertEqual(risk[name], "read")

    def test_the_answer_surface_is_provably_read_only(self) -> None:
        risk = {spec.name: spec.risk_level for spec in specs()}
        offenders = [name for name in ANSWER_TOOL_SURFACE if risk.get(name) != "read"]
        self.assertEqual(offenders, [], "ti ask must not be able to reach a writing tool")

    def test_a_dangerous_operation_on_a_read_tool_is_still_gated(self) -> None:
        # process is read-risk overall, but process.kill needs review, and
        # widening the surface must not have opened a way around that.
        from tacu.codingpolicy import dispatch_coding
        refused: list[str] = []
        result = dispatch_coding("process", {"operation": "kill", "pid": 999_999},
                                 Path.cwd(), Path.home() / ".local/share/tacu", invoke,
                                 lambda message: refused.append(message) or False)
        self.assertEqual(result["status"], "error")
        self.assertIn("review", str(result.get("error")))


if __name__ == "__main__":
    unittest.main()
