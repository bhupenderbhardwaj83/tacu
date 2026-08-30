"""The question-to-SQL loop, driven by scripted models so behaviour is deterministic."""

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

from tacu import dataquery, dataset
from tacu.core import TacuError, evidence_text


def _csv(directory: Path, name: str = "sales.csv") -> Path:
    path = directory / name
    with path.open("w", encoding="utf-8") as handle:
        handle.write("id,region,status,amount\n")
        rows = [
            (1, "east", "paid", 100), (2, "east", "failed", 50),
            (3, "west", "paid", 200), (4, "west", "paid", 300),
            (5, "west", "failed", 25), (6, "north", "paid", 10),
        ]
        for row in rows:
            handle.write(",".join(str(value) for value in row) + "\n")
    return path


class ScriptedModel:
    """Returns queued replies in order and records what it was asked."""

    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.prompts: list[list[dict[str, str]]] = []
        self.model = "scripted"

    def __call__(self, messages: list[dict[str, str]]) -> str:
        self.prompts.append([dict(message) for message in messages])
        if not self.replies:
            return json.dumps({"action": "answer", "answer": "out of scripted replies"})
        return self.replies.pop(0)

    @property
    def last_user_message(self) -> str:
        return self.prompts[-1][-1]["content"]


def _sql(statement: str, why: str = "") -> str:
    return json.dumps({"action": "sql", "sql": statement, "why": why})


def _answer(text: str) -> str:
    return json.dumps({"action": "answer", "answer": text})


class LoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.home = root / "home"
        self.info = dataset.load_csv(_csv(root), name="sales", home=self.home)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _run(self, model: ScriptedModel, question: str = "which region sold most?", **kwargs):
        return dataquery.answer_question(
            self.info, question, client=model, chat=model, home=self.home, **kwargs)

    def test_query_then_answer(self) -> None:
        model = ScriptedModel(
            _sql("SELECT region, SUM(amount) AS total FROM data GROUP BY region"),
            _answer("West sold the most at 525."),
        )
        outcome = self._run(model)
        self.assertEqual(outcome.answer, "West sold the most at 525.")
        self.assertEqual(len(outcome.successful_steps), 1)
        self.assertEqual(outcome.steps[0].rows[0][0], "east")

    def test_real_results_are_shown_to_the_model(self) -> None:
        model = ScriptedModel(
            _sql("SELECT SUM(amount) FROM data"),
            _answer("685 in total."),
        )
        self._run(model)
        # The second prompt must contain the actual number from SQLite.
        self.assertIn("685", model.prompts[1][-1]["content"])

    def test_bad_column_is_corrected_from_the_error(self) -> None:
        model = ScriptedModel(
            _sql("SELECT nonexistent FROM data"),
            _sql("SELECT SUM(amount) AS total FROM data"),
            _answer("685 in total."),
        )
        outcome = self._run(model)
        self.assertTrue(outcome.steps[0].error)
        self.assertTrue(outcome.steps[1].ok)
        self.assertEqual(outcome.answer, "685 in total.")
        # The model was told what SQLite actually complained about.
        self.assertIn("no such column", model.prompts[1][-1]["content"].lower())

    def test_write_attempts_are_blocked_and_reported(self) -> None:
        model = ScriptedModel(
            _sql("DELETE FROM data"),
            _sql("SELECT COUNT(*) FROM data"),
            _answer("6 rows."),
        )
        outcome = self._run(model)
        self.assertIn("SELECT", outcome.steps[0].error)
        self.assertEqual(outcome.answer, "6 rows.")
        # The data survived the attempt.
        _, rows, _ = dataset.run_query(self.info, "SELECT COUNT(*) FROM data", home=self.home)
        self.assertEqual(rows[0][0], 6)

    def test_step_budget_is_honoured(self) -> None:
        model = ScriptedModel(*[_sql(f"SELECT {index} FROM data") for index in range(10)])
        outcome = self._run(model, max_steps=3)
        self.assertLessEqual(len(outcome.steps), 3)
        self.assertTrue(outcome.stopped_reason)

    def test_repeated_identical_query_is_stopped(self) -> None:
        same = _sql("SELECT COUNT(*) FROM data")
        model = ScriptedModel(same, same, same, same)
        outcome = self._run(model, max_steps=4)
        self.assertEqual(len(outcome.steps), 1, "the same query must not run twice")
        self.assertTrue(outcome.stopped_reason)

    def test_bare_sql_without_json_is_accepted(self) -> None:
        model = ScriptedModel(
            "SELECT COUNT(*) FROM data",
            _answer("6 rows."),
        )
        outcome = self._run(model)
        self.assertTrue(outcome.successful_steps)
        self.assertEqual(outcome.answer, "6 rows.")

    def test_json_in_a_fenced_code_block_is_parsed(self) -> None:
        model = ScriptedModel(
            "```json\n" + _sql("SELECT COUNT(*) FROM data") + "\n```",
            _answer("6 rows."),
        )
        outcome = self._run(model)
        self.assertTrue(outcome.successful_steps)

    def test_unusable_replies_end_with_an_honest_message(self) -> None:
        model = ScriptedModel("I cannot help", "still not json", "nope", "nope", "nope")
        outcome = self._run(model, max_steps=4)
        self.assertIn("could not", outcome.answer.casefold())

    def test_answer_without_querying_is_allowed(self) -> None:
        model = ScriptedModel(_answer("The table has four columns."))
        outcome = self._run(model, question="how many columns are there?")
        self.assertEqual(outcome.answer, "The table has four columns.")
        self.assertEqual(outcome.steps, [])

    def test_empty_question_is_refused(self) -> None:
        model = ScriptedModel(_answer("x"))
        with self.assertRaises(TacuError):
            self._run(model, question="   ")

    def test_forced_summary_when_budget_ends_mid_loop(self) -> None:
        model = ScriptedModel(
            _sql("SELECT region, SUM(amount) FROM data GROUP BY region"),
            _sql("SELECT status, COUNT(*) FROM data GROUP BY status"),
            "West leads with 525.",
        )
        outcome = self._run(model, max_steps=2)
        self.assertEqual(len(outcome.successful_steps), 2)
        self.assertIn("525", outcome.answer)

    def test_transcript_records_every_statement(self) -> None:
        model = ScriptedModel(
            _sql("SELECT COUNT(*) FROM data", why="count rows"),
            _answer("6 rows."),
        )
        outcome = self._run(model)
        transcript = outcome.transcript()
        self.assertIn("SELECT COUNT(*) FROM data", transcript)
        self.assertIn("count rows", transcript)
        self.assertIn("6 rows.", transcript)


class BriefingTests(unittest.TestCase):
    def test_briefing_describes_columns_without_leaking_all_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            info = dataset.load_csv(_csv(root), name="sales", home=home)
            text = dataquery.briefing(dataset.profile_dataset(info, home=home))
            for column in ("id", "region", "status", "amount"):
                self.assertIn(f'"{column}"', text)
            self.assertIn("6 rows", text)
            self.assertIn("distinct", text)
            # Compact enough for a small context window.
            self.assertLess(len(text), 1_500)

    def test_packet_briefing_lists_display_filters_and_avoids_select_star(self) -> None:
        notes = "\n".join(dataquery._pcap_ask_notes("show traffic with acme.example"))
        self.assertIn("not SELECT *", notes)
        self.assertNotIn("tcp.srcport", notes)
        self.assertNotIn("Catalog matches", notes)

    def test_filter_question_attaches_catalog_hits(self) -> None:
        from tacu.wsfilters import FilterField

        hit = FilterField("dns.qry.name", "Name", "dns")
        with patch("tacu.dataquery.lookup_filters", return_value=[hit]) as lookup:
            notes = "\n".join(dataquery._pcap_ask_notes("what wireshark filter shows dns queries"))
        lookup.assert_called_once()
        self.assertIn("Catalog matches", notes)
        self.assertIn("dns.qry.name", notes)
        self.assertIn("tcp.srcport", notes)

    def test_burp_briefing_points_at_form_not_raw_html(self) -> None:
        notes = "\n".join(dataquery._burp_ask_notes())
        self.assertIn("base64-decoded", notes)
        self.assertIn("form", notes)
        self.assertIn("location", notes)
        self.assertIn("SELECT item, time, method, url", notes)
        self.assertNotIn("SELECT *", notes.replace("not SELECT *", ""))


class SqlOnlyTests(unittest.TestCase):
    def test_returns_the_statement_without_running_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            info = dataset.load_csv(_csv(root), name="sales", home=home)
            model = ScriptedModel(_sql("SELECT region FROM data LIMIT 5"))
            statement = dataquery.first_sql_only(info, "regions?", chat=model, home=home)
            self.assertEqual(statement, "SELECT region FROM data LIMIT 5")

    def test_refuses_a_write_even_in_preview(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            info = dataset.load_csv(_csv(root), name="sales", home=home)
            model = ScriptedModel(_sql("DROP TABLE data"))
            with self.assertRaises(TacuError):
                dataquery.first_sql_only(info, "drop it", chat=model, home=home)


class ArgvNormalisationTests(unittest.TestCase):
    """`ti data ask` must not be captured by the top-level `ti ask` rule."""

    def test_dataset_name_is_kept_separate_from_the_question(self) -> None:
        from tacu.cli import normalize_natural_queries

        self.assertEqual(
            normalize_natural_queries(["data", "ask", "sales", "which", "region", "sold", "most"]),
            ["data", "ask", "sales", "which region sold most"],
        )

    def test_flags_survive_the_join(self) -> None:
        from tacu.cli import normalize_natural_queries

        self.assertEqual(
            normalize_natural_queries(["data", "ask", "sales", "how", "many", "--steps", "3"]),
            ["data", "ask", "sales", "how many", "--steps", "3"],
        )
        self.assertEqual(
            normalize_natural_queries(["data", "ask", "sales", "how", "many", "--sql-only"]),
            ["data", "ask", "sales", "how many", "--sql-only"],
        )

    def test_other_data_subcommands_are_untouched(self) -> None:
        from tacu.cli import normalize_natural_queries

        for argv in (
            ["data", "query", "sales", "SELECT * FROM data", "--limit", "5"],
            ["data", "load", "/tmp/x.csv", "--name", "sales"],
            # The literal word "ask" as search text must not be reinterpreted.
            ["data", "search", "sales", "ask"],
        ):
            self.assertEqual(normalize_natural_queries(argv), argv)

    def test_top_level_ask_still_joins_its_question(self) -> None:
        from tacu.cli import normalize_natural_queries

        self.assertEqual(
            normalize_natural_queries(["ask", "what", "is", "my", "ip"]),
            ["ask", "--", "what is my ip"],
        )

    def test_ask_data_name_is_rewritten_to_data_ask(self) -> None:
        from tacu.cli import normalize_natural_queries

        self.assertEqual(
            normalize_natural_queries(
                ["ask", "data", "google_logs", "what", "is", "the", "destination"]),
            ["data", "ask", "google_logs", "what is the destination"],
        )
        self.assertEqual(
            normalize_natural_queries(["ask", "data", "about", "this", "csv"]),
            ["ask", "--", "data about this csv"],
        )


class DataAskCliTests(unittest.TestCase):
    def test_cli_ask_runs_and_stores_a_turn(self) -> None:
        from tacu import cli, core

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir(parents=True)
            source = _csv(root)
            model = ScriptedModel(
                _sql("SELECT region, SUM(amount) AS total FROM data GROUP BY region ORDER BY total DESC"),
                _answer("West sold the most, 525 in total."),
            )
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch.object(cli, "_chat_text", lambda client, messages, **kwargs: model(messages)):
                self.assertEqual(cli.main(["data", "load", str(source), "--name", "sales"]), 0)
                self.assertEqual(
                    cli.main(["data", "ask", "sales", "which", "region", "sold", "most"]), 0)
                with core.HistoryStore(home / "history.db") as store:
                    turn = store.get()
                self.assertIsNotNone(turn)
                self.assertIn("525", turn.response)

    def test_cli_sql_only_does_not_execute(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir(parents=True)
            source = _csv(root)
            model = ScriptedModel(_sql("SELECT COUNT(*) FROM data"))
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch.object(cli, "_chat_text", lambda client, messages, **kwargs: model(messages)):
                cli.main(["data", "load", str(source), "--name", "sales"])
                self.assertEqual(
                    cli.main(["data", "ask", "sales", "how", "many", "--sql-only"]), 0)
            self.assertEqual(len(model.prompts), 1, "sql-only must make exactly one model call")

    def test_juicy_phrases_skip_the_model_and_print_clear_values(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir(parents=True)
            source = root / "dummy_sensitive_data.csv"
            source.write_text(
                "id,api_key,email\n1,DUMMY_secretkey99,ada@example.com\n", encoding="utf-8")
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("tacu.cli.ask") as ask_fn, \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["data", "load", str(source), "--name", "secrets"]), 0)
                self.assertEqual(
                    cli.main(["data", "ask", "secrets", "show", "me", "juicy", "information"]), 0)
                self.assertEqual(cli.main(["data", "juicy", "secrets"]), 0)
                listed = StringIO()
                with redirect_stdout(listed):
                    self.assertEqual(cli.main(["data", "list"]), 0)
            provider.assert_called_once()
            ask_fn.assert_called_once()
            shown = output.getvalue()
            self.assertIn("ada@example.com", shown)
            self.assertIn("DUMMY_secretkey99", shown)
            self.assertIn("high", shown)
            self.assertIn("EMAIL", shown)
            self.assertNotIn("[REDACTED", shown)
            self.assertIn("dummy sensitive data", listed.getvalue())
            self.assertIn("FILE", listed.getvalue())

    def test_juicy_kind_questions_use_the_inventory_not_sql(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir(parents=True)
            source = root / "people.csv"
            source.write_text(
                "id,phone,email,password\n1,9876543210,ada@example.com,s3cretPass\n",
                encoding="utf-8")
            output = StringIO()
            with patch.dict(os.environ, {"TACU_HOME": str(home)}), \
                 patch("tacu.cli.load_provider") as provider, \
                 patch("tacu.cli.ask") as ask_fn, \
                 redirect_stdout(output):
                self.assertEqual(cli.main(["data", "load", str(source), "--name", "people"]), 0)
                self.assertEqual(
                    cli.main(["data", "ask", "people", "are", "there", "mobile",
                              "numbers", "in", "the", "file"]), 0)
                self.assertEqual(
                    cli.main(["data", "ask", "people", "show", "me", "the", "passwords"]), 0)
            self.assertEqual(provider.call_count, 2)
            self.assertEqual(ask_fn.call_count, 2)
            phone_evidence = evidence_text(ask_fn.call_args_list[0].kwargs["tool_result"])
            pass_evidence = evidence_text(ask_fn.call_args_list[1].kwargs["tool_result"])
            self.assertIn("9876543210", phone_evidence)
            self.assertNotIn("s3cretPass", phone_evidence)
            self.assertIn("s3cretPass", pass_evidence)
            shown = output.getvalue()
            self.assertIn("9876543210", shown)
            self.assertIn("s3cretPass", shown)
            self.assertNotIn("◆ ANSWER", shown)


if __name__ == "__main__":
    unittest.main()
