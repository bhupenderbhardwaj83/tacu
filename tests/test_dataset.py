"""Temporary dataset store: loading, profiling, guarded querying, and expiry."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import dataset
from tacu.core import TacuError


def _csv(directory: Path, name: str = "sample.csv", rows: int = 50) -> Path:
    path = directory / name
    with path.open("w", encoding="utf-8") as handle:
        handle.write("id,name,email,score\n")
        for index in range(rows):
            handle.write(f"{index},user{index},user{index}@example.com,{index % 7}\n")
    return path


class LoadTests(unittest.TestCase):
    def test_loads_rows_and_infers_column_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = _csv(Path(directory))
            info = dataset.load_csv(source, home=home)
            self.assertEqual(info.row_count, 50)
            self.assertEqual(info.column_count, 4)
            self.assertEqual(info.columns, ["id", "name", "email", "score"])

            profile = dataset.profile_dataset(info, home=home)
            kinds = {column.name: column.affinity for column in profile.columns}
            self.assertEqual(kinds["id"], "INTEGER")
            self.assertEqual(kinds["score"], "INTEGER")
            self.assertEqual(kinds["email"], "TEXT")

    def test_numeric_columns_support_real_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            info = dataset.load_csv(_csv(Path(directory)), home=home)
            _, rows, _ = dataset.run_query(info, "SELECT SUM(score) FROM data", home=home)
            # Stored as numbers, not strings, so SUM is meaningful.
            self.assertEqual(rows[0][0], sum(index % 7 for index in range(50)))

    def test_messy_headers_become_safe_unique_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "messy.csv"
            source.write_text(
                'First Name,first name,2024 total,"weird!!col",\nA,B,1,C,D\n', encoding="utf-8")
            info = dataset.load_csv(source, home=home)
            for column in info.columns:
                self.assertTrue(column[0].isalpha() or column[0] == "_", column)
            self.assertEqual(len(set(column.casefold() for column in info.columns)),
                             len(info.columns), "column names must be unique")

            profile = dataset.profile_dataset(info, home=home)
            originals = {column.source_name for column in profile.columns}
            self.assertIn("First Name", originals)

    def test_ragged_rows_are_counted_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "ragged.csv"
            source.write_text("a,b,c\n1,2,3\n4,5\n6,7,8,9\n", encoding="utf-8")
            info = dataset.load_csv(source, home=home)
            self.assertEqual(info.row_count, 3)
            self.assertEqual(info.ragged_rows, 2)

    def test_tab_separated_files_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "tabs.tsv"
            source.write_text("alpha\tbeta\n1\t2\n3\t4\n", encoding="utf-8")
            info = dataset.load_csv(source, home=home)
            self.assertEqual(info.columns, ["alpha", "beta"])
            self.assertEqual(info.row_count, 2)

    def test_no_header_option_generates_column_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "raw.csv"
            source.write_text("1,2,3\n4,5,6\n", encoding="utf-8")
            info = dataset.load_csv(source, has_header=False, home=home)
            self.assertEqual(info.columns, ["column_1", "column_2", "column_3"])
            self.assertEqual(info.row_count, 2)

    def test_all_text_people_header_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "people.csv"
            source.write_text(
                "name,email,mobile,city,active\n"
                "Ada Lovelace,ada@example.test,+91 9000000001,London,yes\n"
                "Grace Hopper,grace@example.test,+91 9000000002,New York,yes\n"
                "Edsger Dijkstra,edsger@example.test,+91 9000000003,Nuenen,no\n"
                "Margaret Hamilton,margaret@example.test,+91 9000000004,Cambridge,yes\n",
                encoding="utf-8",
            )
            info = dataset.load_csv(source, home=home)
            self.assertEqual(info.row_count, 4)
            self.assertEqual(info.columns, ["name", "email", "mobile", "city", "active"])
            columns, rows, _ = dataset.head_rows(info, 4, home=home)
            self.assertEqual(columns[0], "name")
            self.assertEqual(rows[0][0], "Ada Lovelace")

    def test_explicit_header_resolves_ambiguous_text_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "ambiguous.csv"
            source.write_text("planet,shade\nMercury,grey\nVenus,yellow\n", encoding="utf-8")
            info = dataset.load_csv(source, has_header=True, home=home)
            self.assertEqual(info.columns, ["planet", "shade"])
            self.assertEqual(info.row_count, 2)

    def test_empty_and_missing_files_report_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            empty = Path(directory) / "empty.csv"
            empty.write_text("", encoding="utf-8")
            with self.assertRaises(TacuError):
                dataset.load_csv(empty, home=home)
            with self.assertRaises(TacuError):
                dataset.load_csv(Path(directory) / "absent.csv", home=home)

    def test_original_file_is_never_modified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = _csv(Path(directory))
            before = source.read_bytes()
            dataset.load_csv(source, home=home)
            self.assertEqual(source.read_bytes(), before)

    def test_store_files_are_owner_only(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX permissions only")
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            info = dataset.load_csv(_csv(Path(directory)), home=home)
            store = dataset.datasets_home(home) / f"{info.id}.db"
            if sys.platform != "win32":
                # Windows has no POSIX mode bits; only the read-only flag survives.
                self.assertEqual(store.stat().st_mode & 0o777, 0o600)
                self.assertEqual(dataset.datasets_home(home).stat().st_mode & 0o777, 0o700)


class QueryGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.home = root / "home"
        self.info = dataset.load_csv(_csv(root), home=self.home)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_select_returns_rows(self) -> None:
        columns, rows, _ = dataset.run_query(
            self.info, "SELECT name FROM data WHERE id < 3", home=self.home)
        self.assertEqual(columns, ["name"])
        self.assertEqual(len(rows), 3)

    def test_group_by_aggregation_works(self) -> None:
        _, rows, _ = dataset.run_query(
            self.info, "SELECT score, COUNT(*) FROM data GROUP BY score", home=self.home)
        self.assertEqual(len(rows), 7)

    def test_writes_are_refused(self) -> None:
        for statement in (
            "DELETE FROM data",
            "DROP TABLE data",
            "UPDATE data SET name='x'",
            "INSERT INTO data VALUES (1,'a','b',2)",
            "CREATE TABLE evil (x)",
            "ATTACH DATABASE '/tmp/x.db' AS other",
            "PRAGMA table_info(data)",
        ):
            with self.assertRaises(TacuError, msg=statement):
                dataset.run_query(self.info, statement, home=self.home)

    def test_stacked_statements_are_refused(self) -> None:
        with self.assertRaises(TacuError):
            dataset.run_query(self.info, "SELECT 1; DROP TABLE data", home=self.home)

    def test_comment_hidden_write_is_refused(self) -> None:
        with self.assertRaises(TacuError):
            dataset.run_query(self.info, "SELECT 1 /* x */ ; DELETE FROM data", home=self.home)

    def test_empty_query_explains_itself(self) -> None:
        with self.assertRaises(TacuError):
            dataset.run_query(self.info, "   ", home=self.home)

    def test_limit_is_applied_and_reported(self) -> None:
        _, rows, truncated = dataset.run_query(
            self.info, "SELECT * FROM data", limit=10, home=self.home)
        self.assertEqual(len(rows), 10)
        self.assertTrue(truncated)

    def test_bad_sql_produces_a_readable_error(self) -> None:
        with self.assertRaises(TacuError) as caught:
            dataset.run_query(self.info, "SELECT nope FROM data", home=self.home)
        self.assertIn("SQL error", str(caught.exception))

    def test_search_finds_rows_without_sql(self) -> None:
        _, rows, _ = dataset.search_rows(self.info, "user42", home=self.home)
        self.assertEqual(len(rows), 1)

    def test_search_respects_limit_flag_after_the_text(self) -> None:
        # REMAINDER used to swallow --limit into the search text and match nothing.
        from tacu import cli

        parsed = cli.parser().parse_args(
            ["data", "search", "demo", "client-42", "--limit", "3"])
        self.assertEqual(parsed.text, ["client-42"])
        self.assertEqual(parsed.limit, 3)

    def test_query_respects_limit_flag_after_the_sql(self) -> None:
        from tacu import cli

        parsed = cli.parser().parse_args(
            ["data", "query", "demo", "SELECT * FROM data", "--limit", "7"])
        self.assertEqual(parsed.sql, ["SELECT * FROM data"])
        self.assertEqual(parsed.limit, 7)

    def test_data_load_header_overrides_are_mutually_exclusive(self) -> None:
        from tacu import cli

        parsed = cli.parser().parse_args(["data", "load", "people.csv", "--header"])
        self.assertTrue(parsed.header)
        self.assertFalse(parsed.no_header)
        with self.assertRaises(SystemExit):
            cli.parser().parse_args(
                ["data", "load", "people.csv", "--header", "--no-header"])

    def test_head_returns_requested_row_count(self) -> None:
        _, rows, _ = dataset.head_rows(self.info, 5, home=self.home)
        self.assertEqual(len(rows), 5)


class LifetimeTests(unittest.TestCase):
    def test_expired_datasets_are_swept_and_files_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            info = dataset.load_csv(_csv(Path(directory)), ttl_hours=0.01, home=home)
            store = dataset.datasets_home(home) / f"{info.id}.db"
            self.assertTrue(store.is_file())

            past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            with dataset._catalog(home) as connection:
                connection.execute("UPDATE datasets SET expires_at=?", (past,))
                connection.commit()

            self.assertEqual(dataset.sweep_expired(home), 1)
            self.assertFalse(store.is_file())
            self.assertEqual(dataset.list_datasets(home), [])

    def test_listing_reports_time_remaining(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            info = dataset.load_csv(_csv(Path(directory)), ttl_hours=4, home=home)
            self.assertIn("left", info.remaining())
            self.assertFalse(info.expired)

    def test_resolution_by_name_and_id_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            info = dataset.load_csv(_csv(Path(directory)), name="orders", home=home)
            self.assertEqual(dataset.resolve_dataset("orders", home).id, info.id)
            self.assertEqual(dataset.resolve_dataset(info.id[:8], home).id, info.id)
            with self.assertRaises(TacuError):
                dataset.resolve_dataset("nothing-like-this", home)

    def test_default_names_are_incremental_dt_and_must_be_unique(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            root = Path(directory)
            first = dataset.load_csv(_csv(root, "dummy_sensitive_data.csv"), home=home)
            second = dataset.load_csv(_csv(root, "another_long_file_name.csv"), home=home)
            self.assertEqual(first.name, "dt1")
            self.assertEqual(second.name, "dt2")
            self.assertEqual(dataset.resolve_dataset("dt1", home).id, first.id)
            self.assertEqual(dataset.resolve_dataset("DT1", home).id, first.id)
            self.assertEqual(dataset.resolve_dataset(first.id, home).id, first.id)
            self.assertEqual(dataset.resolve_dataset(first.id[:8], home).id, first.id)
            custom = dataset.load_csv(_csv(root, "third.csv"), name="logs", home=home)
            self.assertEqual(custom.name, "logs")
            with self.assertRaises(TacuError):
                dataset.load_csv(_csv(root, "fourth.csv"), name="logs", home=home)
            fourth = dataset.load_csv(_csv(root, "fifth.csv"), home=home)
            self.assertEqual(fourth.name, "dt3")

    def test_drop_removes_one_and_all_removes_everything(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            root = Path(directory)
            first = dataset.load_csv(_csv(root, "a.csv"), name="a", home=home)
            dataset.load_csv(_csv(root, "b.csv"), name="b", home=home)
            dataset.drop_dataset(first, home)
            self.assertEqual(len(dataset.list_datasets(home)), 1)
            self.assertEqual(dataset.drop_all(home), 1)
            self.assertEqual(dataset.list_datasets(home), [])


class DataCliTests(unittest.TestCase):
    def test_full_command_flow(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir(parents=True)
            source = _csv(Path(directory))
            with patch.dict(os.environ, {"TACU_HOME": str(home)}):
                self.assertEqual(cli.main(["data", "load", str(source), "--name", "demo"]), 0)
                self.assertEqual(cli.main(["data", "list"]), 0)
                self.assertEqual(cli.main(["data", "show", "demo"]), 0)
                self.assertEqual(cli.main(["data", "head", "demo", "-n", "3"]), 0)
                self.assertEqual(
                    cli.main(["data", "query", "demo", "SELECT COUNT(*) FROM data"]), 0)
                self.assertEqual(cli.main(["data", "search", "demo", "user7"]), 0)
                self.assertEqual(cli.main(["data", "gc"]), 0)
                self.assertEqual(cli.main(["data", "rm", "demo"]), 0)

    def test_load_without_name_is_dt1_and_resolves_by_id(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir(parents=True)
            source = _csv(Path(directory), "dummy_sensitive_data.csv")
            with patch.dict(os.environ, {"TACU_HOME": str(home)}):
                self.assertEqual(cli.main(["data", "load", str(source)]), 0)
                items = dataset.list_datasets(home)
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0].name, "dt1")
                self.assertEqual(cli.main(["data", "show", "dt1"]), 0)
                self.assertEqual(cli.main(["data", "show", items[0].id[:8]]), 0)
                self.assertEqual(cli.main(["data", "head", items[0].id, "-n", "2"]), 0)

    def test_query_rejecting_a_write_exits_nonzero(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir(parents=True)
            source = _csv(Path(directory))
            with patch.dict(os.environ, {"TACU_HOME": str(home)}):
                cli.main(["data", "load", str(source), "--name", "demo"])
                self.assertEqual(cli.main(["data", "query", "demo", "DROP TABLE data"]), 1)


class FormattingTests(unittest.TestCase):
    def test_table_renders_headers_and_handles_nulls(self) -> None:
        rendered = dataset.format_table(["a", "b"], [(1, None), (2, "x")], color=False)
        self.assertIn("a", rendered)
        self.assertIn("x", rendered)
        self.assertEqual(len(rendered.splitlines()), 4)

    def test_packet_ports_are_tinted_without_breaking_alignment(self) -> None:
        from tacu.theme import PALETTE, strip_ansi

        rendered = dataset.format_table(
            ["src_port", "dst_port", "x"], [(443, 80, "ok")], color=True)
        self.assertIn(PALETTE.src, rendered)
        self.assertIn(PALETTE.dst, rendered)
        header, _rule, row = strip_ansi(rendered).splitlines()
        self.assertEqual(header.find("x"), row.find("ok"))
        plain = dataset.format_table(
            ["src_port", "dst_port", "x"], [(443, 80, "ok")], color=False)
        self.assertNotIn("\x1b[", plain)
        other = dataset.format_table(["amount"], [(9,)], color=True)
        self.assertNotIn("\x1b[", other)

    def test_secret_values_are_never_ellipsized(self) -> None:
        token = "dummyBearerToken_A1B2C3D4E5F6G7H8I9J0"
        rendered = dataset.format_table(
            ["kind", "value", "confidence"],
            [("bearer", token, "critical")],
            width=18, color=False,
        )
        self.assertIn(token, rendered)
        self.assertNotIn("…", rendered)
        self.assertNotIn("dummyBearerToken_A1B2C3D4E5…", rendered)

    def test_embedded_newlines_do_not_break_row_alignment(self) -> None:
        rendered = dataset.format_table(
            ["req_headers"], [("GET / HTTP/2\r\nHost: mail.google.com\r\n",)], color=False)
        self.assertEqual(len(rendered.splitlines()), 3)
        self.assertIn("GET / HTTP/2", rendered)
        self.assertNotIn("\r", rendered)


class SourceHintTests(unittest.TestCase):
    def test_first_words_of_the_filename_not_the_full_path(self) -> None:
        hint = dataset.source_hint(
            "/Users/me/Desktop/tacu/temp_remove/google_burp_logs.xml")
        self.assertEqual(hint, "google burp logs")
        self.assertEqual(
            dataset.source_hint("dummy_sensitive_data_1000_lines.csv"),
            "dummy sensitive data",
        )


class JuicyFilterTests(unittest.TestCase):
    def test_scans_credential_columns_in_the_clear(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "secrets.csv"
            source.write_text(
                "id,api_key,email\n"
                "1,DUMMY_abc12345678,ada@example.com\n",
                encoding="utf-8",
            )
            info = dataset.load_csv(source, name="secrets", home=home)
            columns, rows, truncated, how = dataset.filter_juicy(info, home=home)
            self.assertEqual(how, "scan")
            self.assertFalse(truncated)
            self.assertEqual(columns, ["where", "kind", "value", "confidence"])
            values = {row[2] for row in rows}
            self.assertIn("ada@example.com", values)
            self.assertIn("DUMMY_abc12345678", values)
            self.assertNotIn("[REDACTED", str(rows))

    def test_uses_the_juicy_column_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "http.csv"
            source.write_text(
                "time,url,juicy,req_body\n"
                "t,https://a.test/,email=ada@example.com,__VIEWSTATE=noise\n"
                "t,https://a.test/x,,html\n",
                encoding="utf-8",
            )
            info = dataset.load_csv(source, name="http", home=home)
            columns, rows, truncated, how = dataset.filter_juicy(info, home=home)
            self.assertEqual(how, "juicy column")
            self.assertIn("juicy", columns)
            self.assertEqual(len(rows), 1)
            self.assertIn("ada@example.com", rows[0][columns.index("juicy")])
            self.assertNotIn("__VIEWSTATE", str(rows))

    def test_reads_an_extract_findings_table_without_rescanning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "findings.csv"
            source.write_text(
                "kind,category,value,source file,source file line number,confidence\n"
                "username,identity,test_admin,page.html,10,medium\n"
                "password,authentication,Dummy-Passw0rd-Only-For-Testing!,page.html,11,high\n"
                "email,identity,ada@example.com,page.html,12,high\n",
                encoding="utf-8",
            )
            info = dataset.load_csv(source, name="dt2", home=home)
            columns, rows, truncated, how = dataset.filter_juicy(
                info, home=home, kinds=frozenset({"password"}))
            self.assertEqual(how, "findings table")
            self.assertFalse(truncated)
            self.assertEqual(columns, ["where", "kind", "value", "confidence"])
            values = {row[2] for row in rows}
            self.assertEqual(values, {"Dummy-Passw0rd-Only-For-Testing!"})
            self.assertNotIn("ada@example.com", values)
            self.assertNotIn("test_admin", values)

    def test_packet_column_is_the_where_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            source = Path(directory) / "frames.csv"
            source.write_text(
                "packet,src,email\n"
                "42,10.0.0.1,ada@example.com\n",
                encoding="utf-8",
            )
            info = dataset.load_csv(source, name="dns", home=home)
            columns, rows, truncated, how = dataset.filter_juicy(info, home=home)
            self.assertEqual(how, "scan")
            self.assertFalse(truncated)
            self.assertTrue(any("packet 42" in str(row[0]) for row in rows))
            self.assertTrue(any(row[2] == "ada@example.com" for row in rows))



if __name__ == "__main__":
    unittest.main()
