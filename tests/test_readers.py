"""JSON, NDJSON, XLSX, PCAP and backup readers, and loading them into a dataset."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import struct
import sys
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from xlsx_fixture import write_xlsx

from tacu import dataset, readers
from tacu.core import TacuError


class DetectFormatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_json_array_is_detected(self) -> None:
        path = self._write("a.json", '[{"a":1},{"a":2}]')
        self.assertEqual(readers.detect_format(path), "json")

    def test_object_per_line_is_ndjson_even_with_a_json_extension(self) -> None:
        # This mislabelling is common in log exports and must not be trusted.
        path = self._write("a.json", '{"a":1}\n{"a":2}\n{"a":3}\n')
        self.assertEqual(readers.detect_format(path), "ndjson")

    def test_jsonl_extension_is_ndjson(self) -> None:
        path = self._write("a.jsonl", '{"a":1}\n{"a":2}\n{"a":3}\n')
        self.assertEqual(readers.detect_format(path), "ndjson")

    def test_csv_stays_csv(self) -> None:
        path = self._write("a.csv", "a,b\n1,2\n")
        self.assertEqual(readers.detect_format(path), "csv")

    def test_xlsx_is_detected_by_content_not_only_extension(self) -> None:
        path = write_xlsx(self.root / "book.bin", {"S": [["a"], [1]]})
        self.assertEqual(readers.detect_format(path), "xlsx")

    def test_two_line_ndjson_is_detected(self) -> None:
        """Short files must not be mistaken for documents just for being short."""

        path = self._write("a.json", '{"a":1}\n{"a":2}\n')
        self.assertEqual(readers.detect_format(path), "ndjson")

    def test_object_wrapping_a_list_of_records_is_a_document(self) -> None:
        path = self._write("a.json", '{"ok":true,"items":[{"a":1},{"a":2}]}')
        self.assertEqual(readers.detect_format(path), "json")

    def test_plain_object_is_treated_as_a_single_record(self) -> None:
        path = self._write("a.json", '{"name":"tacu","version":"1.2"}')
        self.assertEqual(readers.detect_format(path), "ndjson")

    def test_pretty_printed_object_loads_as_one_record(self) -> None:
        """No line of a pretty-printed document is valid JSON on its own."""

        path = self._write("a.json", '{\n  "name": "tacu",\n  "version": "1.2"\n}\n')
        records = list(readers.read_ndjson(path).records)
        self.assertEqual(records, [{"name": "tacu", "version": "1.2"}])

    def test_pretty_printed_array_of_records_is_a_document(self) -> None:
        path = self._write("a.json", '[\n  {"a": 1},\n  {"a": 2}\n]\n')
        self.assertEqual(readers.detect_format(path), "json")
        self.assertEqual(len(list(readers.read_json(path).records)), 2)

    def test_empty_file_is_refused(self) -> None:
        path = self._write("a.json", "   \n")
        with self.assertRaises(TacuError):
            readers.detect_format(path)

    def test_burp_xml_is_detected_without_an_xml_extension(self) -> None:
        request = base64.b64encode(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").decode("ascii")
        path = self.root / "export"
        path.write_text(
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2026.7.3">\n'
            f'  <item><url>https://a.test/</url><request base64="true">{request}</request></item>\n'
            "</items>\n",
            encoding="utf-8",
        )
        self.assertEqual(readers.detect_format(path), "burp")
        self.assertEqual(readers.detect_format(self.root / "export"), "burp")

    def test_html_page_is_text_not_burp_xml(self) -> None:
        path = self._write(
            "page.html",
            "<!DOCTYPE html>\n<html><body>hello ada@example.com</body></html>\n",
        )
        self.assertEqual(readers.detect_format(path), "text")

    def test_other_xml_is_not_treated_as_csv_or_burp(self) -> None:
        path = self._write("scan.xml", '<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>\n')
        with self.assertRaises(TacuError) as raised:
            readers.detect_format(path)
        message = str(raised.exception).casefold()
        self.assertIn("xml", message)
        self.assertIn("burp", message)


class FlattenTests(unittest.TestCase):
    def test_nested_objects_become_dotted_columns(self) -> None:
        flat = readers.flatten({"a": 1, "b": {"c": 2}}, depth=2)
        self.assertEqual(flat, {"a": 1, "b.c": 2})

    def test_depth_one_keeps_nested_objects_as_json(self) -> None:
        flat = readers.flatten({"a": 1, "b": {"c": 2}}, depth=1)
        self.assertEqual(flat["a"], 1)
        self.assertEqual(json.loads(flat["b"]), {"c": 2})

    def test_lists_are_always_json_text(self) -> None:
        flat = readers.flatten({"tags": ["x", "y"]}, depth=5)
        self.assertEqual(json.loads(flat["tags"]), ["x", "y"])

    def test_depth_beyond_the_limit_becomes_json(self) -> None:
        flat = readers.flatten({"a": {"b": {"c": {"d": 1}}}}, depth=2)
        self.assertEqual(json.loads(flat["a.b"]), {"c": {"d": 1}})

    def test_booleans_and_nulls_survive(self) -> None:
        flat = readers.flatten({"ok": True, "no": False, "missing": None})
        self.assertEqual(flat["ok"], 1)
        self.assertEqual(flat["no"], 0)
        self.assertIsNone(flat["missing"])

    def test_a_bare_scalar_becomes_a_value_column(self) -> None:
        self.assertEqual(readers.flatten(7), {"value": 7})


class NdjsonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_records_are_read_line_by_line(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text('{"a":1}\n{"a":2}\n{"a":3}\n', encoding="utf-8")
        self.assertEqual([record["a"] for record in readers.read_ndjson(path).records], [1, 2, 3])

    def test_blank_lines_and_stray_brackets_are_ignored(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text('[\n{"a":1},\n\n{"a":2}\n]\n', encoding="utf-8")
        self.assertEqual([record["a"] for record in readers.read_ndjson(path).records], [1, 2])

    def test_a_broken_line_is_skipped_rather_than_losing_the_file(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text('{"a":1}\nnot json\n{"a":2}\n', encoding="utf-8")
        self.assertEqual([record["a"] for record in readers.read_ndjson(path).records], [1, 2])

    def test_strict_mode_reports_the_broken_line(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text('{"a":1}\nnot json\n', encoding="utf-8")
        with self.assertRaises(TacuError) as caught:
            list(readers.read_ndjson(path, strict=True).records)
        self.assertIn("line 2", str(caught.exception))


class JsonArrayScannerTests(unittest.TestCase):
    """The scanner replaces json.load, so its edge cases matter most."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _read(self, text: str, **kwargs) -> list[dict]:
        path = self.root / "a.json"
        path.write_text(text, encoding="utf-8")
        return list(readers.read_json(path, **kwargs).records)

    def test_top_level_array(self) -> None:
        self.assertEqual([record["a"] for record in self._read('[{"a":1},{"a":2}]')], [1, 2])

    def test_records_under_a_key_are_found(self) -> None:
        records = self._read('{"ok":true,"items":[{"a":1},{"a":2}]}')
        self.assertEqual([record["a"] for record in records], [1, 2])

    def test_named_key_is_honoured_when_several_arrays_exist(self) -> None:
        text = '{"errors":[{"a":9}],"items":[{"a":1},{"a":2}]}'
        self.assertEqual([record["a"] for record in self._read(text, array_path="items")], [1, 2])
        self.assertEqual([record["a"] for record in self._read(text, array_path="errors")], [9])

    def test_missing_key_is_reported(self) -> None:
        with self.assertRaises(TacuError):
            self._read('{"items":[{"a":1}]}', array_path="nope")

    def test_structural_characters_inside_strings_do_not_split_records(self) -> None:
        records = self._read('[{"m":"a],[b{}c,d"},{"m":"plain"}]')
        self.assertEqual(records[0]["m"], "a],[b{}c,d")
        self.assertEqual(len(records), 2)

    def test_escaped_quotes_and_backslashes_are_handled(self) -> None:
        original = [{"m": 'say "hi"'}, {"m": "back\\slash"}, {"m": "new\nline"}]
        records = self._read(json.dumps(original))
        self.assertEqual([record["m"] for record in records], [item["m"] for item in original])

    def test_deeply_nested_records_stay_whole(self) -> None:
        records = self._read('[{"a":{"b":[1,2,{"c":3}]}},{"a":{"b":[]}}]')
        self.assertEqual(len(records), 2)
        self.assertEqual(json.loads(records[0]["a.b"]), [1, 2, {"c": 3}])

    def test_whitespace_and_newlines_between_records(self) -> None:
        self.assertEqual(len(self._read('[\n  {"a":1} ,\n\n  {"a":2}\n]\n')), 2)

    def test_empty_array(self) -> None:
        self.assertEqual(self._read("[]"), [])

    def test_record_boundaries_are_found_across_block_edges(self) -> None:
        """A record split across two reads must not be lost or duplicated."""

        original = [{"index": index, "padding": "x" * 997} for index in range(400)]
        path = self.root / "a.json"
        path.write_text(json.dumps(original), encoding="utf-8")
        with patch.object(readers, "READ_BLOCK", 61):  # a size that lands mid-record
            records = list(readers.read_json(path).records)
        self.assertEqual([record["index"] for record in records],
                         [item["index"] for item in original])

    def test_malformed_record_is_reported_clearly(self) -> None:
        with self.assertRaises(TacuError):
            self._read('[{"a":1},{"a":}]')

    def test_a_top_level_scalar_is_refused(self) -> None:
        with self.assertRaises(TacuError):
            self._read('"just a string"')

    def _peak_reading(self, records: int) -> tuple[int, int, int]:
        path = self.root / f"big{records}.json"
        with path.open("w", encoding="utf-8") as handle:
            handle.write("[")
            for index in range(records):
                if index:
                    handle.write(",")
                handle.write(json.dumps({"index": index, "padding": "y" * 200}))
            handle.write("]")
        tracemalloc.start()
        count = sum(1 for _ in readers.read_json(path).records)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        return count, peak, path.stat().st_size

    def test_memory_does_not_grow_with_the_size_of_the_array(self) -> None:
        """The point of the scanner: peak memory must not track file size.

        Comparing two sizes is the honest test — a single absolute threshold
        would pass even if usage grew linearly.
        """

        small_count, small_peak, small_size = self._peak_reading(5_000)
        large_count, large_peak, large_size = self._peak_reading(40_000)
        self.assertEqual((small_count, large_count), (5_000, 40_000))
        self.assertGreater(large_size, small_size * 4)
        # Eight times the data must not cost anything like eight times the memory.
        self.assertLess(large_peak, small_peak * 2,
                        f"{small_size} bytes peaked at {small_peak}, "
                        f"but {large_size} bytes peaked at {large_peak}")
        self.assertLess(large_peak, large_size // 2)


class XlsxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _book(self) -> Path:
        return write_xlsx(
            self.root / "book.xlsx",
            {
                "Sales": [
                    ["name", "region", "amount", "signed_on", "active"],
                    ["Ada", "east", 1200, ("date", 45000), True],
                    ["Grace", "west", 980.5, ("date", 45001), False],
                    ["Alan", None, 50, ("date", 45002), True],
                ],
                "Notes": [["note"], ["second sheet"]],
            },
            skip_cells={(4, 1)},
        )

    def test_first_sheet_is_read_with_headers_as_keys(self) -> None:
        records = list(readers.read_xlsx(self._book()).records)
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["name"], "Ada")
        self.assertEqual(records[1]["amount"], "980.5")

    def test_date_serials_become_readable_dates(self) -> None:
        records = list(readers.read_xlsx(self._book()).records)
        self.assertEqual(records[0]["signed_on"], "2023-03-15")
        self.assertEqual(records[2]["signed_on"], "2023-03-17")

    def test_booleans_become_one_and_zero(self) -> None:
        records = list(readers.read_xlsx(self._book()).records)
        self.assertEqual(records[0]["active"], 1)
        self.assertEqual(records[1]["active"], 0)

    def test_a_skipped_cell_leaves_later_columns_in_place(self) -> None:
        """Sparse cells are why cell references are used instead of position."""

        records = list(readers.read_xlsx(self._book()).records)
        self.assertIsNone(records[2]["region"])
        self.assertEqual(records[2]["amount"], "50")

    def test_named_sheet_is_selected(self) -> None:
        records = list(readers.read_xlsx(self._book(), sheet="Notes").records)
        self.assertEqual(records, [{"note": "second sheet"}])

    def test_unknown_sheet_lists_what_is_available(self) -> None:
        with self.assertRaises(TacuError) as caught:
            list(readers.read_xlsx(self._book(), sheet="Ghost").records)
        self.assertIn("Sales", str(caught.exception))

    def test_sheet_names_are_reported(self) -> None:
        self.assertEqual(readers.sheet_names(self._book()), ["Sales", "Notes"])

    def test_no_header_names_columns_by_position(self) -> None:
        book = write_xlsx(self.root / "plain.xlsx", {"S": [["a", 1], ["b", 2]]})
        records = list(readers.read_xlsx(book, has_header=False).records)
        self.assertEqual(records[0], {"column_1": "a", "column_2": "1"})

    def test_blank_rows_are_skipped(self) -> None:
        book = write_xlsx(self.root / "gap.xlsx", {"S": [["a"], [None], ["x"]]})
        records = list(readers.read_xlsx(book).records)
        self.assertEqual(records, [{"a": "x"}])


class LoadRecordsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.home = self.root / "home"

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_ndjson_becomes_a_queryable_dataset(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text("".join(
            json.dumps({"id": index, "user": {"plan": "pro" if index % 2 else "free"}}) + "\n"
            for index in range(10)), encoding="utf-8")
        info = dataset.load_any(path, name="a", home=self.home)
        self.assertEqual(info.row_count, 10)
        self.assertIn("user_plan", info.columns)
        _, rows, _ = dataset.run_query(
            info, "SELECT user_plan, COUNT(*) FROM data GROUP BY user_plan", home=self.home)
        self.assertEqual(dict(rows), {"free": 5, "pro": 5})

    def test_types_are_inferred_from_json_values(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text('{"n":1,"f":1.5,"s":"x"}\n{"n":2,"f":2.5,"s":"y"}\n', encoding="utf-8")
        info = dataset.load_any(path, name="a", home=self.home)
        profile = dataset.profile_dataset(info, home=self.home)
        kinds = {column.name: column.affinity for column in profile.columns}
        self.assertEqual(kinds["n"], "INTEGER")
        self.assertEqual(kinds["f"], "REAL")
        self.assertEqual(kinds["s"], "TEXT")

    def test_records_with_different_keys_are_unioned(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text('{"a":1}\n{"b":2}\n{"a":3,"b":4}\n', encoding="utf-8")
        info = dataset.load_any(path, name="a", home=self.home)
        self.assertEqual(sorted(info.columns), ["a", "b"])
        _, rows, _ = dataset.run_query(
            info, "SELECT COUNT(a), COUNT(b) FROM data", home=self.home)
        self.assertEqual(rows[0], (2, 2))

    def test_original_key_is_remembered_for_renamed_columns(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text('{"user":{"id":1}}\n', encoding="utf-8")
        info = dataset.load_any(path, name="a", home=self.home)
        profile = dataset.profile_dataset(info, home=self.home)
        origins = {column.name: column.source_name for column in profile.columns}
        self.assertEqual(origins["user_id"], "user.id")

    def test_json_column_is_queryable_with_json_extract(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text('{"items":[{"qty":2},{"qty":3}]}\n{"items":[]}\n', encoding="utf-8")
        info = dataset.load_any(path, name="a", home=self.home)
        _, rows, _ = dataset.run_query(
            info, "SELECT SUM(json_extract(e.value,'$.qty')) FROM data, json_each(data.items) e",
            home=self.home)
        self.assertEqual(rows[0][0], 5)

    def test_xlsx_becomes_a_queryable_dataset_with_typed_columns(self) -> None:
        book = write_xlsx(self.root / "b.xlsx", {
            "S": [["city", "people"], ["Pune", 7000000], ["Oslo", 700000]]})
        info = dataset.load_any(book, name="b", home=self.home)
        _, rows, _ = dataset.run_query(
            info, "SELECT city FROM data WHERE people > 1000000", home=self.home)
        self.assertEqual(rows, [("Pune",)])

    def test_too_many_columns_suggests_a_shallower_load(self) -> None:
        wide = {f"key_{index}": index for index in range(dataset.MAX_COLUMNS + 5)}
        path = self.root / "wide.ndjson"
        path.write_text(json.dumps(wide) + "\n", encoding="utf-8")
        with self.assertRaises(TacuError) as caught:
            dataset.load_any(path, name="wide", home=self.home)
        self.assertIn("--depth", str(caught.exception))

    def test_empty_file_is_refused(self) -> None:
        path = self.root / "a.ndjson"
        path.write_text("", encoding="utf-8")
        with self.assertRaises(TacuError):
            dataset.load_any(path, name="a", home=self.home)

    def test_csv_still_goes_through_the_delimited_loader(self) -> None:
        path = self.root / "a.csv"
        path.write_text("a,b\n1,2\n3,4\n", encoding="utf-8")
        info = dataset.load_any(path, name="a", home=self.home)
        self.assertEqual((info.row_count, info.column_count), (2, 2))


class LoadCliTests(unittest.TestCase):
    def test_cli_loads_each_format_and_reports_it(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            (root / "a.ndjson").write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
            (root / "b.json").write_text('{"items":[{"a":1},{"a":2},{"a":3}]}', encoding="utf-8")
            write_xlsx(root / "c.xlsx", {"S": [["a"], [1], [2], [3], [4]]})
            expected = {"a": 2, "b": 3, "c": 4}
            with patch.dict(os.environ, {"TACU_HOME": str(home)}):
                for name, rows in expected.items():
                    suffix = {"a": "ndjson", "b": "json", "c": "xlsx"}[name]
                    code = cli.main(["data", "load", str(root / f"{name}.{suffix}"),
                                     "--name", name])
                    self.assertEqual(code, 0)
                    info = dataset.resolve_dataset(name, home=home)
                    self.assertEqual(info.row_count, rows, f"{name}.{suffix}")

    def test_cli_path_option_selects_the_array(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            (root / "a.json").write_text(
                '{"errors":[{"a":1}],"items":[{"a":1},{"a":2}]}', encoding="utf-8")
            with patch.dict(os.environ, {"TACU_HOME": str(home)}):
                cli.main(["data", "load", str(root / "a.json"), "--name", "a",
                          "--path", "errors"])
            self.assertEqual(dataset.resolve_dataset("a", home=home).row_count, 1)

    def test_cli_sheet_option_selects_the_sheet(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            write_xlsx(root / "b.xlsx", {"One": [["a"], [1]], "Two": [["a"], [1], [2]]})
            with patch.dict(os.environ, {"TACU_HOME": str(home)}):
                cli.main(["data", "load", str(root / "b.xlsx"), "--name", "b", "--sheet", "Two"])
            self.assertEqual(dataset.resolve_dataset("b", home=home).row_count, 2)

    def test_cli_enriches_a_loaded_pcap(self) -> None:
        from tacu import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            path = write_pcap(root / "cap.pcap", [
                _ethernet(_ipv4("8.8.8.8", "10.0.0.1", 17,
                                _udp(53, 53, _dns_response("acme.example", "203.0.113.10")))),
                _ethernet(_ipv4("10.0.0.1", "203.0.113.10", 6, _tcp(1, 443, 0x02, b""))),
            ])
            with patch.dict(os.environ, {"TACU_HOME": str(home)}):
                self.assertEqual(cli.main(["data", "load", str(path), "--name", "wireshark"]), 0)
                self.assertEqual(cli.main(["data", "enrich", "wireshark"]), 0)
                info = dataset.resolve_dataset("wireshark", home=home)
            _, rows, _ = dataset.run_query(
                info, "SELECT dst_name FROM data WHERE protocol = 'TCP'", home=home)
            self.assertEqual(rows[0][0], "acme.example")


def _ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return (bytes.fromhex("001122334455aabbccddeeff")
            + struct.pack("!H", ethertype) + payload)


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    import socket

    total = 20 + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 1, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + payload


def _tcp(src_port: int, dst_port: int, flags: int, payload: bytes) -> bytes:
    offset = 5 << 4
    return struct.pack("!HHIIBBHHH", src_port, dst_port, 1, 0, offset, flags, 8192, 0, 0) + payload


def _udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def _dns_query(name: str = "example.com") -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + _dns_name(name) + struct.pack("!HH", 1, 1)


def _dns_response(qname: str, ip: str, *, ident: int = 0x1234) -> bytes:
    import socket

    header = struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0)
    question = _dns_name(qname) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + question + answer


def _dns_cname(qname: str, target: str, *, ident: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0)
    question = _dns_name(qname) + struct.pack("!HH", 1, 1)
    rdata = _dns_name(target)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
    return header + question + answer


def _tls_client_hello(sni: str) -> bytes:
    name = sni.encode("ascii")
    name_entry = bytes([0]) + struct.pack("!H", len(name)) + name
    sni_data = struct.pack("!H", len(name_entry)) + name_entry
    extension = struct.pack("!HH", 0, len(sni_data)) + sni_data
    body = (
        b"\x03\x03" + (b"\x00" * 32) + b"\x00"
        + struct.pack("!H", 2) + b"\x00\x2f"
        + b"\x01\x00"
        + struct.pack("!H", len(extension)) + extension
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x03]) + struct.pack("!H", len(handshake)) + handshake


def write_pcap(path: Path, frames: list[bytes], ts: int = 1_700_000_000) -> Path:
    parts = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for index, frame in enumerate(frames):
        parts.append(struct.pack("<IIII", ts, index * 1000, len(frame), len(frame)))
        parts.append(frame)
    path.write_bytes(b"".join(parts))
    return path


def write_pcapng(path: Path, frame: bytes) -> Path:
    def block(kind: int, payload: bytes) -> bytes:
        length = 12 + len(payload)
        pad = (4 - (len(payload) % 4)) % 4
        length += pad
        return struct.pack("<II", kind, length) + payload + (b"\x00" * pad) + struct.pack("<I", length)

    shb = struct.pack("<II", 0x0A0D0D0A, 28) + b"\x4d\x3c\x2b\x1a" + struct.pack("<HHqI", 1, 0, -1, 28)
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    epb = block(6, struct.pack("<IIIII", 0, 0, 0, len(frame), len(frame)) + frame)
    path.write_bytes(shb + idb + epb)
    return path


class PcapAndBakTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_pcap_extension_is_detected(self) -> None:
        path = write_pcap(self.root / "a.pcap", [
            _ethernet(_ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(1234, 80, 0x18, b"GET / HTTP/1.1\r\n"))),
        ])
        self.assertEqual(readers.detect_format(path), "pcap")

    def test_pcap_packets_become_filterable_rows(self) -> None:
        http = _ethernet(_ipv4("10.0.0.1", "8.8.8.8", 6, _tcp(5555, 80, 0x18, b"GET /index HTTP/1.1\r\n")))
        dns = _ethernet(_ipv4("10.0.0.1", "8.8.8.8", 17, _udp(53000, 53, _dns_query("example.com"))))
        path = write_pcap(self.root / "cap.pcap", [http, dns])
        records = list(readers.read_pcap(path).records)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["src"], "10.0.0.1")
        self.assertEqual(records[0]["dst"], "8.8.8.8")
        self.assertEqual(records[0]["protocol"], "HTTP")
        self.assertIn("GET /index", str(records[0]["info"]))
        self.assertEqual(records[1]["protocol"], "DNS")
        self.assertEqual(records[1]["info"], "example.com")
        self.assertEqual(records[1]["dst_port"], 53)
        self.assertIn("src_name", records[0])
        self.assertIn("dst_name", records[0])
        self.assertNotIn("_names", records[0])

    def test_dns_answer_names_later_tcp_to_that_ip(self) -> None:
        dns = _ethernet(_ipv4("8.8.8.8", "10.0.0.1", 17,
                              _udp(53, 53000, _dns_response("acme.example", "203.0.113.10"))))
        tcp = _ethernet(_ipv4("10.0.0.1", "203.0.113.10", 6, _tcp(5555, 443, 0x02, b"")))
        path = write_pcap(self.root / "acme.pcap", [dns, tcp])
        records = list(readers.read_pcap(path).records)
        self.assertEqual(records[0]["protocol"], "DNS")
        self.assertIn("203.0.113.10", str(records[0]["info"]))
        self.assertEqual(records[1]["protocol"], "TCP")
        self.assertEqual(records[1]["dst"], "203.0.113.10")
        self.assertEqual(records[1]["dst_name"], "acme.example")
        self.assertEqual(records[1]["src_name"], "")

    def test_http_host_and_tls_sni_name_the_destination(self) -> None:
        http = _ethernet(_ipv4(
            "10.0.0.1", "93.184.216.34", 6,
            _tcp(4000, 80, 0x18, b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
        ))
        later = _ethernet(_ipv4("10.0.0.1", "93.184.216.34", 6, _tcp(4000, 80, 0x10, b"")))
        hello = _ethernet(_ipv4(
            "10.0.0.1", "198.51.100.7", 6, _tcp(5000, 443, 0x18, _tls_client_hello("acme.example")),
        ))
        tls = _ethernet(_ipv4("10.0.0.1", "198.51.100.7", 6, _tcp(5000, 443, 0x10, b"")))
        path = write_pcap(self.root / "sites.pcap", [http, later, hello, tls])
        records = list(readers.read_pcap(path).records)
        self.assertEqual(records[0]["http_host"], "www.example.com")
        self.assertEqual(records[0]["dst_name"], "www.example.com")
        self.assertEqual(records[1]["dst_name"], "www.example.com")
        self.assertEqual(records[2]["sni"], "acme.example")
        self.assertEqual(records[2]["dst_name"], "acme.example")
        self.assertEqual(records[3]["dst_name"], "acme.example")

    def test_cname_from_one_packet_names_a_record_from_another(self) -> None:
        cname = _ethernet(_ipv4("8.8.8.8", "10.0.0.1", 17,
                                _udp(53, 53000, _dns_cname("acme.example", "waf.example.net"))))
        answer = _ethernet(_ipv4("8.8.8.8", "10.0.0.1", 17,
                                 _udp(53, 53001, _dns_response("waf.example.net", "203.0.113.50"))))
        tcp = _ethernet(_ipv4("10.0.0.1", "203.0.113.50", 6, _tcp(4433, 443, 0x02, b"")))
        path = write_pcap(self.root / "waf.pcap", [cname, answer, tcp])
        records = list(readers.read_pcap(path).records)
        self.assertIn("acme.example", records[2]["dst_name"])
        self.assertIn("waf.example.net", records[2]["dst_name"])

    def test_enrich_rebuilds_an_existing_pcap_dataset(self) -> None:
        path = write_pcap(self.root / "net.pcap", [
            _ethernet(_ipv4("8.8.8.8", "10.1.1.1", 17,
                            _udp(53, 53, _dns_response("tacu.test", "10.1.1.9")))),
            _ethernet(_ipv4("10.1.1.1", "10.1.1.9", 6, _tcp(9, 443, 0x02, b""))),
        ])
        home = self.root / "home"
        info = dataset.load_any(path, name="net", home=home)
        rebuilt = dataset.enrich_dataset(info, home=home)
        self.assertEqual(rebuilt.name, "net")
        _, rows, _ = dataset.run_query(
            rebuilt, "SELECT dst, dst_name FROM data WHERE protocol = 'TCP'", home=home)
        self.assertEqual(rows[0][0], "10.1.1.9")
        self.assertEqual(rows[0][1], "tacu.test")

    def test_enrich_refuses_a_non_pcap_dataset(self) -> None:
        path = self.root / "a.csv"
        path.write_text("a,b\n1,2\n", encoding="utf-8")
        home = self.root / "home"
        info = dataset.load_any(path, name="csv", home=home)
        with self.assertRaises(TacuError) as caught:
            dataset.enrich_dataset(info, home=home)
        self.assertIn("packet capture", str(caught.exception))

    def test_pcapng_is_detected_and_loaded(self) -> None:
        frame = _ethernet(_ipv4("192.168.1.10", "192.168.1.1", 6, _tcp(4000, 443, 0x02, b"")))
        path = write_pcapng(self.root / "a.pcapng", frame)
        self.assertEqual(readers.detect_format(path), "pcap")
        records = list(readers.read_pcap(path).records)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["src"], "192.168.1.10")
        self.assertEqual(records[0]["dst_port"], 443)
        self.assertIn("SYN", str(records[0]["info"]))

    def test_pcap_loads_into_a_queryable_dataset(self) -> None:
        path = write_pcap(self.root / "net.pcap", [
            _ethernet(_ipv4("10.1.1.1", "10.1.1.2", 17, _udp(123, 53, _dns_query("tacu.test")))),
        ])
        home = self.root / "home"
        info = dataset.load_any(path, name="net", home=home)
        self.assertEqual(info.row_count, 1)
        _, rows, _ = dataset.run_query(info, "SELECT src, protocol, info FROM data", home=home)
        self.assertEqual(rows[0][0], "10.1.1.1")
        self.assertEqual(rows[0][1], "DNS")
        self.assertEqual(rows[0][2], "tacu.test")

    def test_sqlite_bak_is_detected_and_loaded(self) -> None:
        path = self.root / "notes.bak"
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE notes (id INTEGER, body TEXT)")
            connection.execute("INSERT INTO notes VALUES (1, 'hello')")
            connection.execute("INSERT INTO notes VALUES (2, 'world')")
            connection.commit()
        self.assertEqual(readers.detect_format(path), "sqlite")
        home = self.root / "home"
        info = dataset.load_any(path, name="notes", home=home)
        self.assertEqual(info.row_count, 2)
        _, rows, _ = dataset.run_query(info, "SELECT body FROM data WHERE id = 2", home=home)
        self.assertEqual(rows[0][0], "world")

    def test_json_bak_loads_as_json(self) -> None:
        path = self.root / "export.bak"
        path.write_text('[{"host":"a"},{"host":"b"}]', encoding="utf-8")
        self.assertEqual(readers.detect_format(path), "json")
        info = dataset.load_any(path, name="export", home=self.root / "home")
        self.assertEqual(info.row_count, 2)

    def test_text_bak_becomes_one_row_per_line(self) -> None:
        path = self.root / "dump.bak"
        path.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
        self.assertEqual(readers.detect_format(path), "text")
        records = list(readers.read_text(path).records)
        self.assertEqual([row["text"] for row in records], ["alpha", "beta", "gamma"])

    def test_binary_bak_that_is_not_sqlite_or_pcap_is_refused(self) -> None:
        path = self.root / "opaque.bak"
        path.write_bytes(b"\x00\x01\x02\x03" + b"\xff" * 32)
        with self.assertRaises(TacuError) as raised:
            readers.detect_format(path)
        self.assertIn("cannot unpack", str(raised.exception))

    def test_text_bak_mentioning_sql_server_is_still_text(self) -> None:
        path = self.root / "notes.bak"
        path.write_text("Microsoft SQL Server notes\nsecond line\n", encoding="utf-8")
        self.assertEqual(readers.detect_format(path), "text")

    def test_sql_server_bak_explains_that_tables_cannot_be_restored(self) -> None:
        path = self.root / "mydatabase.bak"
        marker = "Microsoft SQL Server".encode("utf-16-le")
        path.write_bytes(b"\x01\x0f\x00\x00" + b"\x00" * 80 + marker + b"\x00" * 40)
        with self.assertRaises(TacuError) as raised:
            readers.detect_format(path)
        message = str(raised.exception)
        self.assertIn("SQL Server", message)
        self.assertIn("bcp", message)
        self.assertIn("ti data load", message)

    def test_registry_hive_becomes_one_row_per_value(self) -> None:
        path = self.root / "SOFTWARE.bak"
        _write_minimal_hive(path)
        self.assertEqual(readers.detect_format(path), "registry")
        home = self.root / "home"
        info = dataset.load_any(path, name="hive", home=home)
        self.assertGreaterEqual(info.row_count, 2)
        _, rows, _ = dataset.run_query(
            info, "SELECT name, data FROM data WHERE name = 'Build'", home=home)
        self.assertEqual(rows[0][0], "Build")
        self.assertEqual(str(rows[0][1]), "26100")
        _, nested, _ = dataset.run_query(
            info, "SELECT data FROM data WHERE name = 'Start'", home=home)
        self.assertEqual(str(nested[0][0]), "3")


def _pad8(length: int) -> int:
    return (length + 7) & ~7


def _hive_cell(body: bytes) -> bytes:
    size = _pad8(4 + len(body))
    return struct.pack("<i", -size) + body + b"\x00" * (size - 4 - len(body))


def _nk_cell(*, name: str, flags: int, parent: int, subkeys: int, subkey_list: int,
             values: int, value_list: int) -> bytes:
    raw = name.encode("latin-1")
    body = b"nk" + struct.pack("<H", flags)
    body += struct.pack("<Q", 0)
    body += struct.pack("<II", 0, parent)
    body += struct.pack("<IIII", subkeys, 0, subkey_list, 0xFFFFFFFF)
    body += struct.pack("<IIII", values, value_list, 0xFFFFFFFF, 0xFFFFFFFF)
    body += struct.pack("<5I", 0, 0, 0, 0, 0)
    body += struct.pack("<HH", len(raw), 0)
    body += raw
    return _hive_cell(body)


def _vk_cell(*, name: str, kind: int, data: bytes) -> bytes:
    raw = name.encode("latin-1")
    data_len = len(data) | 0x80000000
    data_off = struct.unpack("<I", data.ljust(4, b"\x00")[:4])[0]
    body = b"vk" + struct.pack("<HIIIHH", len(raw), data_len, data_off, kind, 0x0001, 0)
    body += raw
    return _hive_cell(body)


def _offset_cell(offsets: list[int]) -> bytes:
    return _hive_cell(b"".join(struct.pack("<I", offset) for offset in offsets))


def _lf_cell(entries: list[tuple[int, bytes]]) -> bytes:
    body = b"lf" + struct.pack("<H", len(entries))
    for offset, hint in entries:
        body += struct.pack("<I", offset) + hint[:4].ljust(4, b"\x00")
    return _hive_cell(body)


def _write_minimal_hive(path: Path) -> None:
    """A tiny valid hive: ROOT\\Build=26100 and ROOT\\Control\\Start=3."""

    build = _vk_cell(name="Build", kind=4, data=struct.pack("<I", 26100))
    start = _vk_cell(name="Start", kind=4, data=struct.pack("<I", 3))
    # Offsets are relative to the first hbin (file offset 0x1000). First cell is at 0x20.
    cursor = 0x20
    root_nk_off = cursor
    cursor += len(_nk_cell(name="ROOT", flags=0x2C, parent=0xFFFFFFFF, subkeys=1,
                           subkey_list=0, values=1, value_list=0))
    build_off = cursor
    cursor += len(build)
    root_values_off = cursor
    cursor += len(_offset_cell([build_off]))
    child_nk_off = cursor
    cursor += len(_nk_cell(name="Control", flags=0x20, parent=root_nk_off, subkeys=0,
                           subkey_list=0xFFFFFFFF, values=1, value_list=0))
    start_off = cursor
    cursor += len(start)
    child_values_off = cursor
    cursor += len(_offset_cell([start_off]))
    subkeys_off = cursor

    root_nk = _nk_cell(name="ROOT", flags=0x2C, parent=0xFFFFFFFF, subkeys=1,
                       subkey_list=subkeys_off, values=1, value_list=root_values_off)
    child_nk = _nk_cell(name="Control", flags=0x20, parent=root_nk_off, subkeys=0,
                        subkey_list=0xFFFFFFFF, values=1, value_list=child_values_off)
    subkeys = _lf_cell([(child_nk_off, b"CONT")])

    payload = (root_nk + build + _offset_cell([build_off]) + child_nk + start
               + _offset_cell([start_off]) + subkeys)
    hbin_header = b"hbin" + struct.pack("<II", 0, 4096) + b"\x00" * 20
    hbin = hbin_header + payload
    hbin += b"\x00" * (4096 - len(hbin))
    header = bytearray(4096)
    header[0:4] = b"regf"
    struct.pack_into("<I", header, 0x24, root_nk_off)
    struct.pack_into("<I", header, 0x28, 4096)
    path.write_bytes(bytes(header) + hbin)


def _b64(message: bytes) -> str:
    return base64.b64encode(message).decode("ascii")


class BurpExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_save_items_xml_becomes_one_row_per_request(self) -> None:
        request = b"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>"
        path = self.root / "history.xml"
        path.write_text(
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2024.10" exportTime="Thu Jan 01 00:00:00 UTC 2026">\n'
            "  <item>\n"
            "    <time>Thu Jan 01 00:00:00 UTC 2026</time>\n"
            "    <url><![CDATA[https://example.com/login]]></url>\n"
            "    <host ip=\"93.184.216.34\">example.com</host>\n"
            "    <port>443</port>\n"
            "    <protocol>https</protocol>\n"
            "    <method>GET</method>\n"
            "    <path><![CDATA[/login]]></path>\n"
            "    <extension>null</extension>\n"
            f'    <request base64="true">{_b64(request)}</request>\n'
            "    <status>200</status>\n"
            "    <responselength>44</responselength>\n"
            "    <mimetype>HTML</mimetype>\n"
            f'    <response base64="true">{_b64(response)}</response>\n'
            "    <comment></comment>\n"
            "  </item>\n"
            "</items>\n",
            encoding="utf-8",
        )
        self.assertEqual(readers.detect_format(path), "burp")
        info = dataset.load_any(path, name="http", home=self.root / "home")
        self.assertEqual(info.row_count, 1)
        _, rows, _ = dataset.run_query(
            info, "SELECT method, url, status, path, res_body FROM data", home=self.root / "home")
        self.assertEqual(rows[0][0], "GET")
        self.assertEqual(rows[0][1], "https://example.com/login")
        self.assertEqual(str(rows[0][2]), "200")
        self.assertEqual(rows[0][3], "/login")
        self.assertIn("<html>ok</html>", rows[0][4])
        _, numbered, _ = dataset.run_query(
            info, "SELECT item FROM data", home=self.root / "home")
        self.assertEqual(numbered[0][0], 1)

    def test_save_items_xml_numbers_each_history_row(self) -> None:
        request = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"
        path = self.root / "history.xml"
        path.write_text(
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2026.7.3">\n'
            f'  <item><url>https://a.test/one</url>'
            f'<request base64="true">{_b64(request)}</request></item>\n'
            f'  <item><url>https://a.test/two</url>'
            f'<request base64="true">{_b64(request)}</request></item>\n'
            "</items>\n",
            encoding="utf-8",
        )
        info = dataset.load_any(path, name="http", home=self.root / "home")
        _, rows, _ = dataset.run_query(
            info, "SELECT item, url FROM data ORDER BY item", home=self.root / "home")
        self.assertEqual([(row[0], row[1]) for row in rows], [
            (1, "https://a.test/one"),
            (2, "https://a.test/two"),
        ])

    def test_save_items_xml_with_doctype_decodes_form_and_cookies(self) -> None:
        body = (
            b"POST /login.aspx HTTP/1.1\r\n"
            b"Host: testaspnet.vulnweb.com\r\n"
            b"Cookie: ASP.NET_SessionId=abc123\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"\r\n"
            b"__VIEWSTATE=longnoise&tbUsername=ada%40example.com&tbPassword=s3cret%401&btnLogin=Login"
        )
        path = self.root / "history.xml"
        path.write_text(
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE items [\n"
            "<!ELEMENT items (item*)>\n"
            "<!ELEMENT item (url, host, request, response)>\n"
            "<!ELEMENT url (#PCDATA)>\n"
            "<!ELEMENT host (#PCDATA)>\n"
            "<!ATTLIST host ip CDATA \"\">\n"
            "<!ELEMENT request (#PCDATA)>\n"
            "<!ATTLIST request base64 (true|false) \"false\">\n"
            "<!ELEMENT response (#PCDATA)>\n"
            "<!ATTLIST response base64 (true|false) \"false\">\n"
            "]>\n"
            '<items burpVersion="2026.7.3">\n'
            "  <item>\n"
            "    <url><![CDATA[http://testaspnet.vulnweb.com/login.aspx]]></url>\n"
            "    <host ip=\"44.238.29.244\">testaspnet.vulnweb.com</host>\n"
            f'    <request base64="true"><![CDATA[{_b64(body)}]]></request>\n'
            '    <response base64="true"></response>\n'
            "  </item>\n"
            "</items>\n",
            encoding="utf-8",
        )
        records = list(readers.read_burp(path).records)
        self.assertEqual(len(records), 1)
        row = records[0]
        self.assertEqual(row["host_ip"], "44.238.29.244")
        self.assertIn("ASP.NET_SessionId=abc123", row["cookie"])
        self.assertIn("tbUsername=ada@example.com", row["form"])
        self.assertIn("tbPassword=s3cret@1", row["form"])
        self.assertNotIn("__VIEWSTATE", row["form"])
        self.assertNotIn("R0VUIC8", row["req_headers"])
        self.assertIn("POST /login.aspx", row["req_headers"])
        self.assertIn("email=ada@example.com", row["juicy"])
        self.assertIn("tbPassword=s3cret@1", row["juicy"])

    def test_http2_redirect_exposes_host_and_location_not_raw_cookies(self) -> None:
        request = (
            b"GET / HTTP/2\r\n"
            b"Host: mail.google.com\r\n"
            b"Cookie: NID=longsessionblob; SID=alsolong\r\n"
            b"\r\n"
        )
        response = (
            b"HTTP/2 302 Found\r\n"
            b"Location: https://accounts.google.com/ServiceLogin?service=mail\r\n"
            b"\r\n"
        )
        path = self.root / "gmail.txt"
        path.write_text(
            '<?xml version="1.0"?>\n'
            '<items burpVersion="2026.7.3">\n'
            "  <item>\n"
            "    <url><![CDATA[https://mail.google.com/]]></url>\n"
            "    <host ip=\"142.250.29.17\">mail.google.com</host>\n"
            f'    <request base64="true">{_b64(request)}</request>\n'
            "    <status>302</status>\n"
            f'    <response base64="true">{_b64(response)}</response>\n'
            "  </item>\n"
            "</items>\n",
            encoding="utf-8",
        )
        self.assertEqual(readers.detect_format(path), "burp")
        row = list(readers.read_burp(path).records)[0]
        self.assertEqual(row["host"], "mail.google.com")
        self.assertEqual(row["host_ip"], "142.250.29.17")
        self.assertIn("accounts.google.com", row["location"])
        self.assertIn("GET / HTTP/2", row["req_headers"])
        self.assertNotIn("R0VUIC8", row["req_headers"])
        self.assertIn("NID=", row["cookie"])
        self.assertNotIn("longsessionblob", row["juicy"])
        rendered = dataset.format_table(
            ["req_headers"], [(row["req_headers"],)], width=18, color=False)
        self.assertEqual(len(rendered.splitlines()), 3)

    def test_parser_json_dump_normalises_nested_request_response(self) -> None:
        path = self.root / "dump.json"
        path.write_text(json.dumps({
            "proxyHistory": [{
                "id": 44,
                "url": "https://api.example.com/v1/users",
                "method": "POST",
                "status": 201,
                "request": {
                    "headers": "POST /v1/users HTTP/1.1\r\nHost: api.example.com",
                    "body": '{"name":"ada"}',
                },
                "response": {
                    "headers": "HTTP/1.1 201 Created\r\nContent-Type: application/json",
                    "body": '{"id":1}',
                },
            }],
            "auditItems": [{
                "url": "https://api.example.com/v1/users",
                "name": "SQL injection",
                "severity": "High",
                "confidence": "Firm",
                "request": "POST /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
                "response": "HTTP/1.1 201 Created\r\n\r\n",
            }],
        }), encoding="utf-8")
        self.assertEqual(readers.detect_format(path), "burp")
        info = dataset.load_any(path, name="http", home=self.root / "home")
        self.assertEqual(info.row_count, 2)
        _, rows, _ = dataset.run_query(
            info, "SELECT item, source FROM data",
            home=self.root / "home")
        by_source = {row[1]: row[0] for row in rows}
        self.assertEqual(by_source["history"], 44)
        self.assertEqual(by_source["issue"], 2)

    def test_ndjson_parser_dump_loads(self) -> None:
        path = self.root / "history.jsonl"
        path.write_text(
            json.dumps({"url": "https://a.test/", "method": "GET",
                        "request": "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n",
                        "response": "HTTP/1.1 204 No Content\r\n\r\n"}) + "\n"
            + json.dumps({"url": "https://a.test/x", "method": "GET",
                          "request": "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n",
                          "response": "HTTP/1.1 404 Not Found\r\n\r\n"}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(readers.detect_format(path), "burp")
        info = dataset.load_any(path, name="http", home=self.root / "home")
        self.assertEqual(info.row_count, 2)

    def test_burp_project_file_explains_the_export_path(self) -> None:
        path = self.root / "project.burp"
        path.write_bytes(b"\x00BURP\x00" + b"\xff" * 40)
        with self.assertRaises(TacuError) as raised:
            readers.detect_format(path)
        message = str(raised.exception)
        self.assertIn("project file", message.casefold())
        self.assertIn("Save items", message)
        self.assertIn("ti data load", message)


if __name__ == "__main__":
    unittest.main()
