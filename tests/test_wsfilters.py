"""Local Wireshark display-filter catalog lookup."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import wsfilters


class FilterCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.catalog = self.root / "filters.csv"
        self.catalog.write_text(
            "RecordType,FieldName,FilterString,DataType,Description\n"
            "F,Name,dns.qry.name,FT_STRING,dns\n"
            "F,Name Length,dns.qry.name.len,FT_UINT16,dns\n"
            "F,Host,http.host,FT_STRING,http\n"
            "F,Server Name,tls.handshake.extensions_server_name,FT_STRING,tls\n"
            "F,Destination Port,tcp.dstport,FT_UINT16,tcp\n",
            encoding="utf-8",
        )
        self.cache = self.root / "cache"

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_wants_filter_help_is_narrow(self) -> None:
        self.assertTrue(wsfilters.wants_filter_help("what wireshark filter shows dns"))
        self.assertTrue(wsfilters.wants_filter_help("give me a display filter for https"))
        self.assertFalse(wsfilters.wants_filter_help("tell me the communication with acme.example"))

    def test_lookup_matches_protocol_tokens_not_hostnames(self) -> None:
        rows = wsfilters.lookup_filters(
            "wireshark filter for dns queries to acme.example",
            catalog=self.catalog, cache_dir=self.cache,
        )
        names = [item.filter_string for item in rows]
        self.assertIn("dns.qry.name", names)
        self.assertTrue(all("acme" not in name for name in names))

    def test_sni_alias_finds_the_tls_field(self) -> None:
        rows = wsfilters.lookup_filters(
            "display filter for sni",
            catalog=self.catalog, cache_dir=self.cache,
        )
        self.assertEqual(rows[0].filter_string, "tls.handshake.extensions_server_name")

    def test_catalog_is_found_next_to_a_capture_not_only_in_cwd(self) -> None:
        capture_dir = self.root / "caps"
        capture_dir.mkdir()
        nowhere = self.root / "empty"
        nowhere.mkdir()
        sheet = self.root / "utils" / "wireshark_filters.csv"
        sheet.parent.mkdir()
        sheet.write_text(self.catalog.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertIsNone(wsfilters.catalog_path(
            cwd=capture_dir, workspace=nowhere,
            extra_roots=[capture_dir / "sample.pcapng"]))
        found = wsfilters.catalog_path(
            cwd=capture_dir, workspace=nowhere,
            extra_roots=[self.root / "sample.pcapng"])
        self.assertEqual(found.resolve(), sheet.resolve())

    def test_missing_catalog_is_empty(self) -> None:
        self.assertEqual(
            wsfilters.lookup_filters("dns filter", catalog=self.root / "nope.csv"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
