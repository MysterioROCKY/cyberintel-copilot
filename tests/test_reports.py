"""Offline tests for Version 3 page-aware report handling."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberintel.reports import chunk_text, safe_filename


class ReportTests(unittest.TestCase):
    def test_safe_filename_removes_path_components(self) -> None:
        self.assertEqual(safe_filename("../Report 2026!.pdf"), "Report_2026_.pdf")

    def test_chunk_text_keeps_short_text_in_one_chunk(self) -> None:
        self.assertEqual(chunk_text("short report"), ["short report"])

    def test_chunk_text_returns_overlapping_chunks(self) -> None:
        chunks = chunk_text("a" * 25, chunk_size=10, overlap=2)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0], "a" * 10)
        self.assertEqual(chunks[-1], "a" * 9)

    def test_chunk_text_ignores_whitespace_only_input(self) -> None:
        self.assertEqual(chunk_text(" \n\t "), [])
