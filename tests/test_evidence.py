"""Fast offline tests for evidence-status wording."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberintel.evidence import cisa_status, nvd_status


class EvidenceStatusTests(unittest.TestCase):
    def test_nvd_not_requested_without_cve(self) -> None:
        label, _ = nvd_status(None, False, None)
        self.assertEqual(label, "Not requested")

    def test_nvd_record_found(self) -> None:
        label, detail = nvd_status("CVE-2022-40684", True, None)
        self.assertEqual(label, "Record found")
        self.assertIn("official", detail.lower())

    def test_nvd_unavailable_is_distinct_from_missing(self) -> None:
        label, detail = nvd_status("CVE-2022-40684", False, "timeout")
        self.assertEqual(label, "Unavailable")
        self.assertIn("CISA", detail)

    def test_nvd_missing_record(self) -> None:
        label, detail = nvd_status("CVE-2099-99999", False, None)
        self.assertEqual(label, "No record found")
        self.assertIn("CVE-2099-99999", detail)

    def test_cisa_exact_match(self) -> None:
        label, detail = cisa_status("CVE-2022-40684", 1)
        self.assertEqual(label, "Listed in KEV")
        self.assertIn("CISA", detail)

    def test_cisa_no_match_does_not_claim_safety(self) -> None:
        label, detail = cisa_status("CVE-2099-99999", 0)
        self.assertEqual(label, "Not listed in KEV")
        self.assertIn("does not prove", detail)

    def test_cisa_semantic_search_label(self) -> None:
        label, _ = cisa_status(None, 3)
        self.assertEqual(label, "Semantic search")
