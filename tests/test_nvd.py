"""Fast offline tests for NVD parsing and CVE-ID validation."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberintel.nvd import _cvss_summary, extract_cve_id, nvd_record_to_document


SAMPLE_RECORD = {
    "id": "CVE-2024-12345",
    "vulnStatus": "Analyzed",
    "published": "2024-01-01T00:00:00.000",
    "lastModified": "2024-01-02T00:00:00.000",
    "descriptions": [{"lang": "en", "value": "Example vulnerability description."}],
    "metrics": {
        "cvssMetricV31": [
            {"cvssData": {"version": "3.1", "baseScore": 8.8, "baseSeverity": "HIGH"}}
        ]
    },
    "references": [{"url": "https://example.com/advisory"}],
}


class NvdTests(unittest.TestCase):
    def test_extract_cve_normalizes_case(self) -> None:
        self.assertEqual(extract_cve_id("Tell me about cve-2024-12345"), "CVE-2024-12345")

    def test_extract_cve_returns_none_when_absent(self) -> None:
        self.assertIsNone(extract_cve_id("Explain patch management"))

    def test_cvss_summary_uses_latest_available_score(self) -> None:
        self.assertEqual(_cvss_summary(SAMPLE_RECORD["metrics"]), "CVSS v3.1: 8.8 (HIGH)")

    def test_nvd_document_contains_source_and_description(self) -> None:
        document, metadata = nvd_record_to_document(SAMPLE_RECORD)
        self.assertIn("Example vulnerability description.", document)
        self.assertIn("nvd.nist.gov", metadata["source_url"])
