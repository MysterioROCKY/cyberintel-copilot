"""Offline tests for the Version 2 asset-prioritization rules."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberintel.assets import Asset, candidate_match_score, parse_inventory, prioritize_asset


FORTIOS_RECORD = {"cveID": "CVE-2022-40684", "vendorProject": "Fortinet", "product": "FortiOS and FortiProxy", "dateAdded": "2022-10-11"}


class AssetTests(unittest.TestCase):
    def test_parse_inventory_skips_header_and_normalizes_exposure(self) -> None:
        assets, errors = parse_inventory("Product | Version | Internet exposed\nFortinet FortiOS | 7.0 | yes")
        self.assertFalse(errors)
        self.assertEqual(assets, [Asset("Fortinet FortiOS", "7.0", "yes")])

    def test_parse_inventory_reports_invalid_exposure(self) -> None:
        _, errors = parse_inventory("Fortinet FortiOS | 7.0 | maybe")
        self.assertEqual(len(errors), 1)

    def test_product_name_match_scores_highly(self) -> None:
        self.assertEqual(candidate_match_score("Fortinet FortiOS", FORTIOS_RECORD), 100)

    def test_unrelated_product_does_not_match(self) -> None:
        self.assertEqual(candidate_match_score("Mozilla Firefox", FORTIOS_RECORD), 0)

    def test_internet_facing_kev_candidate_is_patch_now(self) -> None:
        finding = prioritize_asset(Asset("Fortinet FortiOS", "7.0", "yes"), [FORTIOS_RECORD])
        self.assertEqual(finding.priority, "Patch now")

    def test_unknown_exposure_kev_candidate_is_review_urgently(self) -> None:
        finding = prioritize_asset(Asset("Fortinet FortiOS", "7.0", "unknown"), [FORTIOS_RECORD])
        self.assertEqual(finding.priority, "Review urgently")

    def test_no_candidate_is_monitor_not_safe(self) -> None:
        finding = prioritize_asset(Asset("Mozilla Firefox", "1", "no"), [FORTIOS_RECORD])
        self.assertEqual(finding.priority, "Monitor")
        self.assertIn("not proof", finding.reason)
