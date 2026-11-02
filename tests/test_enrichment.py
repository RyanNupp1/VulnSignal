"""Tests for cached NVD enrichment."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.enrichment import enrich_findings


class TestEnrichment(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_path = Path(self.temp_dir.name) / "nvd_cache.json"

        self.findings = [
            {
                "cve_id": "CVE-2021-44228",
                "priority": "CRITICAL",
                "triage_score": 7,
            },
            {
                "cve_id": "CVE-2023-0001",
                "priority": "HIGH",
                "triage_score": 5,
            },
        ]

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("core.enrichment.fetch_cve_details")
    def test_retrieves_and_caches_nvd_details(self, mock_fetch):
        mock_fetch.return_value = {
            "cve_id": "CVE-2021-44228",
            "nvd_found": True,
            "cvss": {"base_score": 10.0},
        }

        results = enrich_findings(
            self.findings,
            cache_path=self.cache_path,
        )

        self.assertEqual(
            results[0]["nvd_enrichment"]["status"],
            "retrieved",
        )
        self.assertEqual(results[0]["priority"], "CRITICAL")
        self.assertEqual(results[0]["triage_score"], 7)
        self.assertTrue(self.cache_path.exists())

        saved = json.loads(self.cache_path.read_text())
        self.assertIn("CVE-2021-44228", saved)

    @patch("core.enrichment.fetch_cve_details")
    def test_uses_cache_without_requesting_again(self, mock_fetch):
        self.cache_path.write_text(
            json.dumps({
                "CVE-2021-44228": {
                    "cve_id": "CVE-2021-44228",
                    "nvd_found": True,
                }
            })
        )

        results = enrich_findings(
            self.findings,
            limit=1,
            cache_path=self.cache_path,
        )

        mock_fetch.assert_not_called()
        self.assertEqual(
            results[0]["nvd_enrichment"]["status"],
            "cached",
        )

    @patch("core.enrichment.fetch_cve_details")
    def test_lookup_failure_does_not_stop_processing(self, mock_fetch):
        mock_fetch.side_effect = [
            ValueError("Invalid CVE"),
            {
                "cve_id": "CVE-2023-0001",
                "nvd_found": True,
            },
        ]

        results = enrich_findings(
            self.findings,
            cache_path=self.cache_path,
        )

        self.assertEqual(
            results[0]["nvd_enrichment"]["status"],
            "failed",
        )
        self.assertEqual(
            results[1]["nvd_enrichment"]["status"],
            "retrieved",
        )

    @patch("core.enrichment.fetch_cve_details")
    def test_respects_enrichment_limit(self, mock_fetch):
        mock_fetch.return_value = {
            "cve_id": "CVE-2021-44228",
            "nvd_found": True,
        }

        results = enrich_findings(
            self.findings,
            limit=1,
            cache_path=self.cache_path,
        )

        mock_fetch.assert_called_once()
        self.assertEqual(
            results[1]["nvd_enrichment"]["status"],
            "not_selected",
        )
        self.assertEqual(results[1]["priority"], "HIGH")

    def test_invalid_cve_is_not_requested(self):
        findings = [{"cve_id": None, "priority": "LOW"}]

        with patch("core.enrichment.fetch_cve_details") as mock_fetch:
            results = enrich_findings(
                findings,
                cache_path=self.cache_path,
            )

        mock_fetch.assert_not_called()
        self.assertEqual(
            results[0]["nvd_enrichment"]["status"],
            "invalid_cve",
        )



    @patch("core.enrichment.fetch_cve_details")
    def test_strategic_selection_prioritizes_recent_ransomware(self, mock_fetch):
        findings = [
            {
                "cve_id": "CVE-2020-0001",
                "date_added": "2020-01-01",
                "known_ransomware_use": "Unknown",
                "triage_score": 5,
            },
            {
                "cve_id": "CVE-2026-0001",
                "date_added": "2026-10-30",
                "known_ransomware_use": "Known",
                "triage_score": 5,
            },
        ]
        mock_fetch.side_effect = [
            {"cve_id": "CVE-2026-0001", "nvd_found": True}
        ]

        results = enrich_findings(
            findings,
            limit=1,
            cache_path=self.cache_path,
        )

        self.assertEqual(
            results[0]["nvd_enrichment"]["status"],
            "not_selected",
        )
        self.assertEqual(
            results[1]["nvd_enrichment"]["status"],
            "retrieved",
        )
        mock_fetch.assert_called_once_with(
            "CVE-2026-0001",
            session=None,
        )

    def test_strategic_selection_preserves_original_order(self):
        findings = [
            {
                "cve_id": "CVE-2020-0001",
                "date_added": "2020-01-01",
                "known_ransomware_use": "Unknown",
            },
            {
                "cve_id": "CVE-2026-0001",
                "date_added": "2026-10-30",
                "known_ransomware_use": "Known",
            },
        ]

        results = enrich_findings(
            findings,
            limit=0,
            cache_path=self.cache_path,
        )

        self.assertEqual(
            [item["cve_id"] for item in results],
            ["CVE-2020-0001", "CVE-2026-0001"],
        )

    def test_selection_metadata_is_attached(self):
        findings = [
            {
                "cve_id": "CVE-2026-0001",
                "date_added": "2026-10-30",
                "known_ransomware_use": "Known",
            }
        ]

        results = enrich_findings(
            findings,
            limit=0,
            cache_path=self.cache_path,
        )

        self.assertGreater(results[0]["selection_score"], 0)
        self.assertIn(
            "Known ransomware use",
            results[0]["selection_reasons"],
        )


if __name__ == "__main__":
    unittest.main()
