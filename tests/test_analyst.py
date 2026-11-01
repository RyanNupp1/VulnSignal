import unittest
from datetime import date

from core.analyst import analyze_catalog, analyze_vulnerability


class TestVulnerabilityAnalyst(unittest.TestCase):

    def setUp(self):
        self.record = {
            "cve_id": "CVE-2025-12345",
            "vendor": "Example Vendor",
            "product": "Example Product",
            "due_date": "2025-02-15",
            "known_ransomware_use": "Unknown",
        }

    def test_base_kev_priority(self):
        result = analyze_vulnerability(
            self.record,
            today=date(2025, 1, 1),
        )
        self.assertEqual(result["triage_score"], 2)
        self.assertEqual(result["priority"], "LOW")

    def test_known_ransomware_use_increases_score(self):
        record = {
            **self.record,
            "known_ransomware_use": "Known",
        }
        result = analyze_vulnerability(
            record,
            today=date(2025, 1, 1),
        )
        self.assertEqual(result["triage_score"], 5)
        self.assertEqual(result["priority"], "HIGH")

    def test_overdue_deadline_does_not_increase_score(self):
        result = analyze_vulnerability(
            self.record,
            today=date(2025, 3, 1),
        )
        self.assertEqual(result["triage_score"], 2)
        self.assertEqual(result["priority"], "LOW")
        self.assertTrue(
            any(
                "Historical CISA remediation deadline has passed" in reason
                for reason in result["analysis_reasons"]
            )
        )

    def test_ransomware_and_overdue_deadline(self):
        record = {
            **self.record,
            "known_ransomware_use": "Known",
            "due_date": "2024-12-01",
        }
        result = analyze_vulnerability(
            record,
            today=date(2025, 1, 1),
        )
        self.assertEqual(result["triage_score"], 5)
        self.assertEqual(result["priority"], "HIGH")

    def test_catalog_is_sorted_by_priority(self):
        catalog = {
            "vulnerabilities": [
                self.record,
                {
                    **self.record,
                    "cve_id": "CVE-2025-99999",
                    "known_ransomware_use": "Known",
                    "due_date": "2024-12-01",
                },
            ]
        }
        results = analyze_catalog(
            catalog,
            today=date(2025, 1, 1),
        )
        self.assertEqual(results[0]["priority"], "HIGH")
        self.assertEqual(results[1]["priority"], "LOW")

    def test_invalid_due_date_does_not_crash(self):
        record = {
            **self.record,
            "due_date": "invalid-date",
        }
        result = analyze_vulnerability(
            record,
            today=date(2025, 1, 1),
        )
        self.assertEqual(result["triage_score"], 2)
        self.assertTrue(
            any(
                "could not be interpreted" in reason
                for reason in result["analysis_reasons"]
            )
        )


if __name__ == "__main__":
    unittest.main()
