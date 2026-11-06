import unittest

from core.assessment import assess_inventory


class TestInventoryAssessment(unittest.TestCase):
    def setUp(self):
        self.assets = [{
            "hostname": "server-01",
            "part": "a",
            "vendor": "example",
            "product": "widget",
            "version": "2.1",
        }]

        self.configuration = [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "criteria": "cpe:2.3:a:example:widget:2.1:*:*:*:*:*:*:*",
                    "vulnerable": True,
                }],
            }],
        }]

        self.finding = {
            "cve_id": "CVE-2026-12345",
            "priority": "HIGH",
            "triage_score": 5,
            "nvd_enrichment": {
                "status": "retrieved",
                "data": {
                    "configurations": self.configuration,
                    "source": "NIST National Vulnerability Database",
                    "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
                },
            },
        }

    def test_vulnerable_configuration_is_affected(self):
        results = assess_inventory(
            self.assets, [self.finding], inventory_complete=True
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["exposure_status"], "affected")
        self.assertTrue(results[0]["vulnerable_match"])

    def test_environmental_only_match_is_indeterminate(self):
        finding = {
            **self.finding,
            "nvd_enrichment": {
                **self.finding["nvd_enrichment"],
                "data": {
                    "configurations": [{
                        "nodes": [{
                            "operator": "OR",
                            "cpeMatch": [{
                                "criteria": (
                                    "cpe:2.3:a:example:widget:2.1:"
                                    "*:*:*:*:*:*:*"
                                ),
                                "vulnerable": False,
                            }],
                        }],
                    }],
                },
            },
        }

        results = assess_inventory(
            self.assets, [finding], inventory_complete=True
        )

        self.assertEqual(results[0]["exposure_status"], "indeterminate")
        self.assertFalse(results[0]["vulnerable_match"])

    def test_no_match_in_complete_inventory_is_not_affected(self):
        finding = {
            **self.finding,
            "nvd_enrichment": {
                **self.finding["nvd_enrichment"],
                "data": {
                    "configurations": [{
                        "nodes": [{
                            "operator": "OR",
                            "cpeMatch": [{
                                "criteria": (
                                    "cpe:2.3:a:other:product:1.0:"
                                    "*:*:*:*:*:*:*"
                                ),
                                "vulnerable": True,
                            }],
                        }],
                    }],
                },
            },
        }

        results = assess_inventory(
            self.assets, [finding], inventory_complete=True
        )

        self.assertEqual(results[0]["exposure_status"], "not_affected")

    def test_no_match_in_incomplete_inventory_is_indeterminate(self):
        finding = {
            **self.finding,
            "nvd_enrichment": {
                **self.finding["nvd_enrichment"],
                "data": {
                    "configurations": [{
                        "nodes": [{
                            "operator": "OR",
                            "cpeMatch": [{
                                "criteria": (
                                    "cpe:2.3:a:other:product:1.0:"
                                    "*:*:*:*:*:*:*"
                                ),
                                "vulnerable": True,
                            }],
                        }],
                    }],
                },
            },
        }

        results = assess_inventory(
            self.assets, [finding], inventory_complete=False
        )

        self.assertEqual(results[0]["exposure_status"], "indeterminate")

    def test_missing_nvd_enrichment_is_indeterminate(self):
        finding = {
            "cve_id": "CVE-2026-12345",
            "priority": "HIGH",
            "nvd_enrichment": {"status": "not_selected"},
        }

        results = assess_inventory(
            self.assets, [finding], inventory_complete=True
        )

        self.assertEqual(results[0]["exposure_status"], "indeterminate")
        self.assertEqual(results[0]["nvd_status"], "not_selected")

    def test_multiple_hosts_receive_separate_assessments(self):
        assets = self.assets + [{
            **self.assets[0],
            "hostname": "server-02",
        }]

        results = assess_inventory(
            assets, [self.finding], inventory_complete=True
        )

        self.assertEqual(len(results), 2)
        self.assertEqual(
            {item["hostname"] for item in results},
            {"server-01", "server-02"},
        )

    def test_preserves_priority_and_source_evidence(self):
        results = assess_inventory(
            self.assets, [self.finding], inventory_complete=True
        )

        self.assertEqual(results[0]["priority"], "HIGH")
        self.assertEqual(results[0]["triage_score"], 5)
        self.assertEqual(
            results[0]["source_url"],
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        )


    def test_invalid_finding_rejected_with_empty_inventory(self):
        with self.assertRaisesRegex(ValueError, "Each finding"):
            assess_inventory([], [None], inventory_complete=True)


if __name__ == "__main__":
    unittest.main()
