import unittest

from reports.generator import generate_markdown_report


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.catalog = {
            "source": "CISA Known Exploited Vulnerabilities",
            "catalog_version": "2026.10.30",
            "record_count": 2,
        }

        self.records = [
            {
                "cve_id": "CVE-2025-12345",
                "priority": "CRITICAL",
                "vendor": "Example Vendor",
                "product": "Example Product",
                "vulnerability_name": "Example vulnerability",
                "date_added": "2025-01-01",
                "due_date": "2025-01-10",
                "known_ransomware_use": "Known",
                "triage_score": 7,
                "analysis_reasons": [
                    "Listed in CISA KEV",
                    "Known ransomware campaign use",
                ],
                "source_url": "https://example.com/advisory",
            },
            {
                "cve_id": "CVE-2025-99999",
                "priority": "LOW",
                "vendor": "Another Vendor",
                "product": "Another Product",
                "triage_score": 2,
                "analysis_reasons": ["Listed in CISA KEV"],
                "source_url": "https://example.com/other",
            },
        ]

    def test_report_contains_title_and_metadata(self):
        report = generate_markdown_report(self.catalog, self.records)
        self.assertIn("# Cybersecurity Intelligence Report", report)
        self.assertIn("CISA Known Exploited Vulnerabilities", report)
        self.assertIn("2026.10.30", report)
        self.assertIn("Records collected: 2", report)

    def test_report_counts_priorities(self):
        report = generate_markdown_report(self.catalog, self.records)
        self.assertIn("- CRITICAL: 1", report)
        self.assertIn("- LOW: 1", report)
        self.assertIn("- HIGH: 0", report)

    def test_report_contains_vulnerability_details(self):
        report = generate_markdown_report(self.catalog, self.records)
        self.assertIn("CVE-2025-12345", report)
        self.assertIn("Example Vendor", report)
        self.assertIn("Example Product", report)
        self.assertIn("Known ransomware use: Known", report)

    def test_report_contains_reasons_and_source_links(self):
        report = generate_markdown_report(self.catalog, self.records)
        self.assertIn("Known ransomware campaign use", report)
        self.assertIn("https://example.com/advisory", report)

    def test_report_explains_methodology_limitations(self):
        report = generate_markdown_report(self.catalog, self.records)
        self.assertIn("not CVSS scores", report)
        self.assertIn("organization-specific risk ratings", report)


    def test_report_contains_nvd_enrichment(self):
        enriched_records = [dict(self.records[0])]
        enriched_records[0]["nvd_enrichment"] = {
            "status": "retrieved",
            "data": {
                "nvd_found": True,
                "cvss": {
                    "version": "3.1",
                    "base_score": 9.8,
                    "base_severity": "CRITICAL",
                    "vector": "CVSS:3.1/AV:N/AC:L",
                },
                "weaknesses": ["CWE-502"],
                "description": "Example NVD description.",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-12345",
            },
        }

        report = generate_markdown_report(self.catalog, enriched_records)

        self.assertIn("NVD Enrichment", report)
        self.assertIn("CVSS base score: 9.8", report)
        self.assertIn("CVSS severity: CRITICAL", report)
        self.assertIn("CWE-502", report)
        self.assertIn("Example NVD description.", report)
        self.assertIn("CISA triage score: 7", report)


if __name__ == "__main__":
    unittest.main()
