import unittest

from reports.generator import generate_markdown_report, generate_customer_brief


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


    def test_report_contains_selection_metadata(self):
        records = [dict(self.records[0])]
        records[0]["selection_score"] = 145
        records[0]["selection_reasons"] = [
            "Known ransomware use",
            "Added to KEV within 90 days",
        ]

        report = generate_markdown_report(self.catalog, records)

        self.assertIn("Selection score: 145", report)
        self.assertIn("Known ransomware use", report)
        self.assertIn("Added to KEV within 90 days", report)

    def test_report_explains_not_selected_findings(self):
        records = [dict(self.records[1])]
        records[0]["nvd_enrichment"] = {
            "status": "not_selected",
            "reason": "Lower strategic selection score",
        }

        report = generate_markdown_report(self.catalog, records)

        self.assertIn("Lower strategic selection score", report)

    def test_report_contains_executive_summary(self):
        report = generate_markdown_report(self.catalog, self.records)

        self.assertIn("## Executive Summary", report)
        self.assertIn("Total vulnerabilities analyzed: 2", report)
        self.assertIn("Critical findings: 1", report)
        self.assertIn("High findings: 0", report)

    def test_report_counts_known_ransomware_findings(self):
        report = generate_markdown_report(self.catalog, self.records)

        self.assertIn("Findings associated with known ransomware use: 1", report)

    def test_unknown_ransomware_status_is_not_counted_as_known(self):
        records = [dict(self.records[1])]
        records[0]["known_ransomware_use"] = "Unknown"

        report = generate_markdown_report(self.catalog, records)

        self.assertIn("Findings associated with known ransomware use: 0", report)
    def test_report_contains_analyst_recommendations(self):
        report = generate_markdown_report(self.catalog, self.records)

        self.assertIn("## Analyst Recommendations", report)
        self.assertIn("Validate asset inventory", report)
        self.assertIn("Confirm exposure", report)
        self.assertIn("Prioritize remediation", report)
        self.assertIn("Verify remediation options", report)
        self.assertIn("Track remediation status", report)

    def test_recommendations_disclose_assessment_limitations(self):
        report = generate_markdown_report(self.catalog, self.records)

        self.assertIn(
            "does not independently verify asset presence",
            report,
        )
        self.assertIn("exposure, compromise, or remediation status", report)

    def test_recommendations_precede_methodology(self):
        report = generate_markdown_report(self.catalog, self.records)

        recommendations_position = report.index(
            "## Analyst Recommendations"
        )
        methodology_position = report.index(
            "## Methodology and Limitations"
        )

        self.assertLess(
            recommendations_position,
            methodology_position,
        )


class TestCustomerBrief(unittest.TestCase):
    def setUp(self):
        self.catalog = {
            "source": "CISA Known Exploited Vulnerabilities",
            "catalog_version": "2026.10.30",
        }
        self.records = [
            {
                "cve_id": "CVE-2025-99999",
                "priority": "LOW",
                "vendor": "Low Vendor",
                "product": "Low Product",
                "triage_score": 2,
            },
            {
                "cve_id": "CVE-2025-12345",
                "priority": "CRITICAL",
                "vendor": "Example Vendor",
                "product": "Example Product",
                "known_ransomware_use": "Known",
                "triage_score": 7,
                "date_added": "2025-01-01",
                "due_date": "2025-01-10",
                "source_url": "https://example.com/advisory",
            },
        ]

    def test_brief_contains_summary_and_scope_disclaimer(self):
        brief = generate_customer_brief(self.catalog, self.records)
        self.assertIn("Vulnerabilities analyzed: 2", brief)
        self.assertIn("Critical findings: 1", brief)
        self.assertIn("Known ransomware-associated findings: 1", brief)
        self.assertIn("Scope and Limitations", brief)
        self.assertIn("does not establish that your organization", brief)

    def test_critical_finding_ranks_before_low(self):
        brief = generate_customer_brief(self.catalog, self.records)
        self.assertLess(
            brief.index("CVE-2025-12345"),
            brief.index("CVE-2025-99999"),
        )

    def test_known_ransomware_breaks_priority_tie(self):
        records = [
            {"cve_id": "CVE-2025-11111", "priority": "HIGH"},
            {
                "cve_id": "CVE-2025-22222",
                "priority": "HIGH",
                "known_ransomware_use": "Known",
            },
        ]
        brief = generate_customer_brief(self.catalog, records)
        self.assertLess(
            brief.index("CVE-2025-22222"),
            brief.index("CVE-2025-11111"),
        )

    def test_limit_restricts_selected_findings(self):
        brief = generate_customer_brief(
            self.catalog, self.records, limit=1
        )
        self.assertIn("CVE-2025-12345", brief)
        self.assertNotIn("CVE-2025-99999", brief)

    def test_empty_records_are_handled(self):
        brief = generate_customer_brief(self.catalog, [])
        self.assertIn("Vulnerabilities analyzed: 0", brief)
        self.assertIn("No vulnerabilities were available", brief)

    def test_invalid_limits_are_rejected(self):
        for limit in (-1, 1.5, True, "10"):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    generate_customer_brief(
                        self.catalog, self.records, limit=limit
                    )
if __name__ == "__main__":
    unittest.main()
