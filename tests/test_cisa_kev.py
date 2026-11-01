import unittest
from unittest.mock import Mock

import requests

from collectors.cisa_kev import (
    CISACollectorError,
    CISA_KEV_URL,
    fetch_kev_catalog,
)


def sample_vulnerability():
    return {
        "cveID": "CVE-2025-12345",
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": "Example vulnerability",
        "dateAdded": "2025-01-15",
        "shortDescription": "A sample security vulnerability.",
        "requiredAction": "Apply the vendor's security update.",
        "dueDate": "2025-02-15",
        "knownRansomwareCampaignUse": "Unknown",
    }


class TestCISACollector(unittest.TestCase):

    def setUp(self):
        self.response = Mock()
        self.response.json.return_value = {
            "catalogVersion": "test-version",
            "dateReleased": "2025-01-15",
            "vulnerabilities": [sample_vulnerability()],
        }

        self.session = Mock()
        self.session.get.return_value = self.response

    def test_successful_collection(self):
        result = fetch_kev_catalog(self.session)

        self.assertEqual(result["record_count"], 1)
        self.assertEqual(
            result["vulnerabilities"][0]["cve_id"],
            "CVE-2025-12345",
        )

    def test_uses_expected_url_and_timeout(self):
        fetch_kev_catalog(self.session)

        self.session.get.assert_called_once_with(
            CISA_KEV_URL,
            timeout=20,
        )

    def test_normalizes_source_metadata(self):
        result = fetch_kev_catalog(self.session)
        record = result["vulnerabilities"][0]

        self.assertEqual(record["source"], "CISA Known Exploited Vulnerabilities")
        self.assertEqual(record["vendor"], "Example Vendor")
        self.assertEqual(record["product"], "Example Product")
        self.assertIn("retrieved_at", result)

    def test_http_error_is_reported(self):
        self.session.get.side_effect = requests.Timeout("Timed out")

        with self.assertRaises(CISACollectorError):
            fetch_kev_catalog(self.session)

    def test_invalid_json_is_reported(self):
        self.response.json.side_effect = ValueError("Invalid JSON")

        with self.assertRaises(CISACollectorError):
            fetch_kev_catalog(self.session)

    def test_missing_vulnerability_list_is_rejected(self):
        self.response.json.return_value = {"catalogVersion": "test"}

        with self.assertRaises(CISACollectorError):
            fetch_kev_catalog(self.session)

    def test_malformed_records_are_skipped(self):
        self.response.json.return_value = {
            "vulnerabilities": [
                sample_vulnerability(),
                {"cveID": "CVE-INCOMPLETE"},
                "invalid record",
            ]
        }

        result = fetch_kev_catalog(self.session)

        self.assertEqual(result["record_count"], 1)


if __name__ == "__main__":
    unittest.main()
