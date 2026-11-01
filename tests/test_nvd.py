import unittest
from unittest.mock import Mock

import requests

from collectors.nvd import (
    NVDCollectorError,
    fetch_cve_details,
)


class TestNVDCollector(unittest.TestCase):

    def make_response(self, data, status_code=200):
        response = Mock()
        response.status_code = status_code
        response.json.return_value = data
        response.raise_for_status.return_value = None
        return response

    def test_extracts_cve_details_and_cvss(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2025-12345",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Example vulnerability."
                            }
                        ],
                        "weaknesses": [
                            {
                                "description": [
                                    {
                                        "lang": "en",
                                        "value": "CWE-79"
                                    }
                                ]
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/example"
                                    }
                                }
                            ]
                        },
                        "published": "2025-01-01T00:00:00.000",
                        "lastModified": "2025-01-02T00:00:00.000"
                    }
                }
            ]
        }

        session = Mock()
        session.get.return_value = self.make_response(data)

        result = fetch_cve_details(
            "CVE-2025-12345",
            session=session
        )

        self.assertTrue(result["nvd_found"])
        self.assertEqual(result["cve_id"], "CVE-2025-12345")
        self.assertEqual(
            result["description"],
            "Example vulnerability."
        )
        self.assertEqual(result["weaknesses"], ["CWE-79"])
        self.assertEqual(result["cvss"]["base_score"], 9.8)
        self.assertEqual(result["cvss"]["base_severity"], "CRITICAL")

    def test_handles_missing_cve(self):
        session = Mock()
        session.get.return_value = self.make_response({
            "vulnerabilities": []
        })

        result = fetch_cve_details(
            "CVE-2025-12345",
            session=session
        )

        self.assertFalse(result["nvd_found"])
        self.assertEqual(result["cve_id"], "CVE-2025-12345")

    def test_rejects_invalid_cve_identifier(self):
        with self.assertRaises(ValueError):
            fetch_cve_details("not-a-cve")

    def test_handles_http_error(self):
        session = Mock()
        response = Mock()
        response.raise_for_status.side_effect = (
            requests.HTTPError("HTTP 500")
        )
        session.get.return_value = response

        with self.assertRaises(NVDCollectorError):
            fetch_cve_details(
                "CVE-2025-12345",
                session=session
            )

    def test_handles_invalid_json(self):
        session = Mock()
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError("Invalid JSON")
        session.get.return_value = response

        with self.assertRaises(NVDCollectorError):
            fetch_cve_details(
                "CVE-2025-12345",
                session=session
            )

    def test_rejects_malformed_response(self):
        session = Mock()
        session.get.return_value = self.make_response({
            "unexpected": []
        })

        with self.assertRaises(NVDCollectorError):
            fetch_cve_details(
                "CVE-2025-12345",
                session=session
            )


    def test_rejects_malformed_vulnerability_entry(self):
        session = Mock()
        session.get.return_value = self.make_response({
            "vulnerabilities": ["not-a-dictionary"]
        })

        with self.assertRaises(NVDCollectorError):
            fetch_cve_details(
                "CVE-2025-12345",
                session=session
            )

    def test_rejects_malformed_cve_object(self):
        session = Mock()
        session.get.return_value = self.make_response({
            "vulnerabilities": [{"cve": None}]
        })

        with self.assertRaises(NVDCollectorError):
            fetch_cve_details(
                "CVE-2025-12345",
                session=session
            )

    def test_handles_malformed_optional_fields(self):
        session = Mock()
        session.get.return_value = self.make_response({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-12345",
                    "descriptions": "invalid",
                    "weaknesses": None,
                    "metrics": "invalid"
                }
            }]
        })

        result = fetch_cve_details(
            "CVE-2025-12345",
            session=session
        )

        self.assertTrue(result["nvd_found"])
        self.assertIsNone(result["description"])
        self.assertEqual(result["weaknesses"], [])
        self.assertIsNone(result["cvss"])

    def test_rejects_malformed_cve_identifier(self):
        with self.assertRaises(ValueError):
            fetch_cve_details("CVE-2025-ABC")
if __name__ == "__main__":
    unittest.main()
