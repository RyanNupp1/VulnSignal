"""Tests for strategic vulnerability selection."""

import unittest
from datetime import date

from core.selection import (
    calculate_selection_score,
    select_findings,
)


class TestSelection(unittest.TestCase):

    def setUp(self):
        self.today = date(2026, 11, 1)

    def test_known_ransomware_adds_100_points(self):
        record = {"known_ransomware_use": "Known"}

        result = calculate_selection_score(
            record, today=self.today
        )

        self.assertEqual(result["selection_score"], 100)

    def test_recent_addition_adds_40_points(self):
        record = {"date_added": "2026-10-30"}

        result = calculate_selection_score(
            record, today=self.today
        )

        self.assertEqual(result["selection_score"], 40)

    def test_upcoming_deadline_adds_30_points(self):
        record = {"due_date": "2026-11-05"}

        result = calculate_selection_score(
            record, today=self.today
        )

        self.assertEqual(result["selection_score"], 30)

    def test_expired_deadline_adds_no_points(self):
        record = {"due_date": "2026-10-20"}

        result = calculate_selection_score(
            record, today=self.today
        )

        self.assertEqual(result["selection_score"], 0)

    def test_invalid_dates_do_not_crash(self):
        record = {
            "date_added": "invalid",
            "due_date": "invalid",
        }

        result = calculate_selection_score(
            record, today=self.today
        )

        self.assertEqual(result["selection_score"], 0)
        self.assertEqual(len(result["selection_reasons"]), 2)

    def test_selects_highest_scoring_findings(self):
        findings = [
            {
                "cve_id": "CVE-2020-0001",
                "known_ransomware_use": "Unknown",
                "triage_score": 2,
            },
            {
                "cve_id": "CVE-2026-0002",
                "known_ransomware_use": "Known",
                "triage_score": 5,
            },
        ]

        selected = select_findings(
            findings, limit=1, today=self.today
        )

        self.assertEqual(
            selected[0]["cve_id"], "CVE-2026-0002"
        )

    def test_ties_are_sorted_by_cve_id(self):
        findings = [
            {"cve_id": "CVE-2025-0002"},
            {"cve_id": "CVE-2025-0001"},
        ]

        selected = select_findings(
            findings, today=self.today
        )

        self.assertEqual(
            selected[0]["cve_id"], "CVE-2025-0001"
        )

    def test_selection_does_not_modify_input(self):
        findings = [{"cve_id": "CVE-2025-0001"}]
        original = [dict(item) for item in findings]

        select_findings(findings, today=self.today)

        self.assertEqual(findings, original)

    def test_negative_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            select_findings([], limit=-1)

    def test_boolean_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            select_findings([], limit=True)


if __name__ == "__main__":
    unittest.main()
