"""Deterministic preliminary triage of CISA KEV records."""

from datetime import date


def analyze_vulnerability(record, today=None):
    today = today or date.today()

    score = 2
    reasons = [
        "Listed in CISA Known Exploited Vulnerabilities catalog"
    ]

    ransomware_use = str(
        record.get("known_ransomware_use", "Unknown")
    ).strip().lower()

    if ransomware_use == "known":
        score += 3
        reasons.append("Known ransomware campaign use")

    due_date = record.get("due_date")

    if due_date:
        try:
            deadline = date.fromisoformat(due_date)
        except (TypeError, ValueError):
            reasons.append("Due date could not be interpreted")
        else:
            days_remaining = (deadline - today).days

            if days_remaining < 0:
                reasons.append(
                    "Historical CISA remediation deadline has passed"
                )
            elif days_remaining <= 7:
                score += 1
                reasons.append(
                    "CISA remediation deadline is within 7 days"
                )

    if score >= 7:
        priority = "CRITICAL"
    elif score >= 5:
        priority = "HIGH"
    elif score >= 3:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        **record,
        "triage_score": score,
        "priority": priority,
        "analysis_reasons": reasons,
        "assessment_type": "Rule-based preliminary triage",
    }


def analyze_catalog(catalog, today=None):
    results = [
        analyze_vulnerability(record, today=today)
        for record in catalog.get("vulnerabilities", [])
    ]

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    return sorted(
        results,
        key=lambda item: (
            priority_order[item["priority"]],
            -item["triage_score"],
            item.get("cve_id", ""),
        ),
    )
