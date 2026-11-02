"""Strategic selection of CISA KEV findings for NVD enrichment."""

from datetime import date


def calculate_selection_score(record, today=None):
    """Calculate a transparent selection score for one finding."""
    today = today or date.today()
    score = 0
    reasons = []

    ransomware = str(
        record.get("known_ransomware_use", "Unknown")
    ).strip().lower()

    if ransomware == "known":
        score += 100
        reasons.append("Known ransomware use")

    date_added = record.get("date_added")

    if date_added:
        try:
            added = date.fromisoformat(date_added)
            age_days = (today - added).days

            if 0 <= age_days <= 30:
                score += 40
                reasons.append("Added to KEV within 30 days")
            elif 30 < age_days <= 90:
                score += 20
                reasons.append("Added to KEV within 90 days")
        except (TypeError, ValueError):
            reasons.append("Invalid KEV addition date")

    due_date = record.get("due_date")

    if due_date:
        try:
            deadline = date.fromisoformat(due_date)
            days_remaining = (deadline - today).days

            if 0 <= days_remaining <= 7:
                score += 30
                reasons.append("CISA due date within 7 days")
            elif 7 < days_remaining <= 30:
                score += 15
                reasons.append("CISA due date within 30 days")
        except (TypeError, ValueError):
            reasons.append("Invalid CISA due date")

    triage_score = record.get("triage_score", 0)

    if isinstance(triage_score, (int, float)):
        score += triage_score * 5

    return {
        "selection_score": score,
        "selection_reasons": reasons,
    }


def select_findings(findings, limit=5, today=None):
    """Return the highest-ranked findings without modifying the input."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError("limit must be a non-negative integer")

    ranked = []

    for finding in findings:
        analysis = calculate_selection_score(finding, today=today)
        ranked.append({**finding, **analysis})

    ranked.sort(
        key=lambda item: (
            -item["selection_score"],
            item.get("cve_id", ""),
        )
    )

    return ranked[:limit]
