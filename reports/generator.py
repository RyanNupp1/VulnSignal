"""Generate Markdown reports from analyzed vulnerability records."""

from collections import Counter
from datetime import datetime, timezone


def generate_markdown_report(catalog, analyzed_records):
    priorities = Counter(
        item.get("priority", "UNASSIGNED")
        for item in analyzed_records
    )
    total_findings = len(analyzed_records)

    known_ransomware = sum(
        1
        for item in analyzed_records
        if str(item.get("known_ransomware_use", "")).strip().lower()
        == "known"
    )

    lines = [
        "# Cybersecurity Intelligence Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Source: {catalog.get('source', 'Unknown')}",
        f"Catalog version: {catalog.get('catalog_version', 'Unknown')}",
        f"Records collected: {catalog.get('record_count', len(analyzed_records))}",
        "",
        "",
        "## Executive Summary",
        "",
        f"Total vulnerabilities analyzed: {total_findings}",
        f"Critical findings: {priorities.get('CRITICAL', 0)}",
        f"High findings: {priorities.get('HIGH', 0)}",
        f"Findings associated with known ransomware use: {known_ransomware}",
        "",
        "These findings come from the CISA Known Exploited Vulnerabilities catalog.",
        "They are not confirmation that any particular organization's systems",
        "are affected. Asset inventory and vulnerability matching are required.",
        "",
        "## Priority Summary",
        "",
    ]

    for priority in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED"):
        lines.append(f"- {priority}: {priorities.get(priority, 0)}")

    lines.extend([
        "",
        "## Vulnerability Findings",
        "",
    ])

    for item in analyzed_records:
        lines.extend([
            f"### {item.get('cve_id', 'Unknown CVE')} — {item.get('priority', 'UNASSIGNED')}",
            "",
            f"- Vendor: {item.get('vendor', 'Unknown')}",
            f"- Product: {item.get('product', 'Unknown')}",
            f"- Vulnerability: {item.get('vulnerability_name', 'Not provided')}",
            f"- Date added to KEV: {item.get('date_added', 'Unknown')}",
            f"- CISA remediation due date: {item.get('due_date', 'Not provided')}",
            f"- Known ransomware use: {item.get('known_ransomware_use', 'Unknown')}",
            f"- CISA triage score: {item.get('triage_score', 'Not scored')}",
            f"- Selection score: {item.get('selection_score', 'Not scored')}",
            "",
            "CISA triage reasons:",
        ])

        for reason in item.get("analysis_reasons", []):
            lines.append(f"- {reason}")

        selection_reasons = item.get("selection_reasons", [])
        if selection_reasons:
            lines.extend(["", "Strategic enrichment selection reasons:"])
            for reason in selection_reasons:
                lines.append(f"- {reason}")

        enrichment = item.get("nvd_enrichment", {})
        status = enrichment.get("status", "not_run")

        lines.extend([
            "",
            "#### NVD Enrichment",
            "",
            f"- Lookup status: {status}",
        ])

        if status in ("retrieved", "cached"):
            details = enrichment.get("data", {})
            lines.append(
                f"- NVD record found: {details.get('nvd_found', False)}"
            )

            cvss = details.get("cvss")
            if isinstance(cvss, dict):
                lines.extend([
                    f"- CVSS version: {cvss.get('version', 'Not provided')}",
                    f"- CVSS base score: {cvss.get('base_score', 'Not provided')}",
                    f"- CVSS severity: {cvss.get('base_severity', 'Not provided')}",
                    f"- CVSS vector: {cvss.get('vector', 'Not provided')}",
                ])
            else:
                lines.append("- CVSS data: Not available")

            weaknesses = details.get("weaknesses", [])
            lines.append(
                f"- CWE weaknesses: {', '.join(weaknesses) if weaknesses else 'Not provided'}"
            )

            description = details.get("description")
            if description:
                lines.extend(["", "NVD description:", "", description])

            nvd_source = details.get("source_url")
            if nvd_source:
                lines.extend(["", f"NVD source: {nvd_source}"])

        elif status == "failed":
            lines.append(
                f"- Lookup error: {enrichment.get('error', 'Unknown error')}"
            )

        elif status == "not_selected":
            reason = enrichment.get(
                "reason",
                "Lower strategic selection score",
            )
            lines.append(f"- Not queried: {reason}.")

        elif status == "invalid_cve":
            lines.append("- Lookup skipped because the CVE identifier was invalid.")

        else:
            lines.append("- NVD enrichment was not performed.")

        lines.extend([
            "",
            f"CISA catalog source: {item.get('source_url', 'Not provided')}",
            "",
        ])

    lines.extend([
        "## Analyst Recommendations",
        "",
        "The following actions are recommended for organizations",
        "using this intelligence report:",
        "",
        "1. **Validate asset inventory:** Identify whether affected",
        "   vendors and products are present in the environment.",
        "",
        "2. **Confirm exposure:** Determine whether affected systems",
        "   are reachable, externally exposed, or otherwise accessible.",
        "",
        "3. **Prioritize remediation:** Review applicable vulnerabilities",
        "   associated with known exploitation and ransomware activity.",
        "",
        "4. **Verify remediation options:** Check vendor advisories,",
        "   available patches, and applicable mitigation guidance.",
        "",
        "5. **Track remediation status:** Document affected assets,",
        "   assigned owners, remediation actions, and outstanding risk.",
        "",
        "These recommendations require organization-specific validation.",
        "This report does not independently verify asset presence,",
        "exposure, compromise, or remediation status.",
        "",
        "## Methodology and Limitations",
        "",
        "CISA priorities are produced by a rule-based preliminary triage heuristic.",
        "They are not CVSS scores, confirmed vulnerability assessments, or",
        "organization-specific risk ratings. NVD CVSS scores are reported separately",
        "using the data returned by the National Vulnerability Database.",
        "Strategic selection scores are a separate internal heuristic used to",
        "prioritize limited NVD enrichment requests; they are not severity ratings.",
        "CISA KEV inclusion indicates known exploitation, while ransomware-use",
        "status and CISA remediation deadlines provide additional triage context.",
        "CISA remediation deadlines are federal-agency requirements and should not",
        "be interpreted as universal patch deadlines.",
        "Verify applicability, asset exposure, patch availability, and current",
        "vendor guidance before making remediation decisions.",
        "",
    ])

    return "\n".join(lines)


def generate_customer_brief(catalog, analyzed_records, limit=10):
    """Generate a concise, customer-facing CISA vulnerability intelligence brief."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("limit must be a non-negative integer")

    priorities = Counter(
        item.get("priority", "UNASSIGNED")
        for item in analyzed_records
    )

    known_ransomware = sum(
        1
        for item in analyzed_records
        if str(item.get("known_ransomware_use", "")).strip().lower() == "known"
    )

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "UNASSIGNED": 4,
    }

    def ranking_key(item):
        priority = item.get("priority", "UNASSIGNED")
        ransomware = (
            str(item.get("known_ransomware_use", "")).strip().lower()
            == "known"
        )

        selection_score = item.get("selection_score", 0)
        if (
            isinstance(selection_score, bool)
            or not isinstance(selection_score, (int, float))
        ):
            selection_score = 0

        triage_score = item.get("triage_score", 0)
        if (
            isinstance(triage_score, bool)
            or not isinstance(triage_score, (int, float))
        ):
            triage_score = 0

        return (
            priority_order.get(priority, 4),
            -int(ransomware),
            -selection_score,
            -triage_score,
            str(item.get("cve_id", "")),
        )
    ranked_records = sorted(analyzed_records, key=ranking_key)
    selected = ranked_records[:limit]

    lines = [
        "# VulnSignal Customer Intelligence Brief",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Source: {catalog.get('source', 'Unknown')}",
        f"Catalog version: {catalog.get('catalog_version', 'Unknown')}",
        "",
        "## Executive Overview",
        "",
        f"Vulnerabilities analyzed: {len(analyzed_records)}",
        f"Critical findings: {priorities.get('CRITICAL', 0)}",
        f"High findings: {priorities.get('HIGH', 0)}",
        f"Known ransomware-associated findings: {known_ransomware}",
        "",
        "## Priority Snapshot",
        "",
    ]

    for priority in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED"):
        lines.append(f"- {priority}: {priorities.get(priority, 0)}")

    lines.extend([
        "",
        f"## Selected Vulnerabilities (up to {limit})",
        "",
    ])

    if not selected:
        lines.append("No vulnerabilities were available for this brief.")
    else:
        for item in selected:
            lines.extend([
                f"### {item.get('cve_id', 'Unknown CVE')}",
                "",
                f"- Priority: {item.get('priority', 'UNASSIGNED')}",
                f"- Vendor: {item.get('vendor', 'Not provided')}",
                f"- Product: {item.get('product', 'Not provided')}",
                f"- Vulnerability: {item.get('vulnerability_name', 'Not provided')}",
                f"- Known ransomware use: {item.get('known_ransomware_use', 'Not provided')}",
                f"- CISA date added: {item.get('date_added', 'Not provided')}",
                f"- CISA remediation due date: {item.get('due_date', 'Not provided')}",
            ])

            source_url = item.get("source_url")
            if source_url:
                lines.append(f"- CISA source: {source_url}")

            lines.append("")

    lines.extend([
        "## Recommended Actions",
        "",
        "1. Compare affected vendors and products against your asset inventory.",
        "2. Confirm whether matching systems are exposed or otherwise accessible.",
        "3. Review vendor advisories and available patches or mitigations.",
        "4. Prioritize remediation using your organization's risk and exposure context.",
        "5. Track remediation owners, actions, and outstanding risk.",
        "",
        "## Scope and Limitations",
        "",
        "This brief summarizes vulnerabilities listed in the CISA Known Exploited",
        "Vulnerabilities catalog. It does not establish that your organization",
        "uses affected products or that any of its systems are vulnerable.",
        "Asset matching, exposure validation, and remediation verification are",
        "required before making organization-specific decisions.",
        "",
        "VulnSignal priority is a preliminary rule-based triage indicator,",
        "not a CVSS score or an organization-specific risk rating.",
        "CISA remediation due dates are federal-agency requirements, not",
        "universal patch deadlines.",
        "",
    ])

    return "\n".join(lines)
