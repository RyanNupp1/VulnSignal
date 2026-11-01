"""Generate Markdown reports from analyzed vulnerability records."""

from collections import Counter
from datetime import datetime, timezone


def generate_markdown_report(catalog, analyzed_records):
    priorities = Counter(
        item.get("priority", "UNASSIGNED")
        for item in analyzed_records
    )

    lines = [
        "# Cybersecurity Intelligence Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Source: {catalog.get('source', 'Unknown')}",
        f"Catalog version: {catalog.get('catalog_version', 'Unknown')}",
        f"Records collected: {catalog.get('record_count', len(analyzed_records))}",
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
            "",
            "CISA triage reasons:",
        ])

        for reason in item.get("analysis_reasons", []):
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
            lines.append(
                "- Not queried because the enrichment limit was reached."
            )
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
        "## Methodology and Limitations",
        "",
        "CISA priorities are produced by a rule-based preliminary triage heuristic.",
        "They are not CVSS scores, confirmed vulnerability assessments, or",
        "organization-specific risk ratings. NVD CVSS scores are reported separately",
        "using the data returned by the National Vulnerability Database.",
        "CISA KEV inclusion indicates known exploitation, while ransomware-use",
        "status and CISA remediation deadlines provide additional triage context.",
        "CISA remediation deadlines are federal-agency requirements and should not",
        "be interpreted as universal patch deadlines.",
        "Verify applicability, asset exposure, patch availability, and current",
        "vendor guidance before making remediation decisions.",
        "",
    ])

    return "\n".join(lines)
