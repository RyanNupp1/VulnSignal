"""Assess customer assets against analyzed and NVD-enriched KEV findings."""

from core.asset_matcher import _evaluate_cpe_configurations_for_host
from core.inventory import group_assets_by_host


def assess_inventory(assets, findings, inventory_complete=False):
    """Return one conservative exposure assessment per host and CVE."""
    if not isinstance(assets, list):
        raise ValueError("assets must be supplied as a list.")

    if not isinstance(findings, list):
        raise ValueError("findings must be supplied as a list.")

    if not isinstance(inventory_complete, bool):
        raise ValueError("inventory_complete must be a boolean.")

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each finding must be a dictionary.")

    hosts = group_assets_by_host(assets)
    assessments = []

    for hostname, host_assets in hosts.items():
        for finding in findings:
            enrichment = finding.get("nvd_enrichment")
            enrichment = enrichment if isinstance(enrichment, dict) else {}

            status = enrichment.get("status")
            details = enrichment.get("data")

            evaluator_result = "indeterminate"
            vulnerable_match = False
            exposure_status = "indeterminate"

            if status in {"retrieved", "cached"} and isinstance(details, dict):
                configurations = details.get("configurations", [])

                evaluation = _evaluate_cpe_configurations_for_host(
                    host_assets,
                    configurations,
                    inventory_complete=inventory_complete,
                )

                evaluator_result = evaluation["result"]
                vulnerable_match = evaluation["vulnerable_match"]

                if evaluator_result == "match" and vulnerable_match:
                    exposure_status = "affected"
                    reason = (
                        "NVD applicability configuration matched and "
                        "included a vulnerable CPE."
                    )
                elif evaluator_result == "no_match" and inventory_complete:
                    exposure_status = "not_affected"
                    reason = (
                        "No applicable vulnerable configuration matched "
                        "in the declared complete inventory."
                    )
                elif evaluator_result == "match":
                    reason = (
                        "Configuration matched, but no vulnerable CPE "
                        "was established."
                    )
                else:
                    reason = (
                        "Available inventory and NVD data were insufficient "
                        "to establish exposure or non-exposure."
                    )
            else:
                reason = (
                    f"NVD enrichment unavailable for assessment "
                    f"(status: {status or 'missing'})."
                )

            assessments.append({
                "hostname": hostname,
                "cve_id": finding.get("cve_id"),
                "priority": finding.get("priority"),
                "triage_score": finding.get("triage_score"),
                "exposure_status": exposure_status,
                "evaluator_result": evaluator_result,
                "vulnerable_match": vulnerable_match,
                "assessment_reason": reason,
                "inventory_complete": inventory_complete,
                "nvd_status": status or "missing",
                "source": (
                    details.get("source")
                    if isinstance(details, dict) else None
                ),
                "source_url": (
                    details.get("source_url")
                    if isinstance(details, dict) else None
                ),
            })

    return assessments
