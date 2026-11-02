"""Enrich strategically selected CISA KEV findings with cached NVD details."""

import json
import time
from pathlib import Path

from collectors.nvd import fetch_cve_details, NVDCollectorError
from core.selection import calculate_selection_score


DEFAULT_CACHE_PATH = Path("output/nvd_cache.json")
DEFAULT_LIMIT = 5


def load_cache(cache_path):
    """Load cached NVD records, returning an empty cache if unavailable."""
    path = Path(cache_path)

    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    return data if isinstance(data, dict) else {}


def save_cache(cache, cache_path):
    """Save cached records using an atomic file replacement."""
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(
        json.dumps(cache, indent=2),
        encoding="utf-8",
    )
    temporary_path.replace(path)


def enrich_findings(
    findings,
    limit=DEFAULT_LIMIT,
    cache_path=DEFAULT_CACHE_PATH,
    session=None,
    sleep_seconds=0,
):
    """Enrich the highest-selection-score findings while preserving input order."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError("limit must be a non-negative integer")

    cache = load_cache(cache_path)

    scored_findings = []

    for index, finding in enumerate(findings):
        selection = calculate_selection_score(finding)
        scored_findings.append({
            "index": index,
            "selection_score": selection["selection_score"],
            "cve_id": finding.get("cve_id", ""),
        })

    scored_findings.sort(
        key=lambda item: (
            -item["selection_score"],
            item["cve_id"] if isinstance(item["cve_id"], str) else "",
        )
    )

    selected_indices = {
        item["index"]
        for item in scored_findings[:limit]
    }

    enriched = []
    requests_made = 0

    for index, finding in enumerate(findings):
        result = dict(finding)
        selection = calculate_selection_score(finding)

        result["selection_score"] = selection["selection_score"]
        result["selection_reasons"] = selection["selection_reasons"]

        if index not in selected_indices:
            result["nvd_enrichment"] = {
                "status": "not_selected",
                "reason": "Lower strategic selection score",
            }
            enriched.append(result)
            continue

        cve_id = finding.get("cve_id")

        if not isinstance(cve_id, str) or not cve_id:
            result["nvd_enrichment"] = {
                "status": "invalid_cve",
            }
            enriched.append(result)
            continue

        if cve_id in cache:
            result["nvd_enrichment"] = {
                "status": "cached",
                "data": cache[cve_id],
            }
            enriched.append(result)
            continue

        if requests_made > 0 and sleep_seconds > 0:
            time.sleep(sleep_seconds)

        try:
            details = fetch_cve_details(cve_id, session=session)
            cache[cve_id] = details
            result["nvd_enrichment"] = {
                "status": "retrieved",
                "data": details,
            }
        except (NVDCollectorError, ValueError) as exc:
            result["nvd_enrichment"] = {
                "status": "failed",
                "error": str(exc),
            }

        requests_made += 1
        enriched.append(result)

    save_cache(cache, cache_path)
    return enriched
