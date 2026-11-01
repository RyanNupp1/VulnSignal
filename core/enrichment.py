"""Enrich selected CISA KEV findings with cached NVD details."""

import json
import time
from pathlib import Path

from collectors.nvd import fetch_cve_details, NVDCollectorError


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
    """Attach NVD details to a limited number of prioritized findings."""
    cache = load_cache(cache_path)
    enriched = []

    selected = findings[:limit]

    for index, finding in enumerate(findings):
        result = dict(finding)

        if index >= limit:
            result["nvd_enrichment"] = {
                "status": "not_selected",
                "reason": "Outside enrichment limit",
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

        enriched.append(result)

        if sleep_seconds > 0 and index < len(selected) - 1:
            time.sleep(sleep_seconds)

    save_cache(cache, cache_path)
    return enriched
