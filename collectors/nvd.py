"""Retrieve technical vulnerability details from the NVD CVE API."""

from datetime import datetime, timezone
import re

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class NVDCollectorError(Exception):
    """Raised when NVD data cannot be retrieved or interpreted."""


def fetch_cve_details(cve_id, session=None):
    if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
        raise ValueError("A valid CVE identifier is required")

    client = session or requests

    try:
        response = client.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise NVDCollectorError(f"NVD request failed: {exc}") from exc
    except ValueError as exc:
        raise NVDCollectorError("NVD returned invalid JSON") from exc

    if not isinstance(data, dict):
        raise NVDCollectorError("NVD returned an invalid response")

    vulnerabilities = data.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise NVDCollectorError(
            "NVD response did not contain a valid vulnerabilities list"
        )

    if not vulnerabilities:
        return {
            "cve_id": cve_id,
            "nvd_found": False,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        }

    first_result = vulnerabilities[0]

    if not isinstance(first_result, dict):
        raise NVDCollectorError("NVD returned a malformed vulnerability")

    cve = first_result.get("cve")

    if not isinstance(cve, dict):
        raise NVDCollectorError("NVD returned malformed CVE details")

    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        descriptions = []

    description = next(
        (
            item.get("value")
            for item in descriptions
            if isinstance(item, dict) and item.get("lang") == "en"
        ),
        None,
    )

    weaknesses = []
    raw_weaknesses = cve.get("weaknesses", [])

    if isinstance(raw_weaknesses, list):
        for weakness in raw_weaknesses:
            if not isinstance(weakness, dict):
                continue

            items = weakness.get("description", [])
            if not isinstance(items, list):
                continue

            for item in items:
                if isinstance(item, dict) and item.get("lang") == "en":
                    value = item.get("value")
                    if isinstance(value, str):
                        weaknesses.append(value)

    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}

    cvss = None

    for metric_type in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(metric_type, [])

        if not isinstance(entries, list) or not entries:
            continue

        first_metric = entries[0]
        if not isinstance(first_metric, dict):
            continue

        metric = first_metric.get("cvssData")
        if not isinstance(metric, dict):
            continue

        cvss = {
            "version": metric.get("version"),
            "base_score": metric.get("baseScore"),
            "base_severity": metric.get("baseSeverity"),
            "vector": metric.get("vectorString"),
        }
        break

    cpe_matches = extract_cpe_matches(cve.get("configurations", []))

    return {
        "cve_id": cve.get("id", cve_id),
        "nvd_found": True,
        "description": description,
        "weaknesses": sorted(set(weaknesses)),
        "cvss": cvss,
        "cpe_matches": cpe_matches,
        "configurations": cve.get("configurations", []),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "source": "NIST National Vulnerability Database",
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def extract_cpe_matches(configurations):
    """Extract CPE match criteria and version boundaries from NVD data."""
    matches = []

    def walk(value):
        if isinstance(value, list):
            for item in value:
                walk(item)
            return

        if not isinstance(value, dict):
            return

        cpe_matches = value.get("cpeMatch", [])
        if isinstance(cpe_matches, list):
            for item in cpe_matches:
                if not isinstance(item, dict):
                    continue

                criteria = item.get("criteria")
                if not isinstance(criteria, str):
                    continue

                matches.append({
                    "criteria": criteria,
                    "vulnerable": item.get("vulnerable"),
                    "version_start_including": item.get(
                        "versionStartIncluding"
                    ),
                    "version_start_excluding": item.get(
                        "versionStartExcluding"
                    ),
                    "version_end_including": item.get(
                        "versionEndIncluding"
                    ),
                    "version_end_excluding": item.get(
                        "versionEndExcluding"
                    ),
                })

        for key in ("nodes", "children"):
            walk(value.get(key, []))

    walk(configurations)
    return matches
