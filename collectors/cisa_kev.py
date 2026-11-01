"""Collect and normalize CISA Known Exploited Vulnerabilities."""

from datetime import datetime, timezone

import requests


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

SOURCE_NAME = "CISA Known Exploited Vulnerabilities"


class CISACollectorError(Exception):
    """Raised when CISA intelligence cannot be retrieved or validated."""


def fetch_kev_catalog(session=None):
    """Fetch the public CISA KEV catalog and return normalized records."""

    client = session or requests

    try:
        response = client.get(CISA_KEV_URL, timeout=20)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise CISACollectorError(
            f"Unable to retrieve CISA catalog: {exc}"
        ) from exc
    except ValueError as exc:
        raise CISACollectorError(
            "CISA returned invalid JSON."
        ) from exc

    if not isinstance(payload, dict):
        raise CISACollectorError("Unexpected catalog format.")

    vulnerabilities = payload.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        raise CISACollectorError(
            "Catalog is missing its vulnerabilities list."
        )

    records = []

    required_fields = (
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
    )

    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue

        if not all(item.get(field) for field in required_fields):
            continue

        records.append({
            "cve_id": item["cveID"],
            "vendor": item["vendorProject"],
            "product": item["product"],
            "vulnerability_name": item["vulnerabilityName"],
            "date_added": item["dateAdded"],
            "description": item["shortDescription"],
            "required_action": item["requiredAction"],
            "due_date": item["dueDate"],
            "known_ransomware_use": item.get(
                "knownRansomwareCampaignUse", "Unknown"
            ),
            "source": SOURCE_NAME,
            "source_url": CISA_KEV_URL,
        })

    return {
        "source": SOURCE_NAME,
        "source_url": CISA_KEV_URL,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "catalog_version": payload.get("catalogVersion"),
        "catalog_date_released": payload.get("dateReleased"),
        "record_count": len(records),
        "vulnerabilities": records,
    }
