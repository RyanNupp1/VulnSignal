"""Run the cybersecurity intelligence collection pipeline."""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from collectors.cisa_kev import fetch_kev_catalog
from core.analyst import analyze_catalog
from core.enrichment import enrich_findings
from reports.generator import generate_markdown_report, generate_customer_brief


def main():
    print("Cybersecurity Intelligence Pipeline")
    print("=" * 40)

    print("\n[1/4] Collecting CISA KEV catalog...")
    catalog = fetch_kev_catalog()
    print(f"Collected {len(catalog['vulnerabilities'])} records.")

    print("\n[2/4] Analyzing vulnerabilities...")
    analyzed = analyze_catalog(catalog)
    print(f"Analyzed {len(analyzed)} records.")

    print("\n[3/4] Enriching selected findings with NVD...")
    enriched = enrich_findings(
        analyzed,
        limit=5,
        sleep_seconds=6.5,
    )

    statuses = Counter(
        record.get("nvd_enrichment", {}).get("status", "unknown")
        for record in enriched
    )

    print("NVD enrichment results:")
    for status, count in sorted(statuses.items()):
        print(f"  {status}: {count}")

    print("\n[4/4] Generating reports...")
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    markdown = generate_markdown_report(catalog, enriched)
    markdown_path = output_dir / f"intel_report_{timestamp}.md"
    markdown_path.write_text(markdown, encoding="utf-8")

    customer_brief = generate_customer_brief(
        catalog, enriched, limit=10
    )
    customer_brief_path = (
        output_dir / f"customer_brief_{timestamp}.md"
    )
    customer_brief_path.write_text(
        customer_brief, encoding="utf-8"
    )

    json_path = output_dir / f"intel_data_{timestamp}.json"
    json_path.write_text(
        json.dumps(
            {
                "catalog_metadata": {
                    key: value
                    for key, value in catalog.items()
                    if key != "vulnerabilities"
                },
                "analyzed_vulnerabilities": enriched,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\nPipeline completed.")
    print(f"Markdown report: {markdown_path}")
    print(f"Customer brief:  {customer_brief_path}")
    print(f"JSON data:       {json_path}")


if __name__ == "__main__":
    main()
