# VulnSignal

VulnSignal is a lightweight cybersecurity intelligence pipeline built with Python. It collects public vulnerability information, applies transparent rule-based triage, enriches selected findings with NIST NVD data, and generates Markdown and JSON reports.

## Current capabilities

- Collects the CISA Known Exploited Vulnerabilities (KEV) catalog.
- Normalizes vulnerability records.
- Applies an explainable preliminary priority score.
- Accounts for known ransomware use and CISA remediation due dates.
- Enriches selected findings with NIST NVD data.
- Retrieves available CVSS metrics, descriptions, and CWE weaknesses.
- Caches NVD lookups to reduce repeated requests.
- Generates timestamped Markdown and JSON reports.
- Includes automated unit tests.

## Data sources

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NIST NVD API: https://nvd.nist.gov/developers/vulnerabilities

## Requirements

- Python 3.10 or newer
- requests

Install the dependency:

    python -m pip install requests

## Run VulnSignal

From the project directory:

    python main.py

Generated reports are written to the `output/` directory.

## Run tests

    python -m unittest discover -s tests -v

## Triage methodology and limitations

VulnSignal uses a transparent, rule-based CISA triage score to help organize findings. This score is not a CVSS score, a confirmed vulnerability assessment, or an organization-specific risk rating.

NVD CVSS metrics are reported separately when available. CVSS describes standardized vulnerability severity; it does not independently establish risk to a particular organization.

CISA KEV inclusion indicates that a vulnerability is known to have been exploited in the wild. Actual remediation priority depends on affected assets, exposure, available mitigations, business impact, and current vendor guidance.

The current pipeline enriches a limited number of findings per run to respect NVD service rate limits. Findings outside that limit are identified in the report.

## Security and responsible use

- Uses publicly available vulnerability information.
- Does not scan or exploit target systems.
- Does not attempt unauthorized access.
- Keeps generated reports and local configuration out of the public repository.
- Never commit API keys, tokens, passwords, or other secrets.

## Project status

VulnSignal is an actively developed cybersecurity learning and portfolio project. Its scoring methodology and enrichment policy may evolve as testing and validation continue.
