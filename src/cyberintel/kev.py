"""Download and convert CISA KEV records into local RAG documents."""

import json
from pathlib import Path

import requests

from cyberintel.config import CISA_KEV_JSON_URL


def download_kev_catalog(destination: Path) -> dict:
    """Download the official CISA KEV JSON feed and save the exact raw response."""
    response = requests.get(CISA_KEV_JSON_URL, timeout=60)
    response.raise_for_status()
    catalog = response.json()

    if not isinstance(catalog.get("vulnerabilities"), list):
        raise ValueError("The downloaded CISA KEV feed has an unexpected format.")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return catalog


def kev_record_to_document(record: dict) -> tuple[str, dict]:
    """Create searchable defensive text and safe metadata from one KEV record."""
    cve_id = record["cveID"]
    source_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"

    document = "\n".join(
        [
            f"CVE ID: {cve_id}",
            f"Vendor/project: {record.get('vendorProject', 'Not listed')}",
            f"Product: {record.get('product', 'Not listed')}",
            f"Vulnerability name: {record.get('vulnerabilityName', 'Not listed')}",
            f"CISA description: {record.get('shortDescription', 'Not listed')}",
            f"Required action: {record.get('requiredAction', 'Not listed')}",
            "Known ransomware use: "
            f"{record.get('knownRansomwareCampaignUse', 'Unknown')}",
            f"Date added to CISA KEV: {record.get('dateAdded', 'Not listed')}",
            f"CISA due date: {record.get('dueDate', 'Not listed')}",
            f"Notes: {record.get('notes', 'None')}",
            f"Official source: {source_url}",
        ]
    )

    metadata = {
        "cve_id": cve_id,
        "vendor_project": record.get("vendorProject", "Not listed"),
        "product": record.get("product", "Not listed"),
        "vulnerability_name": record.get("vulnerabilityName", "Not listed"),
        "source_name": "CISA Known Exploited Vulnerabilities Catalog",
        "source_url": source_url,
        "date_added": record.get("dateAdded", "Not listed"),
    }
    return document, metadata
