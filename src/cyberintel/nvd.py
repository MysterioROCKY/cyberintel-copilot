"""Read and cache individual public CVE records from NIST's NVD API."""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from cyberintel.config import RAW_DATA_DIR


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CACHE_MAX_AGE = timedelta(hours=24)


def extract_cve_id(query: str) -> str | None:
    """Return a normalized CVE identifier when the user supplied one."""
    match = CVE_PATTERN.search(query)
    return match.group(0).upper() if match else None


def _cache_path(cve_id: str) -> Path:
    return RAW_DATA_DIR / "nvd" / f"{cve_id}.json"


def _read_fresh_cache(path: Path) -> dict | None:
    if not path.exists():
        return None
    modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    if datetime.now(timezone.utc) - modified > CACHE_MAX_AGE:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_nvd_record(cve_id: str) -> dict | None:
    """Fetch one NVD CVE record, using a 24-hour local cache when available."""
    path = _cache_path(cve_id)
    cached = _read_fresh_cache(path)
    if cached is not None:
        return cached

    response = requests.get(NVD_API_URL, params={"cveId": cve_id}, timeout=30)
    response.raise_for_status()
    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    record = vulnerabilities[0].get("cve")
    if not record:
        return None

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def _english_description(descriptions: list[dict]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "Not listed")
    return "Not listed"


def _cvss_summary(metrics: dict) -> str:
    """Prefer modern CVSS data but tolerate older or incomplete NVD records."""
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_name, [])
        if entries:
            metric = entries[0]
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore", "Not scored")
            severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "Not listed"
            version = cvss_data.get("version", metric_name.replace("cvssMetric", ""))
            return f"CVSS v{version}: {score} ({severity})"
    return "No CVSS score listed by NVD"


def nvd_record_to_document(record: dict) -> tuple[str, dict]:
    """Create source-backed text that can be passed to the local LLM."""
    cve_id = record["id"]
    source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    references = [reference.get("url") for reference in record.get("references", []) if reference.get("url")]
    reference_text = "\n".join(f"- {url}" for url in references[:5]) or "No references listed"

    document = "\n".join(
        [
            f"CVE ID: {cve_id}",
            f"NVD status: {record.get('vulnStatus', 'Not listed')}",
            f"Published: {record.get('published', 'Not listed')}",
            f"Last modified: {record.get('lastModified', 'Not listed')}",
            f"NVD description: {_english_description(record.get('descriptions', []))}",
            f"Severity: {_cvss_summary(record.get('metrics', {}))}",
            "NVD references:\n" + reference_text,
            f"Official source: {source_url}",
        ]
    )
    metadata = {
        "cve_id": cve_id,
        "source_name": "NIST National Vulnerability Database",
        "source_url": source_url,
        "severity": _cvss_summary(record.get("metrics", {})),
        "published": record.get("published", "Not listed"),
    }
    return document, metadata
