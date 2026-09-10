"""Local inventory parsing and conservative CISA KEV-based risk prioritization."""

import json
import re
from dataclasses import dataclass

from cyberintel.config import RAW_DATA_DIR


HEADER_NAMES = {"product", "asset", "product name", "asset name"}
EXPOSED_VALUES = {"yes", "y", "true", "internet", "internet-facing", "public"}
NOT_EXPOSED_VALUES = {"no", "n", "false", "internal", "private"}
IGNORED_TOKENS = {"and", "the", "for", "multiple", "product", "products", "software"}


@dataclass(frozen=True)
class Asset:
    name: str
    version: str
    internet_exposed: str


@dataclass(frozen=True)
class AssetFinding:
    asset: Asset
    priority: str
    reason: str
    match_type: str
    matches: tuple[dict, ...]


def parse_inventory(text: str) -> tuple[list[Asset], list[str]]:
    """Parse `product | version | exposure` lines without scanning systems."""
    assets: list[Asset] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = [field.strip() for field in line.split("|")]
        if fields[0].lower() in HEADER_NAMES:
            continue
        if len(fields) > 3:
            errors.append(f"Line {line_number}: use at most three fields separated by |.")
            continue
        if not fields[0]:
            errors.append(f"Line {line_number}: product name is required.")
            continue
        version = fields[1] if len(fields) >= 2 and fields[1] else "Not provided"
        exposure = fields[2].lower() if len(fields) >= 3 else "unknown"
        if exposure in EXPOSED_VALUES:
            exposure = "yes"
        elif exposure in NOT_EXPOSED_VALUES:
            exposure = "no"
        elif exposure not in {"unknown", ""}:
            errors.append(f"Line {line_number}: exposure must be yes, no, or unknown.")
            continue
        else:
            exposure = "unknown"
        assets.append(Asset(name=fields[0], version=version, internet_exposed=exposure))
    return assets, errors


def load_local_kev_records() -> list[dict]:
    """Load the CISA catalog already downloaded for the local RAG knowledge base."""
    catalog_path = RAW_DATA_DIR / "cisa_kev_catalog.json"
    if not catalog_path.exists():
        raise FileNotFoundError("CISA KEV data is missing. Run scripts/build_cisa_kev_kb.py first.")
    return json.loads(catalog_path.read_text(encoding="utf-8")).get("vulnerabilities", [])


def _tokens(value: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", value.lower()) if len(token) > 2 and token not in IGNORED_TOKENS}


def candidate_match_score(asset_name: str, record: dict) -> int:
    """Score product names only; never make an unverified version claim."""
    candidate = f"{record.get('vendorProject', '')} {record.get('product', '')}".strip().lower()
    normalized_asset = " ".join(re.findall(r"[a-z0-9]+", asset_name.lower()))
    normalized_candidate = " ".join(re.findall(r"[a-z0-9]+", candidate))
    if not normalized_asset or not normalized_candidate:
        return 0
    if normalized_asset in normalized_candidate or normalized_candidate in normalized_asset:
        return 100
    shared = _tokens(asset_name) & _tokens(candidate)
    if len(shared) >= 2:
        return 75
    if len(_tokens(asset_name)) == 1 and len(shared) == 1:
        return 60
    return 0


def find_candidate_matches(asset: Asset, records: list[dict], limit: int = 5) -> list[dict]:
    scored = [(candidate_match_score(asset.name, record), record) for record in records]
    matches = [item for item in scored if item[0] > 0]
    matches.sort(key=lambda item: (item[0], item[1].get("dateAdded", "")), reverse=True)
    return [record for _, record in matches[:limit]]


def prioritize_asset(asset: Asset, records: list[dict]) -> AssetFinding:
    """Prioritize an asset using candidate CISA KEV matches and stated exposure."""
    matches = tuple(find_candidate_matches(asset, records))
    if matches and asset.internet_exposed == "yes":
        return AssetFinding(asset, "Patch now", "Candidate CISA KEV match and asset marked internet-facing.", "Candidate product-name match", matches)
    if matches:
        return AssetFinding(asset, "Review urgently", "Candidate CISA KEV match; confirm installed version and exposure before patching.", "Candidate product-name match", matches)
    return AssetFinding(asset, "Monitor", "No candidate CISA KEV product-name match. This is not proof that the asset is safe.", "No candidate match", ())


def prioritize_inventory(assets: list[Asset], records: list[dict]) -> list[AssetFinding]:
    rank = {"Patch now": 0, "Review urgently": 1, "Monitor": 2}
    return sorted((prioritize_asset(asset, records) for asset in assets), key=lambda item: (rank[item.priority], item.asset.name.lower()))


def cisa_record_url(record: dict) -> str:
    return f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={record['cveID']}"
