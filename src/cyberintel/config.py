"""Central configuration for the local CyberIntel Copilot application."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

# This is the non-thinking Qwen 3 instruct variant, not qwen3:4b-thinking.
MODEL_NAME = "qwen3:4b-instruct"
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
CHROMA_PATH = PROCESSED_DATA_DIR / "chroma"
COLLECTION_NAME = "cisa_kev"

CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
