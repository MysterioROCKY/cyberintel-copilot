"""Build the first local RAG knowledge base from CISA's public KEV feed."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from cyberintel.config import RAW_DATA_DIR
from cyberintel.kev import download_kev_catalog, kev_record_to_document
from cyberintel.rag import index_documents


def main() -> None:
    raw_file = RAW_DATA_DIR / "cisa_kev_catalog.json"
    catalog = download_kev_catalog(raw_file)
    records = catalog["vulnerabilities"]

    converted = [kev_record_to_document(record) for record in records]
    documents = [item[0] for item in converted]
    metadatas = [item[1] for item in converted]
    ids = [metadata["cve_id"] for metadata in metadatas]
    total = index_documents(documents, metadatas, ids)

    print(f"Downloaded {len(records)} CISA KEV records.")
    print(f"Indexed {total} records in the local Chroma database.")
    print(f"Raw source saved to: {raw_file}")


if __name__ == "__main__":
    main()
