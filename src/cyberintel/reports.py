"""Page-aware local RAG indexing for uploaded public threat-intelligence PDFs."""

import hashlib
import re
from pathlib import Path

import chromadb
import fitz

from cyberintel.config import CHROMA_PATH, PROCESSED_DATA_DIR, RAW_DATA_DIR
from cyberintel.rag import embedding_model


CHUNK_SIZE = 1100
CHUNK_OVERLAP = 160


def safe_filename(filename: str) -> str:
    """Keep a readable, filesystem-safe name for a locally stored upload."""
    name = Path(filename).name
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "threat_report.pdf"


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split one PDF page into overlapping chunks while preserving page identity."""
    text = " ".join(text.split())
    if not text:
        return []
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = end - overlap
    return chunks


def extract_pdf_pages(content: bytes) -> list[str]:
    """Extract text per page. Image-only PDFs require OCR and are reported clearly."""
    document = fitz.open(stream=content, filetype="pdf")
    try:
        pages = [page.get_text("text") for page in document]
    finally:
        document.close()
    if not any(page.strip() for page in pages):
        raise ValueError("No selectable text was found. Use a text-based PDF; OCR support can be added later.")
    return pages


def _collection_name(report_id: str) -> str:
    return f"report_{report_id[:16]}"


def index_report(filename: str, content: bytes) -> dict:
    """Persist a report locally and create/reuse its page-aware Chroma collection."""
    if not content.startswith(b"%PDF"):
        raise ValueError("The uploaded file does not appear to be a PDF.")
    report_id = hashlib.sha256(content).hexdigest()
    clean_name = safe_filename(filename)
    pages = extract_pdf_pages(content)
    raw_dir = RAW_DATA_DIR / "reports"
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / f"{report_id[:16]}_{clean_name}").write_bytes(content)

    documents: list[str] = []
    metadatas: list[dict] = []
    ids: list[str] = []
    for page_number, page_text in enumerate(pages, start=1):
        for chunk_number, chunk in enumerate(chunk_text(page_text), start=1):
            ids.append(f"{report_id[:16]}_p{page_number}_c{chunk_number}")
            documents.append(chunk)
            metadatas.append(
                {
                    "report_id": report_id,
                    "filename": clean_name,
                    "page": page_number,
                    "chunk": chunk_number,
                    "source_type": "Uploaded threat report",
                }
            )
    if not documents:
        raise ValueError("The report contains no extractable text chunks.")

    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_or_create_collection(name=_collection_name(report_id))
    embeddings = embedding_model().encode(documents, show_progress_bar=True).tolist()
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)
    return {"report_id": report_id, "filename": clean_name, "page_count": len(pages), "chunk_count": len(documents)}


def retrieve_report(report_id: str, query: str, limit: int = 4) -> list[dict]:
    """Return the most relevant page-level excerpts for a question about one report."""
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_collection(name=_collection_name(report_id))
    count = collection.count()
    if not count:
        return []
    query_embedding = embedding_model().encode([query]).tolist()
    result = collection.query(query_embeddings=query_embedding, n_results=min(limit, count))
    return [
        {"document": document, "metadata": metadata}
        for document, metadata in zip(result["documents"][0], result["metadatas"][0], strict=True)
    ]
