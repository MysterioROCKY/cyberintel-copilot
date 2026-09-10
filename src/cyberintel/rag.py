"""Small local Chroma RAG index for vetted cybersecurity source records."""

from functools import lru_cache
import re

import chromadb
from sentence_transformers import SentenceTransformer

from cyberintel.config import (
    CHROMA_PATH,
    COLLECTION_NAME,
    EMBEDDING_MODEL_NAME,
)


@lru_cache(maxsize=1)
def embedding_model() -> SentenceTransformer:
    """Load the local embedding model once per application process."""
    return SentenceTransformer(EMBEDDING_MODEL_NAME)


def collection_exists() -> bool:
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    return COLLECTION_NAME in [item.name for item in client.list_collections()]


def index_documents(documents: list[str], metadatas: list[dict], ids: list[str]) -> int:
    """Embed and persist trusted documents locally."""
    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_or_create_collection(name=COLLECTION_NAME)
    embeddings = embedding_model().encode(documents, show_progress_bar=True).tolist()
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas, embeddings=embeddings)
    return collection.count()


def retrieve(query: str, limit: int = 3) -> list[dict]:
    """Return the most relevant locally indexed source records for a query."""
    if not collection_exists():
        return []

    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_collection(name=COLLECTION_NAME)

    # CVE identifiers are exact identifiers, so direct lookup is more reliable
    # than semantic similarity for an ID-based question.
    match = re.search(r"\bCVE-\d{4}-\d{4,}\b", query, flags=re.IGNORECASE)
    if match:
        cve_id = match.group(0).upper()
        exact = collection.get(ids=[cve_id], include=["documents", "metadatas"])
        if exact.get("documents"):
            return [
                {"document": exact["documents"][0], "metadata": exact["metadatas"][0]}
            ]

    query_embedding = embedding_model().encode([query]).tolist()
    result = collection.query(query_embeddings=query_embedding, n_results=min(limit, collection.count()))

    documents = result.get("documents", [[]])[0]
    metadatas = result.get("metadatas", [[]])[0]
    return [
        {"document": document, "metadata": metadata}
        for document, metadata in zip(documents, metadatas, strict=True)
    ]
