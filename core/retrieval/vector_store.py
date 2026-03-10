from __future__ import annotations

from dataclasses import asdict
from typing import Any

import faiss
import numpy as np

from core.models.schema import CodeChunk
from core.retrieval.embeddings import AzureEmbeddingClient


class CodeVectorStore:
    def __init__(self, embedding_client: AzureEmbeddingClient) -> None:
        self.embedding_client = embedding_client
        self.index: faiss.IndexFlatIP | None = None
        self.chunks: list[CodeChunk] = []
        self.dimension: int | None = None

    def build(self, chunks: list[CodeChunk]) -> None:
        self.chunks = chunks
        if not chunks:
            self.index = None
            self.dimension = None
            return
        embeddings = self.embedding_client.embed_texts([self._embed_text(chunk) for chunk in chunks])
        matrix = np.array(embeddings, dtype="float32")
        faiss.normalize_L2(matrix)
        self.dimension = int(matrix.shape[1])
        self.index = faiss.IndexFlatIP(self.dimension)
        self.index.add(matrix)

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        if self.index is None or not self.chunks:
            return []
        query_vec = np.array(self.embedding_client.embed_texts([query]), dtype="float32")
        faiss.normalize_L2(query_vec)
        scores, ids = self.index.search(query_vec, min(top_k, len(self.chunks)))
        results: list[dict[str, Any]] = []
        for score, idx in zip(scores[0].tolist(), ids[0].tolist()):
            if idx < 0:
                continue
            chunk = self.chunks[idx]
            results.append({
                "score": round(float(score), 4),
                "chunk": asdict(chunk),
            })
        return results

    @staticmethod
    def _embed_text(chunk: CodeChunk) -> str:
        symbol = f"symbol={chunk.symbol_name}\n" if chunk.symbol_name else ""
        return f"file={chunk.file_path}\nkind={chunk.kind}\nlanguage={chunk.language}\n{symbol}{chunk.content}"
