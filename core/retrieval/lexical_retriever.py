from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from core.models.schema import CodeChunk


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


class LexicalCodeRetriever:
    def __init__(self, chunks: list[CodeChunk]) -> None:
        self.chunks = chunks
        self._chunk_tokens: list[list[str]] = [tokenize(self._chunk_text(c)) for c in chunks]

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        q_tokens = tokenize(query)
        if not q_tokens:
            return []

        scored: list[tuple[float, CodeChunk]] = []
        for chunk, tokens in zip(self.chunks, self._chunk_tokens):
            token_set = set(tokens)
            overlap = sum(1 for t in q_tokens if t in token_set)

            symbol_bonus = 0.0
            if chunk.symbol_name:
                q_lower = query.lower()
                if chunk.symbol_name.lower() in q_lower or q_lower in chunk.symbol_name.lower():
                    symbol_bonus = 2.0

            kind_bonus = 0.5 if chunk.kind in {"function", "class"} else 0.0
            score = float(overlap) + symbol_bonus + kind_bonus

            if score > 0:
                scored.append((score, chunk))

        scored.sort(key=lambda x: x[0], reverse=True)

        results: list[dict[str, Any]] = []
        for score, chunk in scored[:top_k]:
            results.append({
                "score": round(score, 4),
                "chunk": asdict(chunk),
            })
        return results

    @staticmethod
    def _chunk_text(chunk: CodeChunk) -> str:
        symbol = f"{chunk.symbol_name}\n" if chunk.symbol_name else ""
        return f"{chunk.file_path}\n{chunk.kind}\n{chunk.language}\n{symbol}{chunk.content}"