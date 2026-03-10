from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from core.models.schema import FunctionNode, RepositoryIndex
from core.retrieval.lexical_retriever import LexicalCodeRetriever


class RepositoryTools:
    def __init__(self, index: RepositoryIndex, graph: dict, lexical_retriever: LexicalCodeRetriever | None = None) -> None:
        self.index = index
        self.graph = graph
        self.lexical_retriever = lexical_retriever
        self._root = Path(index.root_path)

    def search_code(self, query: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for file_path in self.index.files:
            abs_path = self._root / file_path
            try:
                lines = abs_path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                lines = abs_path.read_text(encoding="latin-1").splitlines()
            except Exception:
                continue
            for line_no, line in enumerate(lines, start=1):
                if query.lower() in line.lower():
                    matches.append({"file": file_path, "line": line_no, "content": line.strip()})
        return matches[:50]

    def semantic_search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        if self.lexical_retriever is None:
            return []
        return self.lexical_retriever.search(query, top_k=top_k)

    def get_function_ast(self, function_name: str) -> dict[str, Any] | None:
        fn = self._find_function(function_name)
        return asdict(fn) if fn else None

    def get_class_ast(self, class_name: str) -> dict[str, Any] | None:
        for cls in self.index.classes:
            if cls.name == class_name:
                return asdict(cls)
        return None

    def get_callers(self, function_name: str) -> list[str]:
        return self.graph.get("callers", {}).get(function_name, [])

    def get_callees(self, function_name: str) -> list[str]:
        return self.graph.get("callees", {}).get(function_name, [])

    def trace_variable(self, variable: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for fn in self.index.functions:
            if variable in fn.variables:
                results.append({
                    "function": fn.name,
                    "class_name": fn.class_name,
                    "file": fn.file_path,
                    "location": asdict(fn.location) if fn.location else None,
                })
        return results

    def read_snippet(self, file_path: str, start_line: int, end_line: int) -> str:
        try:
            lines = (self._root / file_path).read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            lines = (self._root / file_path).read_text(encoding="latin-1").splitlines()
        selected = lines[max(0, start_line - 1): end_line]
        return "\n".join(selected)

    def list_files(self) -> list[str]:
        return self.index.files

    def summarize_repository(self) -> dict[str, Any]:
        return {
            "root_path": self.index.root_path,
            "dominant_language": self.index.language,
            "languages": self.index.metadata.get("languages", {}),
            "file_count": len(self.index.files),
            "function_count": len(self.index.functions),
            "class_count": len(self.index.classes),
            "chunk_count": len(self.index.chunks),
        }

    def _find_function(self, function_name: str) -> FunctionNode | None:
        for fn in self.index.functions:
            if fn.name == function_name:
                return fn
        return None
