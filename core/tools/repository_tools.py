from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from core.models.schema import RepositoryIndex
from core.retrieval.lexical_retriever import LexicalCodeRetriever


class RepositoryTools:
    def __init__(self, index: RepositoryIndex, graph: dict, lexical_retriever: LexicalCodeRetriever | None = None) -> None:
        self.index = index
        self.graph = graph
        self.lexical_retriever = lexical_retriever
        self._root = Path(index.root_path)

    def summarize_repository(self) -> dict[str, Any]:
        return {
            "language": self.index.language,
            "file_count": len(self.index.all_files),
            "indexed_code_file_count": len(self.index.files),
            "function_count": len(self.index.functions),
            "class_count": len(self.index.classes),
            "import_count": len(self.index.imports),
            "chunk_count": len(self.index.chunks),
            "text_file_count": len(self.index.metadata.get("text_files", {})),
        }

    def list_files(self) -> list[str]:
        return self.index.all_files

    def search_code(self, query: str, max_results: int = 50) -> list[dict[str, Any]]:
        query_lower = query.lower()
        results: list[dict[str, Any]] = []

        for file_path in self.index.all_files:
            abs_path = self._root / file_path
            if not abs_path.exists() or not abs_path.is_file():
                continue

            try:
                text = self._read_text(abs_path)
            except Exception:
                continue

            lines = text.splitlines()
            for i, line in enumerate(lines, start=1):
                if query_lower in line.lower():
                    results.append({
                        "file_path": file_path,
                        "line": i,
                        "content": line.strip(),
                    })
                    if len(results) >= max_results:
                        return results

        return results

    def semantic_search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        if self.lexical_retriever is None:
            return []
        return self.lexical_retriever.search(query, top_k=top_k)

    def get_function_ast(self, function_name: str) -> dict[str, Any] | None:
        for fn in self.index.functions:
            if fn.name == function_name:
                return asdict(fn)
        return None

    def get_class_ast(self, class_name: str) -> dict[str, Any] | None:
        for cls in self.index.classes:
            if cls.name == class_name:
                return asdict(cls)
        return None

    def get_callers(self, function_name: str) -> list[dict[str, Any]]:
        callers = []
        for fn in self.index.functions:
            if function_name in fn.calls:
                callers.append(asdict(fn))
        return callers

    def get_callees(self, function_name: str) -> list[str]:
        for fn in self.index.functions:
            if fn.name == function_name:
                return fn.calls
        return []

    def trace_variable(self, variable: str) -> list[dict[str, Any]]:
        matches = []
        for fn in self.index.functions:
            if variable in fn.variables:
                matches.append(asdict(fn))
        return matches

    def read_snippet(self, file_path: str, start_line: int, end_line: int) -> dict[str, Any]:
        abs_path = self._root / file_path
        if not abs_path.exists() or not abs_path.is_file():
            raise FileNotFoundError(file_path)

        text = self._read_text(abs_path)
        lines = text.splitlines()

        s = max(1, start_line)
        e = min(len(lines), end_line)

        return {
            "file_path": file_path,
            "start_line": s,
            "end_line": e,
            "content": "\n".join(lines[s - 1:e]),
        }

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1")