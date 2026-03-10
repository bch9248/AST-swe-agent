from __future__ import annotations

from collections import Counter
from pathlib import Path


EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".java": "java",
    ".go": "go",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}


class LanguageDetector:
    def detect_dominant(self, repo_path: str) -> str:
        root = Path(repo_path)
        counts: Counter[str] = Counter()
        for path in root.rglob("*"):
            if not path.is_file() or self._is_ignored(path):
                continue
            lang = EXTENSION_LANGUAGE_MAP.get(path.suffix.lower())
            if lang:
                counts[lang] += 1
        return counts.most_common(1)[0][0] if counts else "unknown"

    def detect_per_file(self, repo_path: str) -> dict[str, str]:
        root = Path(repo_path)
        mapping: dict[str, str] = {}
        for path in root.rglob("*"):
            if not path.is_file() or self._is_ignored(path):
                continue
            lang = EXTENSION_LANGUAGE_MAP.get(path.suffix.lower())
            if lang:
                mapping[str(path.relative_to(root))] = lang
        return mapping

    @staticmethod
    def _is_ignored(path: Path) -> bool:
        ignored_parts = {".git", "node_modules", ".venv", "venv", "build", "dist", "__pycache__"}
        return any(part in ignored_parts for part in path.parts)
