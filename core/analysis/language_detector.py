from __future__ import annotations

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

TEXT_LIKE_EXTENSION_MAP = {
    ".md": "markdown",
    ".txt": "text",
    ".rst": "text",
    ".log": "text",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "config",
    ".csv": "csv",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
    ".sql": "sql",
    ".sh": "shell",
    ".bat": "batch",
    ".ps1": "powershell",
}

TEXT_LIKE_FILENAMES = {
    "readme",
    "license",
    "licence",
    "copying",
    "authors",
    "contributors",
    "changelog",
    "changes",
    "makefile",
    "dockerfile",
    ".gitignore",
    ".dockerignore",
    ".env",
}


class LanguageDetector:
    IGNORE_DIRS = {
        ".git",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".venv",
        "venv",
        ".mypy_cache",
        ".pytest_cache",
        ".idea",
        ".vscode",
        ".next",
        ".cache",
    }

    IGNORE_FILE_SUFFIXES = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".webp",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".7z",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".pyc",
        ".class",
        ".jar",
        ".o",
        ".obj",
        ".a",
        ".lib",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
    }

    def _is_ignored(self, path: Path, root: Path) -> bool:
        rel_parts = path.relative_to(root).parts
        if any(part in self.IGNORE_DIRS for part in rel_parts):
            return True
        if path.suffix.lower() in self.IGNORE_FILE_SUFFIXES:
            return True
        return False

    def detect_per_file(self, repo_path: str) -> dict[str, str]:
        """
        Code files that should go through AST parsing.
        """
        root = Path(repo_path)
        mapping: dict[str, str] = {}

        for path in root.rglob("*"):
            if not path.is_file() or self._is_ignored(path, root):
                continue
            lang = EXTENSION_LANGUAGE_MAP.get(path.suffix.lower())
            if lang:
                mapping[str(path.relative_to(root))] = lang

        return mapping

    def detect_text_like_files(self, repo_path: str) -> dict[str, str]:
        """
        Text-like files that should be visible/searchable/readable,
        but not AST-parsed as code.
        """
        root = Path(repo_path)
        mapping: dict[str, str] = {}

        for path in root.rglob("*"):
            if not path.is_file() or self._is_ignored(path, root):
                continue

            rel = str(path.relative_to(root))
            suffix = path.suffix.lower()
            name_lower = path.name.lower()

            lang = TEXT_LIKE_EXTENSION_MAP.get(suffix)
            if lang:
                mapping[rel] = lang
                continue

            if name_lower in TEXT_LIKE_FILENAMES:
                if name_lower == "makefile":
                    mapping[rel] = "makefile"
                elif name_lower == "dockerfile":
                    mapping[rel] = "dockerfile"
                else:
                    mapping[rel] = "text"

        return mapping

    def detect_all_files(self, repo_path: str) -> list[str]:
        """
        All non-ignored files in the repository.
        """
        root = Path(repo_path)
        files: list[str] = []

        for path in root.rglob("*"):
            if not path.is_file() or self._is_ignored(path, root):
                continue
            files.append(str(path.relative_to(root)))

        return sorted(files)

    def detect_dominant(self, repo_path: str) -> str:
        mapping = self.detect_per_file(repo_path)
        if not mapping:
            return "unknown"

        counts: dict[str, int] = {}
        for _, lang in mapping.items():
            counts[lang] = counts.get(lang, 0) + 1

        return max(counts.items(), key=lambda x: x[1])[0]