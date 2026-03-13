from __future__ import annotations

import re
from pathlib import Path

from tree_sitter_language_pack import get_parser

from core.analysis.language_detector import LanguageDetector
from core.models.schema import (
    ClassNode,
    CodeChunk,
    CodeLocation,
    FunctionNode,
    ImportNode,
    RepositoryIndex,
)


class TreeSitterMultiLanguageParser:
    """
    Multi-language parser for code files plus text-file chunking for docs/configs.
    """

    def __init__(self) -> None:
        self.detector = LanguageDetector()

    def parse_repository(self, repo_path: str) -> RepositoryIndex:
        root = Path(repo_path)

        code_file_langs = self.detector.detect_per_file(repo_path)
        text_file_langs = self.detector.detect_text_like_files(repo_path)
        all_files = self.detector.detect_all_files(repo_path)
        dominant = self.detector.detect_dominant(repo_path)

        index = RepositoryIndex(language=dominant, root_path=str(root.resolve()))
        index.files = sorted(code_file_langs.keys())
        index.all_files = all_files
        index.metadata["languages"] = code_file_langs
        index.metadata["text_files"] = text_file_langs

        # AST-parse code files
        for rel_path, lang in code_file_langs.items():
            abs_path = root / rel_path
            try:
                source = self._read_text(abs_path)
            except Exception:
                continue

            try:
                parser = get_parser(lang)
            except Exception:
                continue

            tree = parser.parse(source.encode("utf-8", errors="ignore"))
            root_node = tree.root_node

            self._extract_imports(index, root_node, rel_path, lang, source)
            self._extract_functions(index, root_node, rel_path, lang, source)
            self._extract_classes(index, root_node, rel_path, lang, source)
            self._extract_code_chunks(index, rel_path, lang, source)

        # Add searchable chunks for text-like files
        for rel_path, lang in text_file_langs.items():
            abs_path = root / rel_path
            try:
                text = self._read_text(abs_path)
            except Exception:
                continue

            self._extract_text_chunks(index, rel_path, lang, text)

        return index

    def _extract_imports(self, index: RepositoryIndex, root_node, rel_path: str, lang: str, source: str) -> None:
        lines = source.splitlines()

        for node in root_node.children:
            node_type = node.type
            if node_type in {
                "import_statement",
                "import_declaration",
                "import_from_statement",
            }:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                snippet = "\n".join(lines[start_line - 1:end_line]).strip()

                index.imports.append(
                    ImportNode(
                        module=snippet,
                        file_path=rel_path,
                        location=CodeLocation(rel_path, start_line, end_line),
                        language=lang,
                    )
                )

    def _extract_functions(self, index: RepositoryIndex, root_node, rel_path: str, lang: str, source: str) -> None:
        lines = source.splitlines()
        query_types = {"function_definition", "function_declaration", "method_definition"}

        for node in self._walk(root_node):
            if node.type not in query_types:
                continue

            name = self._extract_symbol_name(node, source) or f"anonymous_{node.start_point[0] + 1}"
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            snippet = "\n".join(lines[start_line - 1:end_line])

            calls = self._extract_calls_from_text(snippet)
            variables = self._extract_variables_from_text(snippet)

            index.functions.append(
                FunctionNode(
                    name=name,
                    file_path=rel_path,
                    parameters=[],
                    calls=calls,
                    variables=variables,
                    decorators=[],
                    location=CodeLocation(rel_path, start_line, end_line),
                    return_type=None,
                    language=lang,
                )
            )

    def _extract_classes(self, index: RepositoryIndex, root_node, rel_path: str, lang: str, source: str) -> None:
        query_types = {"class_definition", "class_declaration"}

        for node in self._walk(root_node):
            if node.type not in query_types:
                continue

            name = self._extract_symbol_name(node, source) or f"class_{node.start_point[0] + 1}"
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1

            index.classes.append(
                ClassNode(
                    name=name,
                    file_path=rel_path,
                    methods=[],
                    base_classes=[],
                    location=CodeLocation(rel_path, start_line, end_line),
                    language=lang,
                )
            )

    def _extract_code_chunks(self, index: RepositoryIndex, rel_path: str, lang: str, source: str) -> None:
        lines = source.splitlines()
        if not lines:
            return

        window = 80
        start = 1
        while start <= len(lines):
            end = min(len(lines), start + window - 1)
            content = "\n".join(lines[start - 1:end])
            index.chunks.append(
                CodeChunk(
                    chunk_id=f"{rel_path}::code::{start}",
                    file_path=rel_path,
                    content=content,
                    symbol_name=None,
                    kind="code",
                    location=CodeLocation(rel_path, start, end),
                    language=lang,
                )
            )
            start = end + 1

    def _extract_text_chunks(self, index: RepositoryIndex, rel_path: str, lang: str, text: str) -> None:
        lines = text.splitlines()
        if not lines:
            return

        window = 80
        start = 1
        while start <= len(lines):
            end = min(len(lines), start + window - 1)
            content = "\n".join(lines[start - 1:end])
            index.chunks.append(
                CodeChunk(
                    chunk_id=f"{rel_path}::text::{start}",
                    file_path=rel_path,
                    content=content,
                    symbol_name=None,
                    kind="text",
                    location=CodeLocation(rel_path, start, end),
                    language=lang,
                )
            )
            start = end + 1

    def _extract_symbol_name(self, node, source: str) -> str | None:
        for child in node.children:
            if child.type == "identifier":
                return source[child.start_byte:child.end_byte]
        return None

    def _extract_calls_from_text(self, snippet: str) -> list[str]:
        call_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        blacklist = {"if", "for", "while", "switch", "return", "catch", "def", "class"}
        out = []
        for m in call_pattern.finditer(snippet):
            name = m.group(1)
            if name not in blacklist:
                out.append(name)
        return sorted(set(out))

    def _extract_variables_from_text(self, snippet: str) -> list[str]:
        token_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
        blacklist = {
            "def", "class", "return", "if", "else", "elif", "for", "while",
            "import", "from", "try", "except", "finally", "with", "pass",
            "break", "continue", "true", "false", "none",
        }
        tokens = [m.group(1) for m in token_pattern.finditer(snippet)]
        return sorted({t for t in tokens if t.lower() not in blacklist})

    def _walk(self, node):
        yield node
        for child in node.children:
            yield from self._walk(child)

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1")