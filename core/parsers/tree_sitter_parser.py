from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tree_sitter import Node

try:
    from tree_sitter_language_pack import get_language, get_parser
except Exception:  # pragma: no cover
    get_language = None
    get_parser = None

from core.analysis.language_detector import LanguageDetector
from core.models.schema import ClassNode, CodeChunk, CodeLocation, FunctionNode, ImportNode, RepositoryIndex


SUPPORTED_LANGUAGES = {"python", "c", "cpp", "java", "go", "javascript", "typescript"}
FUNCTION_TYPES = {
    "python": {"function_definition", "decorated_definition"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "java": {"method_declaration", "constructor_declaration"},
    "go": {"function_declaration", "method_declaration"},
    "javascript": {"function_declaration", "method_definition", "generator_function_declaration"},
    "typescript": {"function_declaration", "method_definition", "generator_function_declaration"},
}
CLASS_TYPES = {
    "python": {"class_definition"},
    "java": {"class_declaration", "interface_declaration"},
    "javascript": {"class_declaration"},
    "typescript": {"class_declaration", "interface_declaration"},
    "cpp": {"class_specifier", "struct_specifier"},
}
IMPORT_TYPES = {
    "python": {"import_statement", "import_from_statement"},
    "javascript": {"import_statement"},
    "typescript": {"import_statement"},
    "go": {"import_declaration"},
}
CALL_TYPES = {
    "python": {"call"},
    "javascript": {"call_expression"},
    "typescript": {"call_expression"},
    "java": {"method_invocation"},
    "go": {"call_expression"},
    "c": {"call_expression"},
    "cpp": {"call_expression"},
}
IDENTIFIER_TYPES = {
    "python": {"identifier"},
    "javascript": {"identifier", "property_identifier"},
    "typescript": {"identifier", "property_identifier", "type_identifier"},
    "java": {"identifier", "type_identifier"},
    "go": {"identifier", "field_identifier"},
    "c": {"identifier", "field_identifier", "type_identifier"},
    "cpp": {"identifier", "field_identifier", "type_identifier", "namespace_identifier"},
}


@dataclass
class ParseContext:
    root: Path
    file_path: str
    language: str
    content: bytes


class TreeSitterMultiLanguageParser:
    def __init__(self) -> None:
        if get_parser is None:
            raise RuntimeError(
                "tree-sitter parser backend is unavailable. Install tree-sitter-language-pack."
            )
        self.detector = LanguageDetector()

    def parse_repository(self, repo_path: str) -> RepositoryIndex:
        root = Path(repo_path)
        file_langs = self.detector.detect_per_file(repo_path)
        dominant = self.detector.detect_dominant(repo_path)
        index = RepositoryIndex(language=dominant, root_path=str(root.resolve()))
        index.files = sorted(file_langs.keys())
        index.metadata["languages"] = file_langs

        for rel_path, language in file_langs.items():
            if language not in SUPPORTED_LANGUAGES:
                continue
            abs_path = root / rel_path
            try:
                text = abs_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = abs_path.read_text(encoding="latin-1")
            content = text.encode("utf-8")
            parser = get_parser(language)
            tree = parser.parse(content)
            ctx = ParseContext(root=root, file_path=rel_path, language=language, content=content)

            funcs, classes, imports = self._extract_symbols(tree.root_node, ctx)
            index.functions.extend(funcs)
            index.classes.extend(classes)
            index.imports.extend(imports)
            index.chunks.extend(self._build_chunks(tree.root_node, ctx, funcs, classes))

        self._attach_methods(index)
        return index

    def _extract_symbols(self, root: Node, ctx: ParseContext) -> tuple[list[FunctionNode], list[ClassNode], list[ImportNode]]:
        functions: list[FunctionNode] = []
        classes: list[ClassNode] = []
        imports: list[ImportNode] = []

        def walk(node: Node, current_class: Optional[str] = None) -> None:
            raw_type = node.type
            normalized_type = self._unwrap_decorated_type(node, ctx.language)

            if normalized_type in CLASS_TYPES.get(ctx.language, set()):
                class_name = self._extract_name(node, ctx)
                cls = ClassNode(
                    name=class_name or "<anonymous_class>",
                    file_path=ctx.file_path,
                    bases=self._extract_bases(node, ctx),
                    location=self._loc(node, ctx.file_path),
                )
                classes.append(cls)
                next_class = cls.name
            else:
                next_class = current_class

            if normalized_type in FUNCTION_TYPES.get(ctx.language, set()):
                functions.append(self._build_function_node(node, ctx, current_class))

            if raw_type in IMPORT_TYPES.get(ctx.language, set()):
                imports.append(ImportNode(
                    module=self._node_text(node, ctx).strip(),
                    names=[],
                    file_path=ctx.file_path,
                    location=self._loc(node, ctx.file_path),
                ))

            for child in node.children:
                walk(child, next_class)

        walk(root)
        return functions, classes, imports

    def _build_function_node(self, node: Node, ctx: ParseContext, current_class: Optional[str]) -> FunctionNode:
        name = self._extract_name(node, ctx) or "<anonymous_function>"
        params = self._extract_parameters(node, ctx)
        body_node = self._find_body_node(node)
        calls = self._extract_calls(body_node or node, ctx)
        variables = self._extract_variables(body_node or node, ctx)
        return FunctionNode(
            name=name,
            file_path=ctx.file_path,
            parameters=params,
            calls=calls,
            variables=variables,
            location=self._loc(node, ctx.file_path),
            raw_kind=node.type,
            class_name=current_class,
        )

    def _build_chunks(
        self,
        root: Node,
        ctx: ParseContext,
        functions: list[FunctionNode],
        classes: list[ClassNode],
    ) -> list[CodeChunk]:
        chunks: list[CodeChunk] = []
        for fn in functions:
            if not fn.location:
                continue
            chunks.append(CodeChunk(
                chunk_id=f"{ctx.file_path}::function::{fn.name}::{fn.location.start_line}",
                file_path=ctx.file_path,
                content=self._slice_lines(ctx, fn.location.start_line, fn.location.end_line),
                symbol_name=fn.name,
                kind="function",
                location=fn.location,
                language=ctx.language,
            ))
        for cls in classes:
            if not cls.location:
                continue
            chunks.append(CodeChunk(
                chunk_id=f"{ctx.file_path}::class::{cls.name}::{cls.location.start_line}",
                file_path=ctx.file_path,
                content=self._slice_lines(ctx, cls.location.start_line, cls.location.end_line),
                symbol_name=cls.name,
                kind="class",
                location=cls.location,
                language=ctx.language,
            ))
        if not chunks:
            total_lines = len(ctx.content.decode("utf-8", errors="ignore").splitlines())
            if total_lines:
                chunks.extend(self._fallback_line_chunks(ctx, total_lines))
        return chunks

    def _fallback_line_chunks(self, ctx: ParseContext, total_lines: int, window: int = 60) -> list[CodeChunk]:
        chunks: list[CodeChunk] = []
        start = 1
        while start <= total_lines:
            end = min(total_lines, start + window - 1)
            loc = CodeLocation(file_path=ctx.file_path, start_line=start, end_line=end)
            chunks.append(CodeChunk(
                chunk_id=f"{ctx.file_path}::window::{start}",
                file_path=ctx.file_path,
                content=self._slice_lines(ctx, start, end),
                symbol_name=None,
                kind="window",
                location=loc,
                language=ctx.language,
            ))
            start = end + 1
        return chunks

    def _attach_methods(self, index: RepositoryIndex) -> None:
        class_map = {cls.name: cls for cls in index.classes}
        for fn in index.functions:
            if fn.class_name and fn.class_name in class_map:
                class_map[fn.class_name].methods.append(fn.name)

    def _unwrap_decorated_type(self, node: Node, language: str) -> str:
        if language == "python" and node.type == "decorated_definition":
            child = node.child_by_field_name("definition")
            return child.type if child else node.type
        return node.type

    def _extract_name(self, node: Node, ctx: ParseContext) -> Optional[str]:
        for field in ("name", "declarator"):
            child = node.child_by_field_name(field)
            if child:
                if field == "declarator":
                    ident = self._find_first_identifier(child, ctx.language)
                    return self._node_text(ident, ctx) if ident else self._node_text(child, ctx)
                return self._node_text(child, ctx)
        ident = self._find_first_identifier(node, ctx.language)
        return self._node_text(ident, ctx) if ident else None

    def _extract_parameters(self, node: Node, ctx: ParseContext) -> list[str]:
        params: list[str] = []
        for field in ("parameters",):
            child = node.child_by_field_name(field)
            if child:
                for ident in self._iter_identifiers(child, ctx.language):
                    value = self._node_text(ident, ctx)
                    if value not in params:
                        params.append(value)
        return params

    def _extract_bases(self, node: Node, ctx: ParseContext) -> list[str]:
        bases: list[str] = []
        for field in ("superclasses", "bases", "type_parameters"):
            child = node.child_by_field_name(field)
            if child:
                for ident in self._iter_identifiers(child, ctx.language):
                    value = self._node_text(ident, ctx)
                    if value not in bases:
                        bases.append(value)
        return bases

    def _extract_calls(self, node: Node, ctx: ParseContext) -> list[str]:
        calls: list[str] = []
        call_types = CALL_TYPES.get(ctx.language, set())

        def walk(cur: Node) -> None:
            if cur.type in call_types:
                target = cur.child_by_field_name("function") or cur.child_by_field_name("name")
                if target is None and cur.children:
                    target = cur.children[0]
                if target is not None:
                    ident = self._find_first_identifier(target, ctx.language)
                    text = self._node_text(ident or target, ctx).strip()
                    if text:
                        calls.append(text)
            for child in cur.children:
                walk(child)

        walk(node)
        return sorted(set(calls))

    def _extract_variables(self, node: Node, ctx: ParseContext) -> list[str]:
        vars_found: list[str] = []
        for ident in self._iter_identifiers(node, ctx.language):
            text = self._node_text(ident, ctx)
            if text.isidentifier() and text not in vars_found:
                vars_found.append(text)
        return vars_found

    def _find_body_node(self, node: Node) -> Optional[Node]:
        for field in ("body",):
            child = node.child_by_field_name(field)
            if child is not None:
                return child
        for child in node.children:
            if child.type in {"block", "statement_block", "suite"}:
                return child
        return None

    def _iter_identifiers(self, node: Node, language: str):
        id_types = IDENTIFIER_TYPES.get(language, {"identifier"})
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur.type in id_types:
                yield cur
            stack.extend(reversed(cur.children))

    def _find_first_identifier(self, node: Node, language: str) -> Optional[Node]:
        return next(self._iter_identifiers(node, language), None)

    def _node_text(self, node: Node, ctx: ParseContext) -> str:
        return ctx.content[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def _slice_lines(self, ctx: ParseContext, start_line: int, end_line: int) -> str:
        lines = ctx.content.decode("utf-8", errors="ignore").splitlines()
        return "\n".join(lines[max(0, start_line - 1): end_line])

    def _loc(self, node: Node, file_path: str) -> CodeLocation:
        return CodeLocation(
            file_path=file_path,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            start_col=node.start_point[1],
            end_col=node.end_point[1],
        )
