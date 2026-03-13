from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CodeLocation:
    file_path: str
    start_line: int
    end_line: int


@dataclass
class FunctionNode:
    name: str
    file_path: str
    parameters: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    variables: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    location: CodeLocation | None = None
    return_type: str | None = None
    language: str | None = None


@dataclass
class ClassNode:
    name: str
    file_path: str
    methods: list[str] = field(default_factory=list)
    base_classes: list[str] = field(default_factory=list)
    location: CodeLocation | None = None
    language: str | None = None


@dataclass
class ImportNode:
    module: str
    alias: str | None = None
    file_path: str = ""
    location: CodeLocation | None = None
    language: str | None = None


@dataclass
class CodeChunk:
    chunk_id: str
    file_path: str
    content: str
    symbol_name: str | None = None
    kind: str = "code"
    location: CodeLocation | None = None
    language: str | None = None


@dataclass
class SecurityIssue:
    rule_id: str
    title: str
    severity: str
    file_path: str
    line: int
    evidence: str
    suggestion: str


@dataclass
class RepositoryIndex:
    language: str
    root_path: str
    functions: list[FunctionNode] = field(default_factory=list)
    classes: list[ClassNode] = field(default_factory=list)
    imports: list[ImportNode] = field(default_factory=list)

    # Code files that went through AST parsing
    files: list[str] = field(default_factory=list)

    # All non-ignored files in the repository
    all_files: list[str] = field(default_factory=list)

    chunks: list[CodeChunk] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)