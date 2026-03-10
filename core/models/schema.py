from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class CodeLocation:
    file_path: str
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0


@dataclass
class FunctionNode:
    name: str
    file_path: str
    parameters: list[str]
    calls: list[str] = field(default_factory=list)
    variables: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    return_type: Optional[str] = None
    docstring: Optional[str] = None
    location: Optional[CodeLocation] = None
    raw_kind: str = "function"
    class_name: Optional[str] = None


@dataclass
class ClassNode:
    name: str
    file_path: str
    methods: list[str] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    docstring: Optional[str] = None
    location: Optional[CodeLocation] = None


@dataclass
class ImportNode:
    module: str
    names: list[str]
    file_path: str
    location: Optional[CodeLocation] = None


@dataclass
class Issue:
    issue_type: str
    severity: str
    cwe: str
    message: str
    evidence: str
    location: CodeLocation
    remediation: str


@dataclass
class CodeChunk:
    chunk_id: str
    file_path: str
    content: str
    symbol_name: Optional[str]
    kind: str
    location: CodeLocation
    language: str


@dataclass
class RepositoryIndex:
    language: str
    root_path: str
    functions: list[FunctionNode] = field(default_factory=list)
    classes: list[ClassNode] = field(default_factory=list)
    imports: list[ImportNode] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    chunks: list[CodeChunk] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def function_map(self) -> dict[str, FunctionNode]:
        return {f"{Path(fn.file_path).name}:{fn.name}": fn for fn in self.functions}
