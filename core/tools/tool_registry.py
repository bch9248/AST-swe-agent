from __future__ import annotations

import json
from typing import Any, Callable

from core.tools.repository_tools import RepositoryTools


class ToolRegistry:
    def __init__(self, tools: RepositoryTools) -> None:
        self.tools = tools
        self._functions: dict[str, Callable[..., Any]] = {
            "search_code": tools.search_code,
            "semantic_search": tools.semantic_search,
            "get_function_ast": tools.get_function_ast,
            "get_class_ast": tools.get_class_ast,
            "get_callers": tools.get_callers,
            "get_callees": tools.get_callees,
            "trace_variable": tools.trace_variable,
            "read_snippet": tools.read_snippet,
            "list_files": tools.list_files,
            "summarize_repository": tools.summarize_repository,
        }

    def openai_tools(self) -> list[dict[str, Any]]:
        return [
            self._tool_def("summarize_repository", "Get repository-level summary.", {"type": "object", "properties": {}, "additionalProperties": False}),
            self._tool_def("list_files", "List repository files.", {"type": "object", "properties": {}, "additionalProperties": False}),
            self._tool_def("search_code", "Keyword search across the repository.", {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            }),
            self._tool_def("semantic_search", "Search relevant code chunks using lexical matching over code, symbols, and file context.", {
                "type": "object",
                "properties": {"query": {"type": "string"}, "top_k": {"type": "integer", "default": 5}},
                "required": ["query"],
                "additionalProperties": False,
            }),
            self._tool_def("get_function_ast", "Return normalized AST-like metadata for one function.", {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"],
                "additionalProperties": False,
            }),
            self._tool_def("get_class_ast", "Return normalized AST-like metadata for one class.", {
                "type": "object",
                "properties": {"class_name": {"type": "string"}},
                "required": ["class_name"],
                "additionalProperties": False,
            }),
            self._tool_def("get_callers", "List callers of a function.", {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"],
                "additionalProperties": False,
            }),
            self._tool_def("get_callees", "List callees of a function.", {
                "type": "object",
                "properties": {"function_name": {"type": "string"}},
                "required": ["function_name"],
                "additionalProperties": False,
            }),
            self._tool_def("trace_variable", "Trace where a variable name appears in normalized function metadata.", {
                "type": "object",
                "properties": {"variable": {"type": "string"}},
                "required": ["variable"],
                "additionalProperties": False,
            }),
            self._tool_def("read_snippet", "Read source lines from a file.", {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                },
                "required": ["file_path", "start_line", "end_line"],
                "additionalProperties": False,
            }),
        ]

    def execute(self, tool_name: str, arguments_json: str) -> Any:
        fn = self._functions[tool_name]
        args = json.loads(arguments_json) if arguments_json else {}
        return fn(**args)

    @staticmethod
    def _tool_def(name: str, description: str, parameters: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters,
            },
        }
