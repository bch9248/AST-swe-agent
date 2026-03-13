from __future__ import annotations

import json
from typing import Any, Callable

from core.tools.aci_tools import ACITools


class ToolRegistry:
    """
    ACI-only tool registry.

    The LLM can only interact with the uploaded repository through direct
    workspace tools. AST/retrieval tools are intentionally hidden.
    """

    def __init__(self, aci_tools: ACITools) -> None:
        self.aci_tools = aci_tools

        self._functions: dict[str, Callable[..., Any]] = {
            "get_state": aci_tools.get_state,
            "list_dir": aci_tools.list_dir,
            "tree": aci_tools.tree,
            "find_files": aci_tools.find_files,
            "grep_repo": aci_tools.grep_repo,
            "find_entrypoints": aci_tools.find_entrypoints,
            "read_file": aci_tools.read_file,
            "read_many_files": aci_tools.read_many_files,
            "write_file": aci_tools.write_file,
            "append_to_file": aci_tools.append_to_file,
            "replace_in_file": aci_tools.replace_in_file,
            "change_dir": aci_tools.change_dir,
            "run_command": aci_tools.run_command,
            "apply_patch_candidate": aci_tools.apply_patch_candidate,
            "check_syntax": aci_tools.check_syntax,
            "run_verification": aci_tools.run_verification,
            "revert_last_patch": aci_tools.revert_last_patch,
            "get_last_patch_diff": aci_tools.get_last_patch_diff,
        }

    def openai_tools(self) -> list[dict[str, Any]]:
        return [
            self._tool_def(
                "get_state",
                "Get current workspace execution state.",
                {"type": "object", "properties": {}, "additionalProperties": False},
            ),
            self._tool_def(
                "list_dir",
                "List files/directories in the workspace.",
                {
                    "type": "object",
                    "properties": {"path": {"type": "string", "default": "."}},
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "tree",
                "Get a recursive tree-like view of the repository.",
                {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "default": "."},
                        "max_depth": {"type": "integer", "default": 3},
                        "max_entries": {"type": "integer", "default": 300},
                    },
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "find_files",
                "Find files by name substring in the workspace.",
                {
                    "type": "object",
                    "properties": {"pattern": {"type": "string"}},
                    "required": ["pattern"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "grep_repo",
                "Search for a text pattern across repository files.",
                {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "path": {"type": "string", "default": "."},
                        "max_results": {"type": "integer", "default": 50},
                    },
                    "required": ["pattern"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "find_entrypoints",
                "Find likely important files such as README, requirements, package configs, Dockerfiles, app entrypoints, and test files.",
                {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "read_file",
                "Read a file directly from the workspace.",
                {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "read_many_files",
                "Read multiple files in one call.",
                {
                    "type": "object",
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "max_chars_per_file": {"type": "integer", "default": 8000},
                    },
                    "required": ["paths"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "write_file",
                "Write a full file in the workspace.",
                {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "append_to_file",
                "Append content to a file in the workspace.",
                {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "replace_in_file",
                "Replace text in a file in the workspace.",
                {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "old": {"type": "string"},
                        "new": {"type": "string"},
                        "count": {"type": "integer", "default": 1},
                    },
                    "required": ["path", "old", "new"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "change_dir",
                "Change current working directory within the workspace.",
                {
                    "type": "object",
                    "properties": {"path": {"type": "string", "default": "."}},
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "run_command",
                "Run a safe, workspace-scoped shell command.",
                {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "timeout_sec": {"type": "integer", "default": 20},
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "apply_patch_candidate",
                "Apply a unified-diff patch candidate to the workspace. Use this before syntax or verification checks when testing a fix.",
                {
                    "type": "object",
                    "properties": {
                        "diff_text": {"type": "string"},
                    },
                    "required": ["diff_text"],
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "check_syntax",
                "Check syntax/compilability for supported files after a patch. Useful before broader verification.",
                {
                    "type": "object",
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": {"type": "string"},
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "run_verification",
                "Run verification after a patch. If no command is provided, infer a likely verification command from the repository.",
                {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "revert_last_patch",
                "Revert the most recently applied patch candidate. Use this if syntax or verification fails.",
                {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
            self._tool_def(
                "get_last_patch_diff",
                "Get the exact last applied patch diff and changed files.",
                {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            ),
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