from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from core.aci.executor import ACIExecutor
from core.aci.workspace import Workspace
from core.analysis.code_graph import CodeGraphBuilder
from core.analysis.language_detector import LanguageDetector
from core.analysis.vuln_rules import SecurityScanner
from core.config import Settings
from core.llm.azure_openai_client import AzureOpenAIToolAgentClient
from core.parsers.tree_sitter_parser import TreeSitterMultiLanguageParser
from core.retrieval.lexical_retriever import LexicalCodeRetriever
from core.tools.aci_tools import ACITools
from core.tools.repository_tools import RepositoryTools
from core.tools.tool_registry import ToolRegistry


CHAT_SYSTEM_PROMPT = """
You are a SWE-agent style coding agent operating through an Agent-Computer Interface (ACI).

You must interact with the uploaded repository through tools.
Do not answer substantive repository questions from prior assumptions.
Before giving a meaningful answer, first inspect the repository using tools.

For repository understanding:
- Prefer tree, find_entrypoints, grep_repo, and read_many_files over repeatedly reading one file at a time when possible.
- Use find_files when you only know part of a filename.

For risk analysis:
- Ground every claim in observed tool results.
- Before claiming a file is missing, verify it with list_dir, tree, or find_files.
- Before claiming a security or reliability issue exists, inspect the relevant files directly and use grep_repo or run_command when helpful.

For bug fixing and error localization:
- Before modifying a file, read it first.
- When the user asks for debugging, fixing, reproducing, or validating a bug, prefer this SOP:

  1. Inspect the suspected files and any relevant tests/configs.
  2. Create a minimal reproduction file under _aci_repro using create_repro_file.
  3. Run the reproduction with run_repro_test.
  4. Localize the buggy file/function from the repro result and file inspection.
  5. Edit the buggy file using apply_patch_candidate, replace_in_file, or write_file.
  6. Run run_repro_test again to check whether the bug is fixed.
  7. Run check_syntax and then run_verification when relevant.
  8. If the new patch makes things worse or fails, use revert_last_patch and try another fix.

- Prefer a reproduction-first workflow over blind patching.
- Do not claim a fix is correct unless the reproduction or verification result improved through tool use.
- Do not say you inspected, edited, or executed anything unless you actually did so through tools.

Be concise but concrete. Include paths, command outputs, and evidence.
""".strip()


ANALYZE_SYSTEM_PROMPT = """
You are a SWE-agent style repository investigator operating through an Agent-Computer Interface (ACI).

Your task is to analyze the uploaded repository through direct interaction with the workspace tools.

Important controller behavior:
- The outer controller may call you multiple times.
- Each call is one analysis pass.
- The per-pass tool limit applies only to the current pass, not to the whole repository analysis.
- If there are still relevant files or paths left to inspect, put them in next_targets.
- Prefer concrete file paths in next_targets whenever possible.
- Assume the controller will feed next_targets back to you and continue inspection automatically.

You must:
1. Inspect repository files through tools.
2. Progressively cover the repository, not just one small area.
3. Use next_targets as a work queue for continued inspection.
4. Only report risks grounded in observed evidence.
5. Return a STRICT JSON object as the final answer for the current pass.

Rules:
- Start by calling get_state unless the current pass already gives enough recent state.
- Use tree, list_dir, find_entrypoints, find_files, grep_repo, read_file, and read_many_files.
- Prefer batching with read_many_files when inspecting queued targets.
- If useful, create a repro file under _aci_repro and validate through run_repro_test.
- Use run_command only when it adds real value.
- Do not invent risks.
- Do not output markdown.
- Do not wrap the final answer in code fences.
- The final answer must be valid JSON matching this schema exactly:

{
  "summary": "short current-pass summary",
  "important_files": [
    "path/to/file1",
    "path/to/file2"
  ],
  "risks": [
    {
      "title": "short risk title",
      "severity": "low | medium | high | critical | unknown",
      "evidence": "grounded evidence from observed tool results"
    }
  ],
  "next_targets": [
    "path/or/topic to inspect next"
  ]
}
""".strip()


ANALYZE_USER_PROMPT = """
Analyze this repository through direct ACI interaction.

This analysis runs in multiple passes.
For this pass:
- inspect the assigned targets first,
- inspect additional important files if needed,
- return grounded risks,
- and return useful next_targets for the next pass.

If you find a likely bug path and a minimal reproduction is practical, you may:
- create a repro file under _aci_repro,
- run the repro,
- inspect the relevant buggy file,
- patch the file,
- and run the repro again to validate the fix.

Return only a valid JSON object following this schema:
{
  "summary": "short current-pass summary",
  "important_files": [
    "path/to/file1",
    "path/to/file2"
  ],
  "risks": [
    {
      "title": "short risk title",
      "severity": "low | medium | high | critical | unknown",
      "evidence": "grounded evidence from observed tool results"
    }
  ],
  "next_targets": [
    "path/or/topic to inspect next"
  ]
}
""".strip()


class ASTAwareSWEAgentV2:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

        self.detector = LanguageDetector()
        self.parser = TreeSitterMultiLanguageParser()
        self.graph_builder = CodeGraphBuilder()
        self.scanner = SecurityScanner()

        self.llm = AzureOpenAIToolAgentClient(self.settings) if self.settings.ready_for_chat else None

        self.lexical_retriever = None
        self.index = None
        self.repo_tools: RepositoryTools | None = None
        self.issues = []
        self.analysis: dict[str, Any] | None = None

        self.workspace: Workspace | None = None
        self.executor: ACIExecutor | None = None
        self.aci_tools: ACITools | None = None
        self.registry: ToolRegistry | None = None

    def analyze_repository(self, repo_path: str, analyze_tool_limit: int = 24) -> dict[str, Any]:
        index = self.parser.parse_repository(repo_path)
        graph = self.graph_builder.build(index)
        issues = self.scanner.scan(index)

        self.lexical_retriever = LexicalCodeRetriever(index.chunks)
        self.index = index
        self.repo_tools = RepositoryTools(index, graph, self.lexical_retriever)
        self.issues = issues

        self.workspace = Workspace(Path(repo_path))
        self.executor = ACIExecutor(self.workspace)
        self.aci_tools = ACITools(self.executor)
        self.registry = ToolRegistry(self.aci_tools)

        aci_analysis = self._run_iterative_aci_analysis(per_pass_tool_limit=analyze_tool_limit)

        self.analysis = {
            "language": index.language,
            "languages": index.metadata.get("languages", {}),
            "text_files": list(index.metadata.get("text_files", {}).keys()),
            "file_count": len(index.all_files),
            "indexed_code_file_count": len(index.files),
            "function_count": len(index.functions),
            "class_count": len(index.classes),
            "chunk_count": len(index.chunks),
            "issue_count": len(aci_analysis.get("risks", [])),
            "files": index.all_files,
            "indexed_code_files": index.files,
            "graph": graph,
            "issues": aci_analysis.get("risks", []),
            "analysis_summary": aci_analysis.get("summary", ""),
            "analysis_important_files": aci_analysis.get("important_files", []),
            "analysis_next_targets": aci_analysis.get("next_targets", []),
            "analysis_tool_trace": aci_analysis.get("tool_trace", []),
            "analysis_raw_answer": aci_analysis.get("raw_answer", ""),
            "analysis_passes": aci_analysis.get("passes", []),
            "analysis_pass_count": aci_analysis.get("pass_count", 0),
            "analysis_inspected_files": aci_analysis.get("inspected_files", []),
            "analysis_remaining_files": aci_analysis.get("remaining_files", []),
            "analysis_inspection_mode": "tool_trace_strict",
            "embedding_enabled": False,
            "retrieval_mode": "aci_only",
            "llm_enabled": self.llm is not None,
            "aci_enabled": True,
            "workspace_root": str(self.workspace.root),
            "analyze_tool_limit": analyze_tool_limit,
            "analyze_tool_limit_scope": "per_pass",
        }
        return self.analysis

    def _run_iterative_aci_analysis(self, per_pass_tool_limit: int = 24) -> dict[str, Any]:
        if self.registry is None or self.workspace is None:
            return {
                "summary": "Workspace is not initialized.",
                "important_files": [],
                "risks": [],
                "next_targets": [],
                "tool_trace": [],
                "raw_answer": "",
                "passes": [],
                "pass_count": 0,
                "inspected_files": [],
                "remaining_files": [],
            }

        if self.llm is None:
            return {
                "summary": "LLM is not configured, so ACI analysis could not run.",
                "important_files": [],
                "risks": [],
                "next_targets": [],
                "tool_trace": [],
                "raw_answer": "",
                "passes": [],
                "pass_count": 0,
                "inspected_files": [],
                "remaining_files": [],
            }

        all_files = list(self.index.all_files) if self.index is not None else []
        remaining_files = set(all_files)
        queued_targets: list[str] = []
        inspected_files: set[str] = set()
        aggregated_tool_trace: list[dict[str, Any]] = []
        pass_records: list[dict[str, Any]] = []

        aggregated_summary_parts: list[str] = []
        aggregated_important_files: list[str] = []
        aggregated_risks: list[dict[str, Any]] = []
        last_raw_answer = ""

        max_passes = max(8, len(all_files) * 2 if all_files else 12)

        if all_files:
            queued_targets.extend(all_files[: min(12, len(all_files))])

        for pass_index in range(max_passes):
            if not queued_targets and remaining_files:
                batch = sorted(remaining_files)[: min(12, len(remaining_files))]
                queued_targets.extend(batch)

            if not queued_targets and not remaining_files:
                break

            current_targets = self._dedupe_preserve_order(queued_targets)[:12]
            queued_targets = []

            pass_result = self._run_single_analysis_pass(
                assigned_targets=current_targets,
                already_inspected=sorted(inspected_files),
                per_pass_tool_limit=per_pass_tool_limit,
                pass_index=pass_index + 1,
            )

            parsed = pass_result["parsed"]
            pass_inspected_files = self._extract_inspected_files_from_tool_trace(
                pass_result["tool_trace"],
                all_files=all_files,
            )
            last_raw_answer = pass_result["raw_answer"]
            aggregated_tool_trace.extend(pass_result["tool_trace"])

            pass_records.append(
                {
                    "pass_index": pass_index + 1,
                    "assigned_targets": current_targets,
                    "inspected_files": sorted(pass_inspected_files),
                    "summary": parsed.get("summary", ""),
                    "important_files": parsed.get("important_files", []),
                    "risks": parsed.get("risks", []),
                    "next_targets": parsed.get("next_targets", []),
                    "raw_answer": pass_result["raw_answer"],
                }
            )

            if parsed.get("summary"):
                aggregated_summary_parts.append(parsed["summary"])

            aggregated_important_files = self._merge_unique_strings(
                aggregated_important_files,
                parsed.get("important_files", []),
            )

            aggregated_risks = self._merge_risks(
                aggregated_risks,
                parsed.get("risks", []),
            )

            touched_files = pass_inspected_files
            inspected_files.update(touched_files)
            remaining_files -= touched_files

            suggested_next = [
                x for x in parsed.get("next_targets", [])
                if isinstance(x, str) and x.strip()
            ]

            queued_targets.extend(
                x for x in suggested_next
                if x in remaining_files
            )

            if not queued_targets and remaining_files:
                fallback_batch = sorted(remaining_files)[: min(12, len(remaining_files))]
                queued_targets.extend(fallback_batch)

            if not remaining_files:
                break

        return {
            "summary": " | ".join(aggregated_summary_parts).strip(),
            "important_files": aggregated_important_files,
            "risks": aggregated_risks,
            "next_targets": sorted(remaining_files),
            "tool_trace": aggregated_tool_trace,
            "raw_answer": last_raw_answer,
            "passes": pass_records,
            "pass_count": len(pass_records),
            "inspected_files": sorted(inspected_files),
            "remaining_files": sorted(remaining_files),
        }

    def _run_single_analysis_pass(
        self,
        assigned_targets: list[str],
        already_inspected: list[str],
        per_pass_tool_limit: int,
        pass_index: int,
    ) -> dict[str, Any]:
        messages: list[dict[str, Any]] = [{"role": "system", "content": ANALYZE_SYSTEM_PROMPT}]

        try:
            initial_state = self.registry.execute("get_state", "{}")
            messages.append(
                {
                    "role": "system",
                    "content": "Initial workspace state:\n" + json.dumps(initial_state, ensure_ascii=False),
                }
            )
        except Exception:
            pass

        try:
            initial_tree = self.registry.execute(
                "tree",
                json.dumps({"path": ".", "max_depth": 3}, ensure_ascii=False),
            )
            messages.append(
                {
                    "role": "system",
                    "content": "Initial repository tree:\n" + json.dumps(initial_tree, ensure_ascii=False),
                }
            )
        except Exception:
            pass

        messages.append(
            {
                "role": "system",
                "content": (
                    f"Analysis pass #{pass_index}\n"
                    f"Assigned targets for this pass:\n{json.dumps(assigned_targets, ensure_ascii=False)}\n\n"
                    f"Already inspected files:\n{json.dumps(already_inspected[-100:], ensure_ascii=False)}"
                ),
            }
        )

        messages.append({"role": "user", "content": ANALYZE_USER_PROMPT})

        result = self._run_tool_loop(messages, max_tool_rounds=per_pass_tool_limit)
        final_text = result.get("answer", "")
        parsed = self._parse_analysis_json(final_text)

        return {
            "parsed": parsed,
            "raw_answer": final_text,
            "tool_trace": result.get("tool_trace", []),
        }

    def ask(
        self,
        user_question: str,
        memory_messages: list[dict[str, str]],
        chat_tool_limit: int = 28,
    ) -> dict[str, Any]:
        if self.registry is None or self.workspace is None:
            return {"error": "Analyze a repository first."}
        if self.llm is None:
            return {"error": "Azure OpenAI chat configuration is incomplete in .env."}

        messages: list[dict[str, Any]] = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]

        try:
            initial_state = self.registry.execute("get_state", "{}")
            messages.append({
                "role": "system",
                "content": "Initial workspace state:\n" + json.dumps(initial_state, ensure_ascii=False),
            })
        except Exception:
            pass

        try:
            initial_tree = self.registry.execute("tree", json.dumps({"path": ".", "max_depth": 3}, ensure_ascii=False))
            messages.append({
                "role": "system",
                "content": "Initial repository tree:\n" + json.dumps(initial_tree, ensure_ascii=False),
            })
        except Exception:
            pass

        messages.extend(memory_messages)
        messages.append({"role": "user", "content": user_question})

        result = self._run_tool_loop(messages, max_tool_rounds=chat_tool_limit)
        final_text = result.get("answer", "")

        if result.get("tool_trace"):
            evidence_lines = []
            for item in result["tool_trace"][-8:]:
                evidence_lines.append(f"- {item['tool_name']}({item['arguments']})")
            final_text = (
                "Observed repo interactions:\n"
                + "\n".join(evidence_lines)
                + "\n\n"
                + final_text
            )

        return {
            "answer": final_text,
            "tool_trace": result.get("tool_trace", []),
            "analysis": self.analysis,
            "issues": self.analysis.get("issues", []) if self.analysis else [],
            "conversation_append": [
                {"role": "user", "content": user_question},
                {"role": "assistant", "content": final_text},
            ],
        }

    def _run_tool_loop(self, messages: list[dict[str, Any]], max_tool_rounds: int = 40) -> dict[str, Any]:
        tool_trace: list[dict[str, Any]] = []
        seen_calls: set[tuple[str, str]] = set()

        for _ in range(max_tool_rounds):
            response = self.llm.create_chat_completion(
                messages=messages,
                tools=self.registry.openai_tools(),
            )
            msg = response.choices[0].message

            assistant_message: dict[str, Any] = {"role": "assistant"}
            if msg.content:
                assistant_message["content"] = msg.content
            if getattr(msg, "tool_calls", None):
                assistant_message["tool_calls"] = [tc.model_dump() for tc in msg.tool_calls]
            messages.append(assistant_message)

            if not getattr(msg, "tool_calls", None):
                return {
                    "answer": msg.content or "No content returned.",
                    "tool_trace": tool_trace,
                }

            stop_due_to_repeat = False

            for tool_call in msg.tool_calls:
                tool_name = tool_call.function.name
                arguments_json = tool_call.function.arguments or "{}"

                try:
                    canonical_args = json.dumps(
                        json.loads(arguments_json),
                        sort_keys=True,
                        ensure_ascii=False,
                    )
                except Exception:
                    canonical_args = arguments_json

                call_signature = (tool_name, canonical_args)

                if call_signature in seen_calls:
                    tool_result = {
                        "ok": False,
                        "error": "Repeated identical tool call blocked to avoid loops.",
                        "tool_name": tool_name,
                    }
                    stop_due_to_repeat = True
                else:
                    seen_calls.add(call_signature)
                    try:
                        tool_result = self.registry.execute(tool_name, arguments_json)
                    except Exception as e:
                        tool_result = {
                            "ok": False,
                            "error": f"{type(e).__name__}: {e}",
                            "tool_name": tool_name,
                        }

                try:
                    parsed_args = json.loads(arguments_json) if arguments_json else {}
                except Exception:
                    parsed_args = {"raw_arguments": arguments_json}

                tool_trace.append({
                    "tool_name": tool_name,
                    "arguments": parsed_args,
                    "result": tool_result,
                })

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(tool_result, ensure_ascii=False),
                })

            if stop_due_to_repeat:
                messages.append({
                    "role": "system",
                    "content": (
                        "You attempted a repeated identical tool call. "
                        "Do not repeat the same call. Use the available observations "
                        "to produce an answer or choose a different action."
                    ),
                })

        return {
            "answer": "Tool-calling loop exceeded the step limit for this pass.",
            "tool_trace": tool_trace,
        }

    def _parse_analysis_json(self, text: str) -> dict[str, Any]:
        if not text.strip():
            return {
                "summary": "",
                "important_files": [],
                "risks": [],
                "next_targets": [],
            }

        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("Analysis output is not a JSON object.")

            summary = data.get("summary", "")
            important_files = data.get("important_files", [])
            risks = data.get("risks", [])
            next_targets = data.get("next_targets", [])

            if not isinstance(summary, str):
                summary = str(summary)
            if not isinstance(important_files, list):
                important_files = []
            if not isinstance(risks, list):
                risks = []
            if not isinstance(next_targets, list):
                next_targets = []

            normalized_risks = []
            for item in risks:
                if isinstance(item, dict):
                    normalized_risks.append({
                        "title": str(item.get("title", "")),
                        "severity": str(item.get("severity", "unknown")),
                        "evidence": str(item.get("evidence", "")),
                    })

            return {
                "summary": summary,
                "important_files": [str(x) for x in important_files],
                "risks": normalized_risks,
                "next_targets": [str(x) for x in next_targets],
            }

        except Exception:
            return {
                "summary": text.strip(),
                "important_files": [],
                "risks": [],
                "next_targets": [],
            }

    def _extract_inspected_files_from_tool_trace(
        self,
        tool_trace: list[dict[str, Any]],
        all_files: list[str],
    ) -> set[str]:
        """
        Strongest inspection accounting:
        only count files that were actually touched by relevant tools.
        """
        all_files_set = set(all_files)
        inspected: set[str] = set()

        for item in tool_trace:
            if not isinstance(item, dict):
                continue

            tool_name = item.get("tool_name")
            arguments = item.get("arguments", {})
            result = item.get("result", {})

            if not isinstance(arguments, dict):
                arguments = {}
            if not isinstance(result, dict):
                result = {}

            if tool_name == "read_file":
                path = arguments.get("path")
                rel = self._normalize_repo_file_candidate(path, all_files_set)
                if rel:
                    inspected.add(rel)

            elif tool_name == "read_many_files":
                paths = arguments.get("paths", [])
                if isinstance(paths, list):
                    for path in paths:
                        rel = self._normalize_repo_file_candidate(path, all_files_set)
                        if rel:
                            inspected.add(rel)

                files_result = result.get("files", [])
                if isinstance(files_result, list):
                    for entry in files_result:
                        if not isinstance(entry, dict):
                            continue
                        rel = self._normalize_repo_file_candidate(entry.get("path"), all_files_set)
                        if rel:
                            inspected.add(rel)

            elif tool_name == "grep_repo":
                grep_path = arguments.get("path")
                if isinstance(grep_path, str) and grep_path.strip() and grep_path != ".":
                    rel = self._normalize_repo_file_candidate(grep_path, all_files_set)
                    if rel:
                        inspected.add(rel)

                grep_results = result.get("results", [])
                if isinstance(grep_results, list):
                    for entry in grep_results:
                        if not isinstance(entry, dict):
                            continue
                        rel = self._normalize_repo_file_candidate(entry.get("file_path"), all_files_set)
                        if rel:
                            inspected.add(rel)

            elif tool_name == "write_file":
                path = arguments.get("path")
                rel = self._normalize_repo_file_candidate(path, all_files_set)
                if rel:
                    inspected.add(rel)

            elif tool_name == "replace_in_file":
                path = arguments.get("path")
                rel = self._normalize_repo_file_candidate(path, all_files_set)
                if rel:
                    inspected.add(rel)

            elif tool_name == "apply_patch_candidate":
                changed_files = result.get("files_changed", [])
                if isinstance(changed_files, list):
                    for path in changed_files:
                        rel = self._normalize_repo_file_candidate(path, all_files_set)
                        if rel:
                            inspected.add(rel)

        return inspected

    def _normalize_repo_file_candidate(
        self,
        path: Any,
        all_files_set: set[str],
    ) -> str | None:
        """
        Normalize a tool-reported path into a repository-relative file path.
        Ignore non-repo files such as _aci_repro artifacts unless they are in all_files.
        """
        if not isinstance(path, str):
            return None

        cleaned = path.strip().replace("\\", "/")
        if not cleaned or cleaned == ".":
            return None

        while cleaned.startswith("./"):
            cleaned = cleaned[2:]
        cleaned = cleaned.lstrip("/")

        if cleaned in all_files_set:
            return cleaned

        if self.workspace is not None:
            try:
                rel = self.workspace.relpath(self.workspace.resolve_path(cleaned))
                if rel in all_files_set:
                    return rel
            except Exception:
                pass

        return None

    @staticmethod
    def _dedupe_preserve_order(items: list[str]) -> list[str]:
        seen = set()
        out = []
        for item in items:
            if not isinstance(item, str):
                continue
            item = item.strip()
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    @staticmethod
    def _merge_unique_strings(existing: list[str], new_items: list[str]) -> list[str]:
        seen = set(existing)
        merged = list(existing)
        for item in new_items:
            if isinstance(item, str) and item not in seen:
                seen.add(item)
                merged.append(item)
        return merged

    @staticmethod
    def _merge_risks(existing: list[dict[str, Any]], new_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged = list(existing)
        seen = {
            (
                item.get("title", ""),
                item.get("severity", ""),
                item.get("evidence", ""),
            )
            for item in existing
            if isinstance(item, dict)
        }

        for item in new_items:
            if not isinstance(item, dict):
                continue
            sig = (
                item.get("title", ""),
                item.get("severity", ""),
                item.get("evidence", ""),
            )
            if sig not in seen:
                seen.add(sig)
                merged.append(item)
        return merged

    def export_report(self) -> dict[str, Any]:
        if self.index is None:
            return {"error": "No repository analyzed."}

        return {
            "analysis": self.analysis,
            "issues": [asdict(issue) if hasattr(issue, "__dataclass_fields__") else issue for issue in self.issues],
            "repository_index": {
                "language": self.index.language,
                "root_path": self.index.root_path,
                "files": self.index.files,
                "all_files": self.index.all_files,
                "functions": [asdict(f) for f in self.index.functions],
                "classes": [asdict(c) for c in self.index.classes],
                "imports": [asdict(i) for i in self.index.imports],
                "chunks": [asdict(ch) for ch in self.index.chunks],
                "metadata": self.index.metadata,
            },
        }