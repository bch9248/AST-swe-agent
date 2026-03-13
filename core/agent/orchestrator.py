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

For fix proposals:
- Before modifying a file, read it first.
- Prefer this safer patch workflow when suggesting a concrete fix:
  1. apply_patch_candidate
  2. check_syntax
  3. run_verification
  4. if verification fails, revert_last_patch
  5. inspect get_last_patch_diff when needed
- After modifying a file, run a relevant verification command when possible.
- Do not say you inspected, edited, or executed anything unless you actually did so through tools.

Be concise but concrete. Include paths, command outputs, and evidence.
""".strip()


ANALYZE_SYSTEM_PROMPT = """
You are a SWE-agent style repository investigator operating through an Agent-Computer Interface (ACI).

Your task is to analyze the uploaded repository through direct interaction with the workspace tools.

You must:
1. Inspect the repository structure through tools.
2. Identify important files such as README, requirements, configs, entrypoints, scripts, and source directories.
3. Summarize the repository structure and likely purpose.
4. Identify potential security or reliability risks only if they are grounded in observed evidence from tool interactions.
5. Return a STRICT JSON object as the final answer.

Rules:
- Start by calling get_state.
- Then inspect the repository root with tree or list_dir.
- Use find_entrypoints, find_files, grep_repo, read_file, and read_many_files to inspect important docs/configs/source files.
- Use run_command only when it adds real value.
- Do not invent risks. Every risk must cite observed evidence.
- If you are uncertain, say so.
- Do not output markdown.
- Do not wrap the final answer in code fences.
- The final answer must be valid JSON matching this schema exactly:

{
  "summary": "short repository summary",
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

You must use tools before answering.

Return only a valid JSON object following this schema:
{
  "summary": "short repository summary",
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

        aci_analysis = self._run_aci_analysis(max_tool_rounds=analyze_tool_limit)

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
            "embedding_enabled": False,
            "retrieval_mode": "aci_only",
            "llm_enabled": self.llm is not None,
            "aci_enabled": True,
            "workspace_root": str(self.workspace.root),
            "analyze_tool_limit": analyze_tool_limit,
        }
        return self.analysis

    def _run_aci_analysis(self, max_tool_rounds: int = 24) -> dict[str, Any]:
        if self.registry is None or self.workspace is None:
            return {
                "summary": "Workspace is not initialized.",
                "important_files": [],
                "risks": [],
                "next_targets": [],
                "tool_trace": [],
                "raw_answer": "",
            }
        if self.llm is None:
            return {
                "summary": "LLM is not configured, so ACI analysis could not run.",
                "important_files": [],
                "risks": [],
                "next_targets": [],
                "tool_trace": [],
                "raw_answer": "",
            }

        messages: list[dict[str, Any]] = [{"role": "system", "content": ANALYZE_SYSTEM_PROMPT}]

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

        messages.append({"role": "user", "content": ANALYZE_USER_PROMPT})

        result = self._run_tool_loop(messages, max_tool_rounds=max_tool_rounds)
        final_text = result.get("answer", "")
        parsed = self._parse_analysis_json(final_text)

        return {
            "summary": parsed.get("summary", ""),
            "important_files": parsed.get("important_files", []),
            "risks": parsed.get("risks", []),
            "next_targets": parsed.get("next_targets", []),
            "tool_trace": result.get("tool_trace", []),
            "raw_answer": final_text,
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
            "answer": "Tool-calling loop exceeded the step limit.",
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