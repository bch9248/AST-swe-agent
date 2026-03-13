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

Rules:
- Start by calling get_state.
- Then use direct repo interaction tools such as list_dir, find_files, read_file, or run_command.
- Before claiming a file is missing, verify it with list_dir or find_files.
- Before claiming a security issue exists, inspect the relevant files directly.
- Before modifying a file, read it first.
- After modifying a file, run a relevant verification command when possible.
- Ground every claim in observed tool results.
- Do not say you inspected, edited, or executed anything unless you actually did so through tools.
- Be concise but concrete. Include paths, command outputs, and evidence.
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
- Then inspect the repository root with list_dir.
- Use find_files and read_file to inspect important docs/configs/source files.
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

Return only a valid JSON format following this schema:
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

Your output:
{
  "summary":""".strip()


class ASTAwareSWEAgentV2:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

        # Internal metadata pipeline (not exposed as LLM tools)
        self.detector = LanguageDetector()
        self.parser = TreeSitterMultiLanguageParser()
        self.graph_builder = CodeGraphBuilder()
        self.scanner = SecurityScanner()  # now expected to be a no-op scanner

        # LLM client
        self.llm = AzureOpenAIToolAgentClient(self.settings) if self.settings.ready_for_chat else None

        # Internal analysis state
        self.lexical_retriever = None
        self.index = None
        self.repo_tools: RepositoryTools | None = None
        self.issues = []
        self.analysis: dict[str, Any] | None = None

        # ACI state exposed to the LLM
        self.workspace: Workspace | None = None
        self.executor: ACIExecutor | None = None
        self.aci_tools: ACITools | None = None
        self.registry: ToolRegistry | None = None

    def analyze_repository(self, repo_path: str) -> dict[str, Any]:
        """
        Analyze repository structure internally, then run an ACI-based investigation
        to produce the displayed analysis and risk summary.
        """
        index = self.parser.parse_repository(repo_path)
        graph = self.graph_builder.build(index)
        issues = self.scanner.scan(index)

        # Keep internal metadata only for UI and future internal use
        self.lexical_retriever = LexicalCodeRetriever(index.chunks)
        self.index = index
        self.repo_tools = RepositoryTools(index, graph, self.lexical_retriever)
        self.issues = issues

        # Always initialize ACI workspace/tools
        self.workspace = Workspace(Path(repo_path))
        self.executor = ACIExecutor(self.workspace)
        self.aci_tools = ACITools(self.executor)

        # IMPORTANT: only expose ACI tools to the LLM
        self.registry = ToolRegistry(self.aci_tools)

        # Run ACI-driven analysis investigation
        aci_analysis = self._run_aci_analysis()

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
        }
        return self.analysis

    def _run_aci_analysis(self) -> dict[str, Any]:
        """
        Run an automatic ACI investigation when the user clicks Analyze repository.
        """
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
            initial_listing = self.registry.execute("list_dir", json.dumps({"path": "."}, ensure_ascii=False))
            messages.append({
                "role": "system",
                "content": "Initial repository root listing:\n" + json.dumps(initial_listing, ensure_ascii=False),
            })
        except Exception:
            pass

        messages.append({"role": "user", "content": ANALYZE_USER_PROMPT})

        result = self._run_tool_loop(messages, max_tool_rounds=38)
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

    def ask(self, user_question: str, memory_messages: list[dict[str, str]]) -> dict[str, Any]:
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
            initial_listing = self.registry.execute("list_dir", json.dumps({"path": "."}, ensure_ascii=False))
            messages.append({
                "role": "system",
                "content": "Initial repository root listing:\n" + json.dumps(initial_listing, ensure_ascii=False),
            })
        except Exception:
            pass

        messages.extend(memory_messages)
        messages.append({"role": "user", "content": user_question})

        result = self._run_tool_loop(messages, max_tool_rounds=40)
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

    def _extract_risks_from_text(self, text: str) -> list[dict[str, Any]]:
        """
        Simple parser for the analysis result. This does not create findings itself;
        it only structures findings already produced by the ACI investigation.
        """
        if not text.strip():
            return []

        risks: list[dict[str, Any]] = []
        lines = [line.strip() for line in text.splitlines() if line.strip()]

        current: dict[str, Any] | None = None
        for line in lines:
            lower = line.lower()

            if lower.startswith("risk:") or lower.startswith("- risk:"):
                if current:
                    risks.append(current)
                current = {
                    "title": line.split(":", 1)[1].strip() if ":" in line else line,
                    "evidence": "",
                    "severity": "unknown",
                }
            elif current is not None and lower.startswith("evidence:"):
                current["evidence"] = line.split(":", 1)[1].strip() if ":" in line else line
            elif current is not None and lower.startswith("severity:"):
                current["severity"] = line.split(":", 1)[1].strip() if ":" in line else line

        if current:
            risks.append(current)

        return risks
    
    def _parse_analysis_json(self, text: str) -> dict[str, Any]:
        """
        Parse the final ACI analysis output as JSON.
        Falls back to a minimal structure if parsing fails.
        """
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