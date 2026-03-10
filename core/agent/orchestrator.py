from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from core.analysis.code_graph import CodeGraphBuilder
from core.analysis.language_detector import LanguageDetector
from core.analysis.vuln_rules import SecurityScanner
from core.config import Settings
from core.llm.azure_openai_client import AzureOpenAIToolAgentClient
from core.parsers.tree_sitter_parser import TreeSitterMultiLanguageParser
from core.retrieval.lexical_retriever import LexicalCodeRetriever
from core.tools.repository_tools import RepositoryTools
from core.tools.tool_registry import ToolRegistry


SYSTEM_PROMPT = """
You are an AST-aware SWE-agent for code understanding and security analysis.
Use tools aggressively before answering.
Prefer summarize_repository, semantic_search, search_code, get_function_ast, get_class_ast, get_callers, get_callees, trace_variable, and read_snippet.
Use semantic_search for lexical/symbol chunk retrieval, not embeddings.
When reporting a finding, include file paths, symbols, and concrete evidence.
When suggesting a fix, propose a minimal patch with rationale.
Do not claim you inspected code that you did not inspect via tools.
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
        self.analysis: dict[str, Any] | None = None
        self.index = None
        self.tools = None
        self.registry = None
        self.issues = []

    def analyze_repository(self, repo_path: str) -> dict[str, Any]:
        index = self.parser.parse_repository(repo_path)
        graph = self.graph_builder.build(index)
        issues = self.scanner.scan(index)
        self.lexical_retriever = LexicalCodeRetriever(index.chunks)
        self.index = index
        self.tools = RepositoryTools(index, graph, self.lexical_retriever)
        self.registry = ToolRegistry(self.tools)
        self.issues = issues
        self.analysis = {
            "language": index.language,
            "languages": index.metadata.get("languages", {}),
            "file_count": len(index.files),
            "function_count": len(index.functions),
            "class_count": len(index.classes),
            "chunk_count": len(index.chunks),
            "issue_count": len(issues),
            "files": index.files,
            "graph": graph,
            "issues": [asdict(issue) for issue in issues],
            "embedding_enabled": False,
            "retrieval_mode": "lexical_ast_graph",
            "llm_enabled": self.llm is not None,
        }
        return self.analysis

    def ask(self, user_question: str, memory_messages: list[dict[str, str]]) -> dict[str, Any]:
        if self.registry is None or self.tools is None:
            return {"error": "Analyze a repository first."}
        if self.llm is None:
            return {"error": "Azure OpenAI chat configuration is incomplete in .env."}

        messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.extend(memory_messages)
        messages.append({"role": "user", "content": user_question})

        tool_trace: list[dict[str, Any]] = []
        for _ in range(8):
            response = self.llm.create_chat_completion(messages=messages, tools=self.registry.openai_tools())
            msg = response.choices[0].message

            assistant_message: dict[str, Any] = {"role": "assistant"}
            if msg.content:
                assistant_message["content"] = msg.content
            if getattr(msg, "tool_calls", None):
                assistant_message["tool_calls"] = [tc.model_dump() for tc in msg.tool_calls]
            messages.append(assistant_message)

            if not getattr(msg, "tool_calls", None):
                final_text = msg.content or "No content returned."
                return {
                    "answer": final_text,
                    "tool_trace": tool_trace,
                    "analysis": self.analysis,
                    "issues": [asdict(issue) for issue in self.issues],
                    "conversation_append": [
                        {"role": "user", "content": user_question},
                        {"role": "assistant", "content": final_text},
                    ],
                }

            for tool_call in msg.tool_calls:
                tool_name = tool_call.function.name
                arguments_json = tool_call.function.arguments or "{}"
                result = self.registry.execute(tool_name, arguments_json)
                tool_trace.append({
                    "tool_name": tool_name,
                    "arguments": json.loads(arguments_json),
                    "result": result,
                })
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result, ensure_ascii=False),
                })

        return {
            "error": "Tool-calling loop exceeded the step limit.",
            "tool_trace": tool_trace,
            "analysis": self.analysis,
        }
