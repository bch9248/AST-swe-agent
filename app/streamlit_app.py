from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent.orchestrator import ASTAwareSWEAgentV2
from core.config import Settings


st.set_page_config(page_title="AST-aware SWE-Agent v2", layout="wide")


def init_state() -> None:
    if "settings" not in st.session_state:
        st.session_state.settings = Settings()
    if "agent" not in st.session_state:
        st.session_state.agent = ASTAwareSWEAgentV2(st.session_state.settings)
    if "analysis" not in st.session_state:
        st.session_state.analysis = None
    if "memory" not in st.session_state:
        st.session_state.memory = []
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []
    if "repo_path" not in st.session_state:
        st.session_state.repo_path = "examples/python_demo_repo"


init_state()
agent: ASTAwareSWEAgentV2 = st.session_state.agent


with st.sidebar:
    st.subheader("Repository")
    repo_path = st.text_input("Repository path", key="repo_path")
    analyze_btn = st.button("Analyze repository", use_container_width=True)
    clear_memory_btn = st.button("Clear memory", use_container_width=True)

    st.markdown("---")
    st.subheader("Analysis")

    if st.session_state.analysis is None:
        st.empty()
    else:
        analysis = st.session_state.analysis
        with st.expander("Summary"):
            st.json(
                {
                    "language": analysis["language"],
                    "file_count": analysis["file_count"],
                    "function_count": analysis["function_count"],
                    "class_count": analysis["class_count"],
                    "chunk_count": analysis["chunk_count"],
                    "issue_count": analysis["issue_count"],
                    "llm_enabled": analysis["llm_enabled"],
                    # "retrieval_mode": analysis.get("retrieval_mode", "unknown"),
                }
            )
        with st.expander("Detected security issues"):
            st.json(analysis["issues"])
        with st.expander("Detected languages per file"):
            st.json(analysis["languages"])
        with st.expander("Files"):
            st.write(analysis["files"])

if clear_memory_btn:
    st.session_state.memory = []
    st.session_state.chat_messages = []
    st.rerun()

if analyze_btn:
    st.session_state.analysis = agent.analyze_repository(repo_path)
    st.session_state.memory = []
    st.session_state.chat_messages = []
    st.rerun()

analysis = st.session_state.analysis

st.title("AST-aware SWE-Agent")

if analysis is None:
    st.info("Enter a repository path in the sidebar, then click Analyze repository.")
else:
    st.caption(f"Repository: {Path(st.session_state.repo_path).resolve()}")

    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message["role"] == "assistant" and message.get("tool_trace"):
                with st.expander("Tool trace"):
                    st.json(message["tool_trace"])

    user_prompt = st.chat_input("Ask about the repository...", disabled=analysis is None)

    if user_prompt:
        st.session_state.chat_messages.append({"role": "user", "content": user_prompt})
        with st.chat_message("user"):
            st.markdown(user_prompt)

        result = agent.ask(user_prompt, st.session_state.memory)

        if "conversation_append" in result:
            st.session_state.memory.extend(result["conversation_append"])

        if "error" in result:
            assistant_message = {
                "role": "assistant",
                "content": f"Error: {result['error']}",
                "tool_trace": result.get("tool_trace", []),
            }
        else:
            assistant_message = {
                "role": "assistant",
                "content": result["answer"],
                "tool_trace": result.get("tool_trace", []),
            }

        st.session_state.chat_messages.append(assistant_message)
        st.rerun()
