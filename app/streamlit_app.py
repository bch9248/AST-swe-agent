from __future__ import annotations

import sys
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent.orchestrator import ASTAwareSWEAgentV2
from core.config import Settings


st.set_page_config(page_title="AST-aware SWE-Agent v2", layout="wide")


def safe_extract_zip(zip_path: str, extract_dir: str) -> None:
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = os.path.abspath(os.path.join(extract_dir, member.filename))
            if not member_path.startswith(os.path.abspath(extract_dir)):
                raise ValueError("Unsafe zip file: path traversal detected.")
        zf.extractall(extract_dir)


def extract_uploaded_repo(uploaded_file) -> tuple[str, str]:
    temp_dir = tempfile.mkdtemp(prefix="repo_upload_")
    zip_path = os.path.join(temp_dir, uploaded_file.name)

    with open(zip_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    safe_extract_zip(zip_path, extract_dir)

    entries = [p for p in Path(extract_dir).iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return str(entries[0]), temp_dir

    return extract_dir, temp_dir


def cleanup_uploaded_repo() -> None:
    old_temp_dir = st.session_state.get("uploaded_temp_dir")
    if old_temp_dir and os.path.exists(old_temp_dir):
        shutil.rmtree(old_temp_dir, ignore_errors=True)
    st.session_state.uploaded_temp_dir = None


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
        st.session_state.repo_path = None
    if "uploaded_repo_name" not in st.session_state:
        st.session_state.uploaded_repo_name = None
    if "uploaded_temp_dir" not in st.session_state:
        st.session_state.uploaded_temp_dir = None
    if "analyze_tool_limit" not in st.session_state:
        st.session_state.analyze_tool_limit = 30
    if "chat_tool_limit" not in st.session_state:
        st.session_state.chat_tool_limit = 30


init_state()
agent: ASTAwareSWEAgentV2 = st.session_state.agent

with st.sidebar:
    st.subheader("Repository")

    uploaded_repo = st.file_uploader(
        "Upload repository (.zip)",
        type=["zip"],
        help="Upload a zipped repository. The agent will interact with it through ACI tools.",
    )

    st.markdown("### Tool-call limits")

    st.session_state.analyze_tool_limit = st.number_input(
        "Analyze limit",
        min_value=1,
        max_value=100,
        value=st.session_state.analyze_tool_limit,
        step=1,
        help="Maximum number of tool-calling rounds used during repository analysis.",
    )

    st.session_state.chat_tool_limit = st.number_input(
        "Chat limit",
        min_value=1,
        max_value=100,
        value=st.session_state.chat_tool_limit,
        step=1,
        help="Maximum number of tool-calling rounds used per chat turn.",
    )

    analyze_btn = st.button("Analyze repository", use_container_width=True)
    clear_memory_btn = st.button("Clear memory", use_container_width=True)

    st.markdown("---")
    st.subheader("Analysis")

    if st.session_state.analysis is None:
        st.empty()
    else:
        analysis = st.session_state.analysis
        with st.expander("Summary", expanded=True):
            st.json(
                {
                    "repository": st.session_state.get("uploaded_repo_name") or Path(st.session_state.repo_path).name,
                    "language": analysis.get("language"),
                    "file_count": analysis.get("file_count"),
                    "indexed_code_file_count": analysis.get("indexed_code_file_count"),
                    "function_count": analysis.get("function_count"),
                    "class_count": analysis.get("class_count"),
                    "chunk_count": analysis.get("chunk_count"),
                    "issue_count": analysis.get("issue_count"),
                    # "llm_enabled": analysis.get("llm_enabled"),
                    # "aci_enabled": analysis.get("aci_enabled"),
                    # "retrieval_mode": analysis.get("retrieval_mode"),
                }
            )
        
        with st.expander("All files in repository"):
            st.write(analysis.get("files", []))
        with st.expander("Raw ACI analysis output"):
            st.code(analysis.get("analysis_raw_answer", ""), language="json")
        with st.expander("Risks", expanded=True):
            risks = analysis.get("issues", [])
            if not risks:
                st.write("No grounded risks reported.")
            else:
                st.json(risks)

        with st.expander("Important files"):
            st.json(analysis.get("analysis_important_files", []))

        with st.expander("Repo detail", expanded=True):
            st.markdown(analysis.get("analysis_summary", ""))

        with st.expander("Analysis tool trace"):
            st.json(analysis.get("analysis_tool_trace", []))

if clear_memory_btn:
    st.session_state.memory = []
    st.session_state.chat_messages = []
    st.rerun()

if analyze_btn:
    if uploaded_repo is None:
        st.sidebar.error("Please upload a repository .zip file first.")
    else:
        try:
            cleanup_uploaded_repo()

            repo_path, temp_dir = extract_uploaded_repo(uploaded_repo)

            st.session_state.repo_path = repo_path
            st.session_state.uploaded_repo_name = uploaded_repo.name
            st.session_state.uploaded_temp_dir = temp_dir

            # IMPORTANT: create a fresh agent and keep it in session_state
            st.session_state.agent = ASTAwareSWEAgentV2(st.session_state.settings)
            agent = st.session_state.agent

            st.session_state.analysis = agent.analyze_repository(
                repo_path,
                analyze_tool_limit=int(st.session_state.analyze_tool_limit),
            )
            st.session_state.memory = []
            st.session_state.chat_messages = []
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Failed to analyze uploaded repository: {e}")

analysis = st.session_state.analysis

st.title("AST-aware SWE-Agent")
st.caption("ACI-only mode: the agent is forced to interact with the uploaded repository through direct workspace tools.")

if analysis is None:
    st.info("Upload a repository .zip in the sidebar, then click Analyze repository.")
else:
    repo_label = st.session_state.get("uploaded_repo_name") or Path(st.session_state.repo_path).name
    st.caption(f"Repository: {repo_label}")

    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

            if message["role"] == "assistant" and message.get("tool_trace"):
                tool_names = [item.get("tool_name", "?") for item in message["tool_trace"]]
                if tool_names:
                    st.caption("Tools used: " + " → ".join(tool_names))

                with st.expander("Tool trace"):
                    st.json(message["tool_trace"])

    user_prompt = st.chat_input("Ask about the repository...", disabled=analysis is None)

    if user_prompt:
        st.session_state.chat_messages.append({"role": "user", "content": user_prompt})
        with st.chat_message("user"):
            st.markdown(user_prompt)

        result = agent.ask(
            user_prompt,
            st.session_state.memory,
            chat_tool_limit=int(st.session_state.chat_tool_limit),
        )

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