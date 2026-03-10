# AST-aware SWE-Agent v2

A research-oriented starter project for code-question answering over repositories.

This version adds:
- Azure OpenAI tool-calling for an actual SWE-agent loop
- vector retrieval over code chunks using Azure embeddings + FAISS
- Tree-sitter-based multi-language parsing
- conversation memory in the Streamlit UI

## Architecture

```text
Code Repository
      |
Language Detector
      |
Tree-sitter Multi-Language Parser
      |
AST / Symbol Normalization
      |
Code Graph Builder + Code Chunker
      |
Azure Embeddings -> FAISS Vector Store
      |
Azure OpenAI Tool-Calling Agent
      |
Streamlit Chat UI with Session Memory
```

## Supported languages

Implemented parsing coverage is aimed at:
- Python
- C
- C++
- Java
- Go
- JavaScript
- TypeScript

The symbol extraction is intentionally generic and normalization-first. It is suitable for repository QA, call-graph navigation, code search, and early research prototypes. For production-grade static analysis, you will likely want per-language enrichers on top of this base.

## Project layout

```text
app/
  streamlit_app.py
core/
  agent/
  analysis/
  llm/
  models/
  parsers/
  retrieval/
  tools/
examples/
  python_demo_repo/
.env.example
requirements.txt
```

## Environment

Copy `.env.example` to `.env` and fill in your Azure values:

```bash
cp .env.example .env
```

Required variables:

```env
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://YOUR-RESOURCE.openai.azure.com
AZURE_OPENAI_CHAT_DEPLOYMENT=YOUR_CHAT_DEPLOYMENT
AZURE_OPENAI_EMBEDDING_DEPLOYMENT=YOUR_EMBEDDING_DEPLOYMENT
```

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
streamlit run app/streamlit_app.py
```

Then analyze:

```text
examples/python_demo_repo
```

## UI capabilities

- Analyze repository structure
- inspect detected languages
- inspect security findings
- ask natural-language questions about the code
- preserve multi-turn chat memory for the current browser session
- inspect the tool trace used by the agent

## Built-in tools exposed to the LLM

- `summarize_repository()`
- `list_files()`
- `search_code(query)`
- `semantic_search(query, top_k)`
- `get_function_ast(function_name)`
- `get_class_ast(class_name)`
- `get_callers(function_name)`
- `get_callees(function_name)`
- `trace_variable(variable)`
- `read_snippet(file_path, start_line, end_line)`

## Important implementation notes

1. The parser is Tree-sitter-based, but the normalized schema is deliberately language-agnostic.
2. Vector retrieval uses Azure embeddings. If the embedding deployment is not configured, semantic search is unavailable.
3. Conversation memory is stored in Streamlit Session State, so it lasts for the connected browser session but is not a durable database.
4. This project is a strong research scaffold, not a full static analyzer or a full autonomous patching system.

## Natural next upgrades

- add repo-level caching for parsed indexes
- add diff generation and patch application preview
- add per-language semantic enrichers
- add test-aware repair loops
- add vulnerability propagation analysis across call paths
