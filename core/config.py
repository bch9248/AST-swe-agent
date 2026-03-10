from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


@dataclass
class Settings:
    azure_openai_api_key: str = os.getenv("AZURE_OPENAI_API_KEY", "")
    azure_openai_endpoint: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    azure_openai_chat_deployment: str = os.getenv("AZURE_OPENAI_CHAT_DEPLOYMENT", "")
    azure_openai_embedding_deployment: str = os.getenv("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "")
    retrieval_mode: str = os.getenv("RETRIEVAL_MODE", "lexical")
    azure_openai_api_version: str = os.getenv("AZURE_OPENAI_API_VERSION", "")

    @property
    def azure_openai_base_url(self) -> str:
        endpoint = self.azure_openai_endpoint.rstrip("/")
        if not endpoint:
            return ""
        return f"{endpoint}/openai/v1/"

    @property
    def ready_for_chat(self) -> bool:
        return bool(self.azure_openai_api_key and self.azure_openai_base_url and self.azure_openai_chat_deployment)

    @property
    def ready_for_embeddings(self) -> bool:
        return bool(
            self.retrieval_mode == "vector"
            and self.ready_for_chat
            and self.azure_openai_embedding_deployment
        )
    @staticmethod
    def project_root() -> Path:
        return Path(__file__).resolve().parents[1]
