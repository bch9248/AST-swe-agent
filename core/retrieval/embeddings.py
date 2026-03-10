from __future__ import annotations

from typing import Sequence

from openai import OpenAI

from core.config import Settings


class AzureEmbeddingClient:
    def __init__(self, settings: Settings) -> None:
        if not settings.ready_for_embeddings:
            raise RuntimeError("Azure embedding configuration is incomplete.")
        self._settings = settings
        self._client = OpenAI(
            api_key=settings.azure_openai_api_key,
            base_url=settings.azure_openai_base_url,
        )

    def embed_texts(self, texts: Sequence[str]) -> list[list[float]]:
        response = self._client.embeddings.create(
            model=self._settings.azure_openai_embedding_deployment,
            input=list(texts),
        )
        return [item.embedding for item in response.data]
