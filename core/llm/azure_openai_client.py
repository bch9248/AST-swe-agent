from __future__ import annotations

from typing import Any

from openai import OpenAI

from core.config import Settings


class AzureOpenAIToolAgentClient:
    def __init__(self, settings: Settings) -> None:
        if not settings.ready_for_chat:
            raise RuntimeError("Azure chat configuration is incomplete.")
        self.settings = settings
        self.client = OpenAI(
            api_key=settings.azure_openai_api_key,
            base_url=settings.azure_openai_base_url,
        )

    def create_chat_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = "auto",
        temperature: float = 0.1,
    ):
        kwargs: dict[str, Any] = {
            "model": self.settings.azure_openai_chat_deployment,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice
        return self.client.chat.completions.create(**kwargs)
