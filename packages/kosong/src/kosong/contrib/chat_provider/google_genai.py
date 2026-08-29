from __future__ import annotations

from typing import Any

from kosong.contrib.chat_provider.openai_legacy import OpenAILegacy


class GoogleGenAI(OpenAILegacy):
    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str,
        vertexai: bool = False,
        default_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            model=model,
            base_url=base_url,
            api_key=api_key,
            default_headers=default_headers,
        )
        self._vertexai = vertexai
