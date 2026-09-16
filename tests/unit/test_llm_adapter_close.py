"""LLMAdapter.close() 资源释放弧直测（2026-09-16 错峰轮）。

覆盖点：``llm_runtime.py`` ``close()`` 的 ``await self._client.close()``——
此前无任何用例显式关闭适配器，底层 httpx 连接池释放路径零覆盖。

断言真实副作用：close() 后 SDK 客户端进入已关闭状态。
openai/httpx 为跨平台依赖，双端可跑。
"""

from __future__ import annotations

import asyncio

from winreverse.config import LLMConfig
from winreverse.llm_runtime import LLMAdapter


def test_llm_adapter_close_releases_http_client() -> None:
    """close() 必须真实关闭底层 AsyncOpenAI/httpx 连接池（构造不发起网络）。"""
    config = LLMConfig(
        model="test-model",
        api_key="sk-test-close",
        base_url="http://127.0.0.1:9/v1",
    )
    adapter = LLMAdapter(config)
    assert adapter._client.is_closed() is False

    asyncio.run(adapter.close())

    assert adapter._client.is_closed() is True
