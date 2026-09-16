"""测试模块：winreverse.soul.compaction（残余行为缺口）

覆盖点：provider 返回不可用摘要（.message=None / 空串）的静默降级、
流式分派中畸形 chunk 跳过与全空降级、AutoCompact.buffer_tokens 属性、
CJK 计价四区间（汉字/假名/谚文/扩展A）、prepare(max_preserved=0) 原样返回。
"""

from __future__ import annotations

from typing import Any

from kosong.types import Message, MessageRole
from winreverse.soul.compaction import (
    AutoCompact,
    SimpleCompaction,
    _count_cjk_chars,
    estimate_text_tokens,
)


def _user(text: str) -> Message:
    return Message(role=MessageRole.USER, content=text)


def _long_history(n: int = 6) -> list[Message]:
    return [_user(f"payload {i}") for i in range(n)]


class NoneMessageProvider:
    """generate 成功返回但 .message 为 None（不可用作摘要）。"""

    async def generate(self, messages: list[Message], model: str) -> Any:
        return type("R", (), {"message": None})()


class EmptyStrProvider:
    """generate 返回空字符串（同样不可用作摘要）。"""

    async def generate(self, messages: list[Message], model: str) -> str:
        return ""


class StreamingProvider:
    """generate_streaming 形态：按序吐出指定 chunk。"""

    def __init__(self, chunks: list[dict[str, Any]]) -> None:
        self._chunks = chunks

    async def generate_streaming(
        self, messages: list[Message], model: str
    ) -> Any:  # pragma: no cover - 由 compact 消费
        for chunk in self._chunks:
            yield chunk


async def test_provider_message_none_falls_back_without_summary() -> None:
    """generate 成功但 .message=None：不抛异常，退化为仅保留最近消息。"""
    messages = _long_history(6)
    result = await SimpleCompaction(llm_provider=NoneMessageProvider()).compact(messages)

    assert len(result.messages) == 2
    assert result.removed_messages == 4
    assert all(
        not (m.role == MessageRole.SYSTEM and "[Previously compacted]" in str(m.content))
        for m in result.messages
    )
    assert result.usage is None
    assert result.original_tokens > result.compacted_tokens > 0


async def test_provider_empty_str_summary_falls_back() -> None:
    """generate 返回空串：`result or None` 收敛为无摘要，走 keep-recent。"""
    result = await SimpleCompaction(llm_provider=EmptyStrProvider()).compact(_long_history(6))
    assert len(result.messages) == 2
    assert result.removed_messages == 4


async def test_streaming_malformed_chunks_skipped_good_chunk_accumulates() -> None:
    """非 list/空 choices、非 dict delta、空 content 的 chunk 全部跳过，不崩且不污染摘要。"""
    provider = StreamingProvider(
        [
            {"choices": "not-a-list"},
            {"choices": []},
            {"choices": [{"delta": "flat-string"}]},
            {"choices": [{"delta": {"content": ""}}]},
            {"choices": [{"delta": {"content": "GOOD "}}]},
            {"choices": [{"delta": {"content": "SUMMARY"}}]},
        ]
    )
    result = await SimpleCompaction(llm_provider=provider).compact(_long_history(6))

    assert len(result.messages) == 3  # 摘要 + 保留 2 条
    summary = result.messages[0]
    assert summary.role == MessageRole.SYSTEM
    assert "GOOD SUMMARY" in str(summary.content)
    assert result.removed_messages == 3


async def test_streaming_all_chunks_empty_falls_back_to_keep_recent() -> None:
    """流式分块全为空 content：accumulated 为空 → 无摘要，退化为 keep-recent。"""
    provider = StreamingProvider(
        [
            {"choices": [{"delta": {"content": ""}}]},
            {"choices": [{"delta": {}}]},
        ]
    )
    result = await SimpleCompaction(llm_provider=provider).compact(_long_history(6))
    assert len(result.messages) == 2
    assert result.removed_messages == 4


def test_auto_compact_buffer_tokens_property() -> None:
    """buffer_tokens 暴露构造值，默认 13000。"""
    assert AutoCompact().buffer_tokens == 13000
    assert AutoCompact(buffer_tokens=777).buffer_tokens == 777


def test_cjk_pricing_covers_four_unicode_ranges() -> None:
    """汉字/假名/谚文/CJK 扩展A 四个区间都按 CJK 计价，ASCII 不计。"""
    assert _count_cjk_chars("中文汉字") == 4
    assert _count_cjk_chars("アイウエオ") == 5  # 片假名
    assert _count_cjk_chars("あいうえお") == 5  # 平假名
    assert _count_cjk_chars("한국어") == 3  # 谚文
    assert _count_cjk_chars("\u3400\u3401") == 2  # CJK 扩展 A
    assert _count_cjk_chars("plain ascii") == 0

    # 同长度下 CJK 计价严格高于 ASCII（3 假名 → 2 token，3 ASCII → 0 token）
    cjk = estimate_text_tokens([_user("あいう")])
    ascii_tokens = estimate_text_tokens([_user("abc")])
    assert cjk == 2 > ascii_tokens == 0


def test_prepare_zero_preserved_returns_everything_unchanged() -> None:
    """max_preserved_messages<=0：不产出压缩请求，原样返回全部消息。"""
    messages = _long_history(6)
    prepared = SimpleCompaction(max_preserved_messages=0).prepare(messages)
    assert prepared.compact_message is None
    assert prepared.to_preserve == messages
