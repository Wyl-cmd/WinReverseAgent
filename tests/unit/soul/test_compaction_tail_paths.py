"""SimpleCompaction 守卫与 LLM 路径尾部弧补测（2026-09-14 07:00 监督轮）。

补既有 test_compaction.py 未触达的 Linux 可实跑弧：
- prepare 空消息 / max_preserved_messages<=0 守卫（原样返回）
- prepare 全量可保留 → 无可压缩段守卫
- compact 无压缩请求时提前返回
- compact LLM 路径 custom_instruction 追加进提示词
- provider 返回裸字符串时按摘要文本采用
"""

from __future__ import annotations

from typing import Any

from kosong.types import Message, MessageRole
from winreverse.soul.compaction import CompactionStrategy, SimpleCompaction

# =============================================================================
# 测试辅助
# =============================================================================


def _user(text: str) -> Message:
    """构造 user 消息。"""
    return Message(role=MessageRole.USER, content=text)


def _long_history(n: int = 6, text: str = "hello world payload") -> list[Message]:
    """构造 n 条 user 消息历史。"""
    return [_user(f"{text} {i}") for i in range(n)]


class FakeProvider:
    """压缩用 LLM Provider 桩：固定返回摘要对象，记录调用入参。"""

    def __init__(self, reply: str = "COMPACT_SUMMARY") -> None:
        self.reply = reply
        self.calls: list[list[Message]] = []

    async def generate(self, messages: list[Message], model: str) -> Any:
        self.calls.append(messages)
        return type("R", (), {"message": Message(role=MessageRole.ASSISTANT, content=self.reply)})()


class StrProvider:
    """非标准 Provider 桩：generate 直接返回裸字符串。"""

    def __init__(self) -> None:
        self.calls: list[list[Message]] = []

    async def generate(self, messages: list[Message], model: str) -> Any:
        self.calls.append(messages)
        return "STR_SUMMARY"


# =============================================================================
# prepare 守卫返回弧
# =============================================================================


class TestPrepareGuards:
    """prepare 守卫返回弧。"""

    def test_empty_messages_returns_nothing_to_do(self) -> None:
        """空历史直接原样返回、不构造压缩请求。"""
        comp = SimpleCompaction(max_preserved_messages=2)
        prepared = comp.prepare([])
        assert prepared.compact_message is None
        assert prepared.to_preserve == []

    def test_nonpositive_preserved_returns_input(self) -> None:
        """max_preserved_messages<=0 视为禁用压缩，原样返回全部消息。"""
        comp = SimpleCompaction(max_preserved_messages=0)
        history = _long_history(4)
        prepared = comp.prepare(history)
        assert prepared.compact_message is None
        assert list(prepared.to_preserve) == history

    def test_all_preserved_nothing_to_compact(self) -> None:
        """全部消息都在保留额度内 → 无可压缩段，compact_message 为 None。"""
        comp = SimpleCompaction(max_preserved_messages=3)
        history = _long_history(3)
        prepared = comp.prepare(history)
        assert prepared.compact_message is None
        assert list(prepared.to_preserve) == history


# =============================================================================
# compact 守卫与 LLM 路径分支
# =============================================================================


class TestCompactGuards:
    """compact 守卫与 LLM 路径分支。"""

    async def test_no_compact_message_returns_early(self) -> None:
        """无压缩请求时提前返回：消息原样、token 不变、无移除。"""
        comp = SimpleCompaction(max_preserved_messages=2, llm_provider=None)
        result = await comp.compact(_long_history(1))
        assert result.strategy_used == CompactionStrategy.SIMPLE
        assert result.removed_messages == 0
        assert result.original_tokens == result.compacted_tokens
        assert len(result.messages) == 1

    async def test_llm_prompt_appends_custom_instruction(self) -> None:
        """LLM 路径把 custom_instruction 追加进压缩提示词。"""
        from winreverse.soul.compaction import _message_text

        provider = FakeProvider()
        comp = SimpleCompaction(max_preserved_messages=2, llm_provider=provider)
        result = await comp.compact(_long_history(6), custom_instruction="保留所有 IOC")
        assert provider.calls
        assert "保留所有 IOC" in _message_text(provider.calls[0][0])
        assert result.messages[0].role == MessageRole.SYSTEM

    async def test_provider_returning_bare_str_is_used_as_summary(self) -> None:
        """provider 返回裸字符串时按摘要文本采用（非标准 Provider 协议容错）。"""
        from winreverse.soul.compaction import _message_text

        provider = StrProvider()
        comp = SimpleCompaction(max_preserved_messages=2, llm_provider=provider)
        result = await comp.compact(_long_history(6))
        assert "STR_SUMMARY" in _message_text(result.messages[0])
