"""被测模块: winreverse.soul.compaction（Compactor LAYERED 摘要链预算弧）。

覆盖点: _compact_layered 旧区全空内容原样返回守卫、new_summary 超
_MAX_SUMMARY_CHARS 硬截断、prior 分支 new_budget 截断三处尾部弧。
"""

from __future__ import annotations

from kosong.types import Message, MessageRole
from winreverse.soul.compaction import (
    _MAX_SUMMARY_CHARS,
    CompactionStrategy,
    Compactor,
    _message_text,
)

_HEADER = "[Previously compacted]\n"
_NEWLY_TAG = "\n\n[Newly compacted]\n"
_NEWER_TRUNCATION_MARK = "\n...[newer summary truncated]..."


def _comp() -> Compactor:
    return Compactor(strategy=CompactionStrategy.LAYERED, max_tokens=100000)


def _summary_text(result: list[Message]) -> str:
    """取压缩结果中唯一的 SYSTEM 摘要消息文本。"""
    summary_msgs = [m for m in result if m.role == MessageRole.SYSTEM]
    assert len(summary_msgs) == 1, f"expected exactly one system summary, got {len(summary_msgs)}"
    return _message_text(summary_msgs[0])


class TestLayeredBudgetArcs:
    """LAYERED 增量摘要链的三处预算/守卫弧（guest 覆盖 818/822/833）。"""

    def test_empty_old_region_returns_messages_unchanged(self) -> None:
        """旧区消息全部为空内容 → 无可摘要内容，按无需压缩原样返回。"""
        comp = _comp()
        messages = [
            Message(role=MessageRole.USER, content=""),
            Message(role=MessageRole.USER, content=""),
            Message(role=MessageRole.USER, content="a"),
            Message(role=MessageRole.USER, content="b"),
            Message(role=MessageRole.USER, content="c"),
            Message(role=MessageRole.USER, content="d"),
        ]
        result, info = comp.compact(messages, model="cl100k_base")

        assert result == messages
        assert info.removed_messages == 0
        assert not any(m.role == MessageRole.SYSTEM for m in result[1:])

    def test_new_summary_hard_truncated_to_max_chars(self) -> None:
        """new_summary 超过 _MAX_SUMMARY_CHARS → 截到上限（33×508+32=16796 > 16000）。"""
        comp = _comp()
        payload = "A" * 600
        old = [Message(role=MessageRole.USER, content=f"{payload}-{i}") for i in range(33)]
        recent = [Message(role=MessageRole.USER, content=f"recent-{i}") for i in range(33)]

        result, info = comp.compact(old + recent, model="cl100k_base")

        text = _summary_text(result)
        assert text.startswith(_HEADER)
        newly = text[len(_HEADER) :]
        assert len(newly) == _MAX_SUMMARY_CHARS
        assert info.removed_messages == len(old) - 1  # 旧区 33 条被 1 条摘要取代
        # 保留区消息原样保留在摘要之后
        assert result[-len(recent) :] == recent

    def test_prior_budget_truncates_new_summary(self) -> None:
        """带 prior 时 new_budget = 16000-5333-50 = 10617 < new_summary 10688 → 截断打标。"""
        comp = _comp()
        prior_text = _HEADER + "P" * (_MAX_SUMMARY_CHARS // 3)
        system_prior = Message(role=MessageRole.SYSTEM, content=prior_text)
        payload = "B" * 600
        old = [Message(role=MessageRole.USER, content=f"{payload}-{i}") for i in range(21)]
        recent = [Message(role=MessageRole.USER, content=f"recent-{i}") for i in range(21)]

        result, info = comp.compact([system_prior, *old, *recent], model="cl100k_base")

        text = _summary_text(result)
        assert text.startswith(_HEADER)
        assert "[Newly compacted]" in text
        assert _NEWER_TRUNCATION_MARK in text

        newly = text.split(_NEWLY_TAG, 1)[1]
        new_budget = max(_MAX_SUMMARY_CHARS - (_MAX_SUMMARY_CHARS // 3) - 50, 1000)
        assert len(newly) == new_budget + len(_NEWER_TRUNCATION_MARK)
        assert info.removed_messages == len(old)
