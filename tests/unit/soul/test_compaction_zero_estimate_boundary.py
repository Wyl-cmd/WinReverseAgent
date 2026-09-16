"""测试模块：winreverse.soul.compaction（SnipCompact 边界行为）

覆盖点：全空 content 消息启发式估算恰为 0；单消息历史按 max_snip_ratio 被
完整裁剪且释放 token 等于其估算值；enabled=False 恒等透传（非拷贝）。
注：compact 的 total_tokens==0 早退弧仅在 tiktoken 不可用环境可达
（tiktoken 路径每条消息有 +4 保底开销），属真机互补路径，本地不硬凑。
"""

from __future__ import annotations

from kosong.types import Message, MessageRole
from winreverse.soul.compaction import (
    SnipCompact,
    _estimate_message_tokens,
    estimate_text_tokens,
)


def test_estimate_text_tokens_empty_contents_is_zero() -> None:
    """全空文本消息（如仅含 tool_calls 的占位消息）启发式估算恰为 0。"""
    msgs = [Message(role=MessageRole.USER, content="") for _ in range(3)]
    assert estimate_text_tokens(msgs) == 0


def test_snip_compact_single_message_fully_snipped() -> None:
    """单消息历史低于 max_snip_ratio 保留量：整体裁剪，释放=其估算值。"""
    compactor = SnipCompact(max_snip_ratio=0.5)
    msgs = [Message(role=MessageRole.USER, content="")]
    out, freed = compactor.compact(msgs)
    assert out == []
    assert freed == _estimate_message_tokens(msgs)


def test_snip_compact_disabled_passthrough_identity() -> None:
    """enabled=False：短路返回入参本身（非拷贝），即便消息内容很长。"""
    compactor = SnipCompact(max_snip_ratio=0.5, enabled=False)
    msgs = [Message(role=MessageRole.USER, content="hello world " * 64)]
    out, freed = compactor.compact(msgs)
    assert out is msgs
    assert freed == 0
