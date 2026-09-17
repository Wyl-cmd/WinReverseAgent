"""winreverse.soul.compaction 剩余可达弧补测。

覆盖点：_estimate_message_tokens 的 tiktoken 异常回退（156-159 行的 except 分支）、
SimpleCompaction.prepare 保留预算跳过 system/tool 角色（305→302 分支）、
MicroCompact 无 TOOL 结果消息时零节省（536→543 分支）、
SnipCompact 配对保护整对救回时零释放（605→612 分支）。
"""

from __future__ import annotations

from kosong.types import Message, MessageRole, ToolCall
from winreverse.soul.compaction import (
    MicroCompact,
    SimpleCompaction,
    SnipCompact,
    _estimate_message_tokens,
    _message_text,
    estimate_text_tokens,
)


def _user(text: str) -> Message:
    return Message(role=MessageRole.USER, content=text)


def _tool(call_id: str, text: str) -> Message:
    return Message(role=MessageRole.TOOL, content=text, tool_call_id=call_id)


def _assistant_with_call(call_id: str, name: str = "t") -> Message:
    return Message(
        role=MessageRole.ASSISTANT,
        content="",
        tool_calls=[
            ToolCall(id=call_id, function=ToolCall.FunctionBody(name=name, arguments="{}"))
        ],
    )


def test_estimate_message_tokens_tiktoken_error_falls_back_to_heuristic(
    monkeypatch: object,
) -> None:
    """tiktoken 抛非 ImportError 异常（如离线拉不到 BPE 词表）时整列回退启发式。"""

    def _boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("BPE table unavailable")

    monkeypatch.setattr("tiktoken.encoding_for_model", _boom)
    monkeypatch.setattr("tiktoken.get_encoding", _boom)
    messages = [_user("hello world"), _user("你好，世界")]
    assert _estimate_message_tokens(messages, model="gpt-4o") == estimate_text_tokens(messages)


def test_estimate_message_tokens_without_tiktoken_falls_back(monkeypatch: object) -> None:
    """tiktoken 未安装（ImportError）→ 直接回退启发式估算。"""
    import sys

    monkeypatch.setitem(sys.modules, "tiktoken", None)  # 使 `import tiktoken` 抛 ImportError

    messages = [_user("hello world"), _user("你好，世界")]
    assert _estimate_message_tokens(messages, model="gpt-4o") == estimate_text_tokens(messages)


def test_snip_compact_zero_token_estimate_returns_unchanged(monkeypatch: object) -> None:
    """token 估算为 0（空内容消息）→ 原样返回、零释放，不做无意义裁剪。"""
    messages = [_user("x")]
    monkeypatch.setattr("winreverse.soul.compaction._estimate_message_tokens", lambda *a, **k: 0)

    out, freed = SnipCompact().compact(messages)

    assert out == messages
    assert freed == 0


def test_prepare_counts_only_user_assistant_for_preserve_budget() -> None:
    """保留预算只数 user/assistant：尾部扫描越过 system 消息继续向前找名额。"""
    compaction = SimpleCompaction(max_preserved_messages=2)
    history = [
        _user("early question"),
        _user("middle question"),
        Message(role=MessageRole.SYSTEM, content="mid-run system note"),
        Message(role=MessageRole.ASSISTANT, content="recent answer"),
    ]
    result = compaction.prepare(history)
    assert result.to_preserve == history[1:]
    assert result.compact_message is not None
    bundle = _message_text(result.compact_message)
    assert "early question" in bundle
    assert "middle question" not in bundle
    assert "mid-run system note" not in bundle
    assert "Role: system" not in bundle


def test_micro_compact_without_tool_result_messages_saves_zero() -> None:
    """可清理 id 收集自 assistant.tool_calls，但替换只作用于 TOOL 消息：
    TOOL 结果缺失时不得虚报节省，消息原样返回。"""
    messages = [_assistant_with_call(f"call-{i}") for i in range(4)]
    result, saved = MicroCompact(keep_recent=3).compact(messages)
    assert saved == 0
    assert result == messages


def test_snip_compact_pair_protection_rescues_everything_frees_zero() -> None:
    """裁剪边界恰好拆散 assistant(tool_calls) 与 tool 结果时整对救回：
    一条不删、零 token 释放。"""
    pair = [_assistant_with_call("call-1", "run"), _tool("call-1", "result payload hello")]
    result, freed = SnipCompact(max_snip_ratio=0.5).compact(pair)
    assert freed == 0
    assert result == pair
