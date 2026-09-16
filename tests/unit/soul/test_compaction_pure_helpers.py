"""测试模块：winreverse.soul.compaction（纯助手函数直测）

覆盖点：_find_tool_pair_indices 的调用/结果配对映射（多结果聚合、
未知 tool_call_id 丢弃、非工具消息忽略、空输入）；_is_security_content
对 SECURITY_KEYWORDS 全表命中、大小写不敏感与良性/空串排除。
"""

from __future__ import annotations

from kosong.types import Message, MessageRole, ToolCall
from winreverse.soul.compaction import _find_tool_pair_indices, _is_security_content
from winreverse.soul.constants import SECURITY_KEYWORDS


def _call(tc_id: str) -> Message:
    return Message(
        role=MessageRole.ASSISTANT,
        content=f"invoke {tc_id}",
        tool_calls=[
            ToolCall(
                id=tc_id,
                type="function",
                function=ToolCall.FunctionBody(name="tool", arguments="{}"),
            )
        ],
    )


def _tool_result(text: str, tc_id: str) -> Message:
    return Message(role=MessageRole.TOOL, content=text, tool_call_id=tc_id)


def test_pair_map_aggregates_multiple_results_under_assistant() -> None:
    """一次 assistant 多个 tool_calls：全部结果下标聚合到同一 assistant 下标。"""
    messages: list[Message] = [
        Message(role=MessageRole.USER, content="hi"),
        _call("a"),
        _call("b"),
        _tool_result("r1", "a"),
        _tool_result("r2", "b"),
        _tool_result("r3", "a"),
    ]
    assert _find_tool_pair_indices(messages) == {1: [3, 5], 2: [4]}


def test_pair_map_drops_result_with_unknown_call_id() -> None:
    """tool 结果引用不存在的 tool_call_id（或 assistant 无 tool_calls）：不入映射。"""
    messages: list[Message] = [
        _tool_result("orphan", "missing"),
        Message(role=MessageRole.ASSISTANT, content="no calls here"),
    ]
    assert _find_tool_pair_indices(messages) == {}


def test_pair_map_empty_input_is_empty() -> None:
    assert _find_tool_pair_indices([]) == {}


def test_security_content_hits_every_registered_keyword() -> None:
    """SECURITY_KEYWORDS 全表逐词命中：任一关键词出现即判定为安全内容。"""
    for kw in SECURITY_KEYWORDS:
        assert _is_security_content(f"report mentions {kw} in log"), kw


def test_security_content_is_case_insensitive() -> None:
    sample = SECURITY_KEYWORDS[0].upper()
    assert _is_security_content(f"ALERT: {sample} FOUND") is True


def test_security_content_benign_and_empty_are_false() -> None:
    assert _is_security_content("user asks about the weather today") is False
    assert _is_security_content("") is False
