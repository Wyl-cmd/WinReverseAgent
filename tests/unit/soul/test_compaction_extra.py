"""测试模块：winreverse.soul.compaction 补充分支。

覆盖 CompactionResult.estimated_token_count、_part_to_text 媒体占位、
_estimate_message_tokens 的 tool_calls/role/未知模型回退、_protect_tool_pairs
不动点迭代、Micro/Snip 无操作分支、Compactor 小历史保留 system（回归）与
SELECTIVE 短工具结果不截断、LAYERED 空消息跳过与旧摘要链截断。
"""

from __future__ import annotations

from types import SimpleNamespace

from kosong.types import Message, MessageRole, ToolCall
from winreverse.soul.compaction import (
    CompactionResult,
    CompactionStrategy,
    Compactor,
    MicroCompact,
    SimpleCompaction,
    SnipCompact,
    _estimate_message_tokens,
    _part_to_text,
    _protect_tool_pairs,
    estimate_text_tokens,
)

# =============================================================================
# 测试辅助
# =============================================================================


def _user(text: str) -> Message:
    return Message(role=MessageRole.USER, content=text)


def _tool(text: str, tool_call_id: str) -> Message:
    return Message(role=MessageRole.TOOL, content=text, tool_call_id=tool_call_id)


def _assistant_with_tool_call(call_id: str, name: str = "pe_analyzer", args: str = "{}") -> Message:
    return Message(
        role=MessageRole.ASSISTANT,
        content="calling",
        tool_calls=[
            ToolCall(
                id=call_id,
                type="function",
                function=ToolCall.FunctionBody(name=name, arguments=args),
            )
        ],
    )


def _part(dump: dict) -> SimpleNamespace:
    """构造带 model_dump() 的媒体 part 桩（_part_to_text 只依赖该方法）。"""
    return SimpleNamespace(model_dump=lambda d=dump: d)


# =============================================================================
# CompactionResult.estimated_token_count
# =============================================================================


class TestCompactionResultTokenCount:
    """压缩结果 token 估算：LLM 用量优先、无用量走启发式。"""

    def test_usage_output_tokens_plus_preserved(self) -> None:
        kept = [_user("a"), _user("b")]
        result = CompactionResult(
            messages=[Message(role=MessageRole.SYSTEM, content="summary"), *kept],
            original_tokens=500,
            compacted_tokens=0,
            removed_messages=3,
            strategy_used=CompactionStrategy.SIMPLE,
            usage=SimpleNamespace(output_tokens=77),
        )
        assert result.estimated_token_count == 77 + estimate_text_tokens(kept)

    def test_no_usage_falls_back_to_heuristic(self) -> None:
        messages = [_user("hello"), _user("world")]
        result = CompactionResult(
            messages=messages,
            original_tokens=100,
            compacted_tokens=0,
            removed_messages=0,
            strategy_used=CompactionStrategy.SIMPLE,
            usage=None,
        )
        assert result.estimated_token_count == estimate_text_tokens(messages)

    def test_output_tokens_zero_uses_output_field(self) -> None:
        # kosong 旧字段名兼容：output_tokens 缺省为 0 时回退 output 字段
        result = CompactionResult(
            messages=[_user("tail")],
            original_tokens=10,
            compacted_tokens=0,
            removed_messages=0,
            strategy_used=CompactionStrategy.SIMPLE,
            usage=SimpleNamespace(output_tokens=0, output=33),
        )
        assert result.estimated_token_count == 33 + estimate_text_tokens([])

    def test_empty_messages_with_usage_is_zero(self) -> None:
        result = CompactionResult(
            messages=[],
            original_tokens=10,
            compacted_tokens=0,
            removed_messages=1,
            strategy_used=CompactionStrategy.SIMPLE,
            usage=SimpleNamespace(output_tokens=50),
        )
        # messages 为空时不使用 usage（len(messages) > 0 条件）
        assert result.estimated_token_count == 0


# =============================================================================
# _part_to_text 媒体占位分支
# =============================================================================


class TestPartToTextMedia:
    """媒体 part 的压缩输入占位文本。"""

    def test_image_data_url(self) -> None:
        part = _part({"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}})
        assert _part_to_text(part) == "\n[Image attached (base64)]\n"

    def test_image_long_url_truncated_to_200(self) -> None:
        url = "http://example.com/" + "x" * 300
        part = _part({"type": "image_url", "image_url": {"url": url}})
        assert _part_to_text(part) == f"\n[Image attached: {url[:200]}]\n"

    def test_image_payload_not_dict(self) -> None:
        part = _part({"type": "image_url", "image_url": "oops"})
        assert _part_to_text(part) == "\n[Image attached: ]\n"

    def test_video_and_audio_placeholders(self) -> None:
        assert _part_to_text(_part({"type": "video_url"})) == "\n[Video attached]\n"
        assert _part_to_text(_part({"type": "audio_url"})) == "\n[Audio attached]\n"

    def test_unknown_and_missing_type(self) -> None:
        assert _part_to_text(_part({"type": "file_url"})) == "\n[file_url content attached]\n"
        assert _part_to_text(_part({})) == "\n[media content attached]\n"


# =============================================================================
# _estimate_message_tokens（tiktoken 可用路径）
# =============================================================================


class TestEstimateMessageTokensWithTiktoken:
    """tiktoken 路径：tool_calls / role 开销与未知模型回退。"""

    def test_tool_call_name_and_arguments_counted(self) -> None:
        import tiktoken

        enc = tiktoken.get_encoding("cl100k_base")
        msg = _assistant_with_tool_call("t1", name="pe_analyzer", args='{"file": "a.exe"}')
        expected = (
            4
            + len(enc.encode("calling"))
            + len(enc.encode("pe_analyzer"))
            + len(enc.encode('{"file": "a.exe"}'))
            + len(enc.encode(MessageRole.ASSISTANT.value))
        )
        assert _estimate_message_tokens([msg], "cl100k_base") == expected

    def test_empty_arguments_not_counted(self) -> None:
        import tiktoken

        enc = tiktoken.get_encoding("cl100k_base")
        msg = _assistant_with_tool_call("t1", name="tool", args="")
        expected = (
            4
            + len(enc.encode("calling"))
            + len(enc.encode("tool"))
            + len(enc.encode(MessageRole.ASSISTANT.value))
        )
        assert _estimate_message_tokens([msg], "cl100k_base") == expected

    def test_unknown_model_falls_back_to_cl100k(self) -> None:
        msg = _user("hello world")
        unknown = _estimate_message_tokens([msg], "not-a-real-model")
        assert unknown == _estimate_message_tokens([msg], "cl100k_base")


# =============================================================================
# _protect_tool_pairs 不动点迭代
# =============================================================================


class TestProtectToolPairsFixedPoint:
    """被压缩区/保留区拆散的调用对整体挪入保留区（迭代到不动点）。"""

    def test_single_split_pair_moves_assistant(self) -> None:
        old, recent = _protect_tool_pairs({0}, {1}, {0: [1]})
        assert old == set()
        assert recent == {0, 1}

    def test_chained_pairs_need_second_iteration(self) -> None:
        # assistant1(tool 结果 2) 先跨区挪动，第二轮才把 assistant0(结果 1) 带过去
        old, recent = _protect_tool_pairs({0, 1}, {2}, {0: [1], 1: [2]})
        assert old == set()
        assert recent == {0, 1, 2}

    def test_unsplit_pair_untouched(self) -> None:
        old, recent = _protect_tool_pairs({0, 1}, {2, 3}, {0: [1]})
        assert old == {0, 1}
        assert recent == {2, 3}


# =============================================================================
# MicroCompact / SnipCompact 无操作分支
# =============================================================================


class TestMicroCompactNoClearSet:
    """可清理集合为空（keep_recent 覆盖全部）时零改动零节省。"""

    def test_keep_recent_covers_all_tools(self) -> None:
        messages = [
            _assistant_with_tool_call("t1"),
            _tool("result one", "t1"),
            _assistant_with_tool_call("t2"),
            _tool("result two", "t2"),
        ]
        micro = MicroCompact(compactable_tools={"pe_analyzer"}, keep_recent=2)
        result, saved = micro.compact(messages, model="cl100k_base")
        assert saved == 0
        assert result == messages


class TestSnipCompactNoopBranches:
    """SnipCompact 无操作分支：比例为 1、消息为空。"""

    def test_ratio_one_keeps_everything(self) -> None:
        messages = [_user(f"m{i}") for i in range(6)]
        snip = SnipCompact(max_snip_ratio=1.0)
        result, freed = snip.compact(messages, model="cl100k_base")
        assert freed == 0
        assert result == messages

    def test_empty_messages_noop(self) -> None:
        snip = SnipCompact()
        result, freed = snip.compact([], model="cl100k_base")
        assert (result, freed) == ([], 0)


# =============================================================================
# Compactor：小历史保留 system 回归 + SELECTIVE/LAYERED 分支
# =============================================================================


class TestCompactorSmallHistoryKeepsSystem:
    """回归：无需压缩的小历史必须原样返回全部消息（含 system）。

    原实现 _compact_simple/_compactive_selective 的 no-op 分支返回
    non_system，会静默丢弃系统提示消息（与 LAYERED/SnipCompact 行为不一致）。
    """

    def _small_history(self) -> list[Message]:
        return [
            Message(role=MessageRole.SYSTEM, content="You are a Windows RE assistant."),
            _user("turn 1"),
            _user("turn 2"),
        ]

    def test_simple_noop_keeps_system(self) -> None:
        comp = Compactor(strategy=CompactionStrategy.SIMPLE, max_tokens=100000)
        messages = self._small_history()
        result, report = comp.compact(messages, model="cl100k_base")
        assert result == messages
        assert report.removed_messages == 0
        assert result[0].role == MessageRole.SYSTEM

    def test_selective_noop_keeps_system(self) -> None:
        comp = Compactor(strategy=CompactionStrategy.SELECTIVE, max_tokens=100000)
        messages = self._small_history()
        result, _report = comp.compact(messages, model="cl100k_base")
        assert result == messages
        assert result[0].role == MessageRole.SYSTEM


class TestCompactorExtraBranches:
    """max_tokens 属性、SELECTIVE 短工具结果、LAYERED 空消息与旧摘要截断。"""

    def test_max_tokens_property(self) -> None:
        comp = Compactor(strategy=CompactionStrategy.SIMPLE, max_tokens=123456)
        assert comp.max_tokens == 123456

    def test_selective_short_old_tool_result_kept_as_is(self) -> None:
        comp = Compactor(strategy=CompactionStrategy.SELECTIVE, max_tokens=100000)
        short = "S" * 100  # <= 2*_TRUNCATE_KEEP，不应截断
        messages = [_tool(short, "tc_0"), *[_user(f"turn {i}") for i in range(7)]]
        result, _ = comp.compact(messages, model="cl100k_base")
        old_short = [m for m in result if m.role == MessageRole.TOOL and m.tool_call_id == "tc_0"]
        assert len(old_short) == 1
        from winreverse.soul.compaction import _message_text

        assert _message_text(old_short[0]) == short

    def test_layered_skips_empty_old_messages(self) -> None:
        comp = Compactor(strategy=CompactionStrategy.LAYERED, max_tokens=100000)
        messages = [_user(""), *[_user(f"turn {i}") for i in range(1, 10)]]
        result, _ = comp.compact(messages, model="cl100k_base")
        from winreverse.soul.compaction import _message_text

        summary = _message_text(result[0])
        # 旧区空消息不产生摘要条目（"…[user]: \n…"缺位），非空旧消息正常入摘要
        assert "[user]: \n" not in summary
        assert "[user]: turn 1" in summary
        assert any(_message_text(m) == "turn 8" for m in result)

    def test_layered_prior_summary_truncated_on_second_round(self) -> None:
        comp = Compactor(strategy=CompactionStrategy.LAYERED, max_tokens=100000)
        # 第一轮：旧区 16 条 × ~509 字符 ≈ 8100 > _MAX_SUMMARY_CHARS//3 (5333)
        messages = [_user("P" * 480) for _ in range(24)]
        result, _ = comp.compact(messages, model="cl100k_base")
        from winreverse.soul.compaction import _message_text

        result2, _ = comp.compact(result, model="cl100k_base")
        summary2 = _message_text(result2[0])
        assert "[Newly compacted]" in summary2
        assert "...[older summary truncated]..." in summary2


# =============================================================================
# SimpleCompaction：流式 provider 分支
# =============================================================================


class TestSimpleCompactionStreamingProvider:
    """带 generate_streaming 的 provider 走流式聚合分支。"""

    def test_streaming_chunks_accumulate_into_summary(self) -> None:
        import asyncio

        class _StreamingProvider:
            async def generate_streaming(self, messages: list[Message], model: str):
                yield {"choices": [{"delta": {"content": "part1 "}}]}
                yield {"choices": [{"delta": {"content": "part2"}}]}
                yield {"choices": []}  # 无 choices 的块应被跳过
                yield {"choices": [{"delta": {}}]}  # 空 delta 也跳过

        history = [_user(f"turn {i}") for i in range(6)]
        comp = SimpleCompaction(max_preserved_messages=2, llm_provider=_StreamingProvider())
        result = asyncio.run(comp.compact(history, model="cl100k_base"))
        from winreverse.soul.compaction import _message_text

        compacted = _message_text(result.messages[0])
        assert "part1 part2" in compacted
        assert result.usage is None
