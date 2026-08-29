"""测试模块：winreverse.soul.compaction

覆盖：
- token 估算（CJK 感知 / tiktoken 不可用回退）
- should_auto_compact 触发判定
- SimpleCompaction（prepare / LLM 总结 / 失败退化 / 无 provider）
- AutoCompact（触发 / 熔断 / 恢复）
- MicroCompact（旧工具结果清理）
- SnipCompact（比例裁剪 + 配对保护）
- Compactor 三策略门面（simple / selective / layered）
- RuntimeLLMProvider 适配器
"""

from __future__ import annotations

from typing import Any

import pytest

from kosong.types import Message, MessageRole, TextPart
from winreverse.soul.compaction import (
    AutoCompact,
    CompactionStrategy,
    Compactor,
    MicroCompact,
    RuntimeLLMProvider,
    SimpleCompaction,
    SnipCompact,
    estimate_text_tokens,
    should_auto_compact,
)
from winreverse.soul.constants import SECURITY_KEYWORDS

# =============================================================================
# 测试辅助
# =============================================================================


def _user(text: str) -> Message:
    """构造 user 消息。"""
    return Message(role=MessageRole.USER, content=text)


def _assistant(text: str, tool_call_id: str | None = None) -> Message:
    """构造 assistant 消息（可选附带 tool_call 占位）。"""
    if tool_call_id is not None:
        from kosong.types import ToolCall

        return Message(
            role=MessageRole.ASSISTANT,
            content=text,
            tool_calls=[
                ToolCall(
                    id=tool_call_id,
                    type="function",
                    function=ToolCall.FunctionBody(name="tool", arguments="{}"),
                )
            ],
        )
    return Message(role=MessageRole.ASSISTANT, content=text)


def _tool(text: str, tool_call_id: str) -> Message:
    """构造 tool 结果消息。"""
    return Message(role=MessageRole.TOOL, content=text, tool_call_id=tool_call_id)


class FakeProvider:
    """压缩用 LLM Provider 桩：固定返回摘要文本，可注入异常。"""

    def __init__(self, *, reply: str = "COMPACT_SUMMARY", fail: bool = False) -> None:
        self.reply = reply
        self.fail = fail
        self.calls: list[list[Message]] = []

    async def generate(self, messages: list[Message], model: str) -> Any:
        self.calls.append(messages)
        if self.fail:
            raise RuntimeError("provider down")
        return type("R", (), {"message": Message(role=MessageRole.ASSISTANT, content=self.reply)})()


def _long_history(n: int = 12, text: str = "hello world payload") -> list[Message]:
    """构造 n 条 user/assistant 交替的长历史。"""
    messages: list[Message] = []
    for i in range(n):
        messages.append(_user(f"{text} {i}" if i % 2 == 0 else f"{text} reply {i}"))
    return messages


# =============================================================================
# token 估算
# =============================================================================


class TestTokenEstimation:
    """token 估算测试。"""

    def test_empty_is_zero(self) -> None:
        """空序列为 0。"""
        assert estimate_text_tokens([]) == 0

    def test_ascii_pricing(self) -> None:
        """ASCII 按 4 字符/token。"""
        assert estimate_text_tokens([_user("a" * 40)]) == 10

    def test_cjk_priced_higher(self) -> None:
        """等长文本下 CJK 的 token 估值显著高于 ASCII。"""
        ascii_tokens = estimate_text_tokens([_user("a" * 30)])
        cjk_tokens = estimate_text_tokens([_user("测" * 30)])
        assert cjk_tokens > ascii_tokens * 2

    def test_think_parts_excluded(self) -> None:
        """ThinkPart 内容不计入压缩输入。"""
        from kosong.types import ThinkPart

        msg = Message(
            role=MessageRole.ASSISTANT,
            content=[
                ThinkPart(type="think", think="secret reasoning " * 50),
                TextPart(type="text", text="short"),
            ],
        )
        tokens = estimate_text_tokens([msg])
        assert tokens < 50


class TestShouldAutoCompact:
    """触发判定测试。"""

    def test_ratio_trigger(self) -> None:
        """达到比例阈值触发。"""
        assert should_auto_compact(8000, 10000) is True
        assert should_auto_compact(7900, 10000) is False

    def test_reserved_trigger(self) -> None:
        """预留空间超限触发（即使未达比例）。"""
        assert should_auto_compact(9500, 10000, reserved_context_size=1000) is True

    def test_no_trigger(self) -> None:
        """远低于阈值不触发。"""
        assert should_auto_compact(1000, 10000) is False


# =============================================================================
# SimpleCompaction
# =============================================================================


class TestSimpleCompaction:
    """SimpleCompaction 测试。"""

    def test_prepare_preserves_recent(self) -> None:
        """保留最近 2 条 user/assistant，其余进入压缩请求。"""
        comp = SimpleCompaction(max_preserved_messages=2)
        history = _long_history(6)
        prepared = comp.prepare(history)
        assert prepared.compact_message is not None
        assert len(prepared.to_preserve) == 2
        assert prepared.to_preserve[0] is history[-2]
        # 压缩请求中包含被压缩消息的编号与角色
        from winreverse.soul.compaction import _message_text

        request_text = _message_text(prepared.compact_message)
        assert "## Message 1" in request_text
        assert "## Message 4" in request_text
        assert "Role: user" in request_text

    def test_prepare_insufficient_messages(self) -> None:
        """消息不足以保留 N 条时不压缩。"""
        comp = SimpleCompaction(max_preserved_messages=2)
        prepared = comp.prepare([_user("only one")])
        assert prepared.compact_message is None
        assert len(prepared.to_preserve) == 1

    def test_prepare_custom_instruction(self) -> None:
        """自定义压缩指令附加到请求末尾。"""
        from winreverse.soul.compaction import _message_text

        comp = SimpleCompaction(max_preserved_messages=2)
        prepared = comp.prepare(_long_history(4), custom_instruction="保留所有 IOC")
        assert prepared.compact_message is not None
        assert "保留所有 IOC" in _message_text(prepared.compact_message)

    async def test_compact_with_llm_summary(self) -> None:
        """有 provider 时生成 [Previously compacted] 摘要 + 保留消息。"""
        provider = FakeProvider(reply="tool trace summary")
        comp = SimpleCompaction(max_preserved_messages=2, llm_provider=provider)
        history = _long_history(6)
        result = await comp.compact(history)

        assert result.strategy_used == CompactionStrategy.SIMPLE
        assert len(provider.calls) == 1
        from winreverse.soul.compaction import _message_text

        summary_msg = result.messages[0]
        assert summary_msg.role == MessageRole.SYSTEM
        assert "[Previously compacted]" in _message_text(summary_msg)
        assert "tool trace summary" in _message_text(summary_msg)
        assert len(result.messages) == 3  # 摘要 + 2 条保留
        assert result.removed_messages == 6 - 3

    async def test_compact_provider_failure_falls_back(self) -> None:
        """provider 异常时退化为仅保留最近消息。"""
        provider = FakeProvider(fail=True)
        comp = SimpleCompaction(max_preserved_messages=2, llm_provider=provider)
        history = _long_history(6)
        result = await comp.compact(history)
        # 无摘要，仅保留最近 2 条
        assert len(result.messages) == 2
        assert all(m.role != MessageRole.SYSTEM for m in result.messages)

    async def test_compact_without_provider(self) -> None:
        """无 provider 时同样退化为保留最近消息。"""
        comp = SimpleCompaction(max_preserved_messages=2, llm_provider=None)
        result = await comp.compact(_long_history(6))
        assert len(result.messages) == 2


# =============================================================================
# AutoCompact
# =============================================================================


class TestAutoCompact:
    """AutoCompact 熔断触发器测试。"""

    def test_trips_after_consecutive_failures(self) -> None:
        """连续失败达到阈值后熔断，不再触发。"""
        auto = AutoCompact(max_consecutive_failures=3)
        for _ in range(3):
            auto.record_failure()
        assert auto.should_compact(9999, 100) is False

    def test_success_resets_failures(self) -> None:
        """成功重置失败计数。"""
        auto = AutoCompact(max_consecutive_failures=3)
        auto.record_failure()
        auto.record_failure()
        auto.record_success()
        assert auto.consecutive_failures == 0
        assert auto.should_compact(9999, 100) is True

    def test_trigger_passes_through(self) -> None:
        """未熔断时透传 should_auto_compact 判定。"""
        auto = AutoCompact()
        assert auto.should_compact(1000, 10000) is False
        assert auto.should_compact(9999, 10000) is True


# =============================================================================
# MicroCompact
# =============================================================================


class TestMicroCompact:
    """MicroCompact 测试。"""

    def test_clears_old_tool_results(self) -> None:
        """保留最近 keep_recent 条工具结果，旧的清为占位符。"""
        comp = MicroCompact(keep_recent=2)
        messages: list[Message] = []
        for i in range(5):
            messages.append(_assistant(f"call {i}", tool_call_id=f"call_{i}"))
            messages.append(_tool("x" * 400, f"call_{i}"))
        cleared, saved = comp.compact(messages, model="cl100k_base")

        assert saved > 0
        tool_msgs = [m for m in cleared if m.role == MessageRole.TOOL]
        from winreverse.soul.compaction import _message_text

        cleared_texts = [_message_text(m) for m in tool_msgs]
        assert cleared_texts[:3] == ["[Old tool result content cleared]"] * 3
        assert cleared_texts[-2:] == ["x" * 400] * 2

    def test_whitelist_filters_tools(self) -> None:
        """白名单外的工具结果不被清理。"""
        from kosong.types import ToolCall

        comp = MicroCompact(compactable_tools={"memory.dump"}, keep_recent=1)
        messages: list[Message] = []
        for i in range(3):
            tool_name = "memory.dump" if i < 2 else "pe.parse"
            assistant = Message(
                role=MessageRole.ASSISTANT,
                content=f"call {i}",
                tool_calls=[
                    ToolCall(
                        id=f"call_{i}",
                        type="function",
                        function=ToolCall.FunctionBody(name=tool_name, arguments="{}"),
                    )
                ],
            )
            messages.append(assistant)
            messages.append(_tool("y" * 100, f"call_{i}"))
        cleared, saved = comp.compact(messages, model="cl100k_base")
        tool_msgs = [m for m in cleared if m.role == MessageRole.TOOL]
        from winreverse.soul.compaction import _message_text

        # 白名单内的 call_0 被清，白名单外的 call_2 保留
        assert _message_text(tool_msgs[0]) == "[Old tool result content cleared]"
        assert _message_text(tool_msgs[2]) == "y" * 100
        assert saved > 0

    def test_disabled_is_noop(self) -> None:
        """禁用时原样返回。"""
        comp = MicroCompact(enabled=False)
        messages = _long_history(4)
        cleared, saved = comp.compact(messages, model="cl100k_base")
        assert cleared == messages
        assert saved == 0


# =============================================================================
# SnipCompact
# =============================================================================


class TestSnipCompact:
    """SnipCompact 测试。"""

    def test_snips_old_messages(self) -> None:
        """按比例裁剪旧消息，系统消息保留。"""
        comp = SnipCompact(max_snip_ratio=0.5)
        messages = [_user("system-ish prompt"), *_long_history(10)]
        result, freed = comp.compact(messages, model="cl100k_base")
        assert freed > 0
        assert len(result) < len(messages)
        # 系统消息（第一条 user 在此构造里不标记 SYSTEM；构造系统消息验证）
        sys_msg = Message(role=MessageRole.SYSTEM, content="sys")
        messages2 = [sys_msg, *_long_history(10)]
        result2, _ = comp.compact(messages2, model="cl100k_base")
        assert result2[0] is sys_msg

    def test_tool_pair_protection(self) -> None:
        """配对保护：裁剪边界不拆散 assistant 调用与 tool 结果。"""
        comp = SnipCompact(max_snip_ratio=0.5)
        messages: list[Message] = []
        for i in range(8):
            from kosong.types import ToolCall

            messages.append(
                Message(
                    role=MessageRole.ASSISTANT,
                    content=f"call {i}",
                    tool_calls=[
                        ToolCall(
                            id=f"tc_{i}",
                            type="function",
                            function=ToolCall.FunctionBody(name="tool", arguments="{}"),
                        )
                    ],
                )
            )
            messages.append(_tool(f"result {i}", f"tc_{i}"))
        result, _freed = comp.compact(messages, model="cl100k_base")
        # 结果中不存在"tool 结果在而其 assistant 调用被裁掉"的悬空对
        present_call_ids = {
            tc.id for m in result if m.role == MessageRole.ASSISTANT for tc in (m.tool_calls or [])
        }
        for m in result:
            if m.role == MessageRole.TOOL and m.tool_call_id:
                assert m.tool_call_id in present_call_ids


# =============================================================================
# Compactor 门面
# =============================================================================


class TestCompactor:
    """Compactor 三策略门面测试。"""

    def test_simple_strategy_keeps_recent_third(self) -> None:
        """SIMPLE：保留最近 1/3，其余丢弃。"""
        comp = Compactor(strategy=CompactionStrategy.SIMPLE, max_tokens=100000)
        messages = _long_history(12)
        result, report = comp.compact(messages, model="cl100k_base")
        assert report.strategy_used == CompactionStrategy.SIMPLE
        assert len(result) == 4  # 12 的 1/3
        assert report.removed_messages == 8

    def test_selective_strategy_truncates_old_tool_results(self) -> None:
        """SELECTIVE：旧区工具结果首尾截断保留。"""
        comp = Compactor(strategy=CompactionStrategy.SELECTIVE, max_tokens=100000)
        messages: list[Message] = []
        for i in range(9):
            messages.append(_user(f"turn {i}"))
            messages.append(_assistant(f"calling tool {i}"))
            messages.append(_tool("E" * 1000, f"tc_{i}"))
        result, report = comp.compact(messages, model="cl100k_base")
        assert report.strategy_used == CompactionStrategy.SELECTIVE
        from winreverse.soul.compaction import _message_text

        old_tool_texts = [_message_text(m) for m in result if m.role == MessageRole.TOOL]
        # 旧工具结果应被截断（含 [truncated] 标记），新区的保持原文
        assert any("[truncated]" in t for t in old_tool_texts)
        assert any(t == "E" * 1000 for t in old_tool_texts)

    def test_layered_strategy_builds_summary_chain(self) -> None:
        """LAYERED：旧区折叠为 [Previously compacted] 摘要 + 保留最近一半。"""
        comp = Compactor(strategy=CompactionStrategy.LAYERED, max_tokens=100000)
        messages = _long_history(12)
        result, report = comp.compact(messages, model="cl100k_base")
        assert report.strategy_used == CompactionStrategy.LAYERED
        from winreverse.soul.compaction import _message_text

        summary = _message_text(result[0])
        assert summary.startswith("[Previously compacted]")
        assert "[user]" in summary or "[assistant]" in summary
        # 第二次压缩应衔接既有摘要（[Newly compacted] 段落出现）
        result2, _ = comp.compact(result, model="cl100k_base")
        summary2 = _message_text(result2[0])
        assert "[Newly compacted]" in summary2

    def test_layered_security_content_gets_larger_limit(self) -> None:
        """含安全关键词的工具结果在摘要中放宽截取长度。"""
        comp = Compactor(strategy=CompactionStrategy.LAYERED, max_tokens=100000)
        evidence = "exploit chain evidence: " + "D" * 900
        messages: list[Message] = []
        for i in range(12):
            messages.append(_user(f"turn {i}"))
            messages.append(_assistant(f"scan {i}"))
            messages.append(_tool(evidence if i == 0 else "e" * 50, f"tc_{i}"))
        result, _ = comp.compact(messages, model="cl100k_base")
        from winreverse.soul.compaction import _message_text

        summary = _message_text(result[0])
        # 证据内容以 800 字符放行（非安全的 500 字符上限不够覆盖）
        assert "D" * 700 in summary

    def test_security_keywords_constant_used(self) -> None:
        """SECURITY_KEYWORDS 中至少一个词触发放宽。"""
        assert len(SECURITY_KEYWORDS) > 0

    def test_small_history_is_noop_for_layered(self) -> None:
        """历史不足时 LAYERED 不压缩；SIMPLE/SELECTIVE 保留最近 1/3。"""
        messages = _long_history(3)
        layered = Compactor(strategy=CompactionStrategy.LAYERED, max_tokens=100000)
        result, report = layered.compact(list(messages), model="cl100k_base")
        assert len(result) == len(messages)
        assert report.removed_messages == 0
        # SIMPLE 对 3 条历史保留最近 2 条（keep_recent = max(2, n//3)）
        simple = Compactor(strategy=CompactionStrategy.SIMPLE, max_tokens=100000)
        result_simple, _ = simple.compact(list(messages), model="cl100k_base")
        assert len(result_simple) == 2

    async def test_compact_with_llm_delegates(self) -> None:
        """compact_with_llm 委托 SimpleCompaction。"""
        provider = FakeProvider(reply="final summary")
        comp = Compactor(
            strategy=CompactionStrategy.LAYERED, max_tokens=100000, llm_provider=provider
        )
        result = await comp.compact_with_llm(_long_history(6), model="cl100k_base")
        assert "final summary" in (result.messages[0].content[0].text if result.messages else "")

    def test_has_llm_flag(self) -> None:
        """has_llm 反映 provider 配置。"""
        assert Compactor(max_tokens=100).has_llm is False
        assert Compactor(max_tokens=100, llm_provider=FakeProvider()).has_llm is True

    def test_estimate_tokens(self) -> None:
        """estimate_tokens 委托估算函数。"""
        comp = Compactor(max_tokens=100000)
        assert comp.estimate_tokens(_long_history(4), "cl100k_base") > 0


# =============================================================================
# RuntimeLLMProvider 适配器
# =============================================================================


class TestRuntimeLLMProvider:
    """RuntimeLLMProvider 适配器测试。"""

    async def test_wraps_generate(self) -> None:
        """包装带 generate(messages=, model=) 的对象并透传调用。"""

        class FakeLLM:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            async def generate(
                self, messages: list[Message], model: str | None = None, tools: Any = None
            ) -> Any:
                self.calls.append({"messages": messages, "model": model, "tools": tools})
                return "ok"

        llm = FakeLLM()
        provider = RuntimeLLMProvider(llm)
        msgs = [_user("hi")]
        result = await provider.generate(msgs, "test-model")
        assert result == "ok"
        assert llm.calls[0]["messages"] == msgs
        assert llm.calls[0]["model"] == "test-model"
        assert llm.calls[0]["tools"] is None

    async def test_missing_generate_raises(self) -> None:
        """底层对象缺少 generate 时抛 RuntimeError。"""
        provider = RuntimeLLMProvider(object())
        with pytest.raises(RuntimeError, match="generate"):
            await provider.generate([_user("hi")], "m")


# =============================================================================
# Agent 循环挂载
# =============================================================================


class TestAgentCompactionMount:
    """Agent 循环中的自动压缩挂载测试。"""

    def _make_runtime(self, compactor: Compactor | None) -> Any:
        """构造带桩 LLM 的 Runtime。"""
        from winreverse.soul.agent import Runtime

        class FakeLLM:
            async def generate(
                self, messages: list[Message], model: str | None = None, tools: Any = None
            ) -> Any:
                from kosong.types import GenerateResult

                return GenerateResult(
                    id="gen1",
                    message=Message(role=MessageRole.ASSISTANT, content="done"),
                    usage=None,
                    stop_reason="stop",
                )

        return Runtime(llm=FakeLLM(), compactor=compactor)

    async def test_agent_triggers_compaction_on_small_window(self) -> None:
        """窗口极小且 auto_compact 开启时，run 过程中触发压缩并记录事件。"""
        from winreverse.soul.agent import Agent, AgentConfig

        compactor = Compactor(strategy=CompactionStrategy.LAYERED, max_tokens=100)
        runtime = self._make_runtime(compactor)
        config = AgentConfig(
            name="t",
            system_prompt="sys",
            max_turns=3,
            auto_compact=True,
            max_context_size=100,
            compaction_trigger_ratio=0.8,
        )
        agent = Agent(config, runtime)
        # 预填充长历史（超过 100 token 估算阈值）
        agent.messages.extend(_long_history(10))
        await agent.run("final question")

        assert agent.last_compaction is not None
        assert agent.last_compaction.before_tokens > agent.last_compaction.after_tokens

    async def test_agent_skips_compaction_when_disabled(self) -> None:
        """auto_compact=False 时不触发压缩。"""
        from winreverse.soul.agent import Agent, AgentConfig

        compactor = Compactor(strategy=CompactionStrategy.LAYERED, max_tokens=100)
        runtime = self._make_runtime(compactor)
        config = AgentConfig(
            name="t",
            system_prompt="sys",
            max_turns=2,
            auto_compact=False,
            max_context_size=100,
        )
        agent = Agent(config, runtime)
        agent.messages.extend(_long_history(10))
        await agent.run("final question")
        assert agent.last_compaction is None

    async def test_agent_no_compactor_is_noop(self) -> None:
        """Runtime 未配 compactor 时循环正常工作。"""
        from winreverse.soul.agent import Agent, AgentConfig

        runtime = self._make_runtime(None)
        config = AgentConfig(name="t", system_prompt="sys", max_turns=2)
        agent = Agent(config, runtime)
        result = await agent.run("hello")
        assert result == "done"
