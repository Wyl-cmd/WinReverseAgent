"""测试模块：winreverse.soul.agent 的"空最终答复 / max_tokens 截断"修复（P0-3 回归门禁）。

实测背景（2026-09-15，glm-5.3-flash）：
    ``[turn 1] 149.8s stop_reason='max_tokens' tool_calls=0 parts=["TextPart(text='')"]``
    → ``FINAL_ANSWER=''``：确定性分析结果已拿到，但最终答复为空，技能对外表现为"没数据"。
    同一场景下预置执行流 5 步全部 OK。

本测试锁定：
1. ``stop_reason=max_tokens`` 时自动续写并拼接（不把截断当结论）；
2. 最终答复跳过空 TextPart/纯推理消息，取最后一条**含非空文本**的 assistant；
3. 完全空答复时做一次"不带工具"的总结兜底调用；
4. 兜底仍为空 → 抛 ``EmptyFinalAnswerError``（不许静默返回空）；
5. 未调用过 LLM（如 max_turns=0）时行为不变（返回空串）。
"""

from __future__ import annotations

from typing import Any

import pytest

from kosong.types import (
    GenerateResult,
    Message,
    MessageRole,
    TextPart,
    Tool,
    Usage,
)
from winreverse.engine.bus import ToolRegistry
from winreverse.soul.agent import (
    Agent,
    AgentConfig,
    AgentRuntime,
    EmptyFinalAnswerError,
    Runtime,
    parse_tool_call_arguments,
)
from winreverse.soul.toolset import SoulToolsetAdapter


class _ScriptedLLM:
    """按脚本顺序返回结果的 LLM 桩；记录每次调用的 tools 参数。"""

    def __init__(self, responses: list[GenerateResult]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Tool] | None = None,
    ) -> GenerateResult:
        self.calls.append({"messages": list(messages), "model": model, "tools": tools})
        if not self._responses:
            return GenerateResult(
                message=Message(role=MessageRole.ASSISTANT, content="脚本耗尽"),
                stop_reason="stop",
                usage=Usage(),
            )
        return self._responses.pop(0)


def _result(
    content: str | list[Any] = "",
    stop_reason: str = "stop",
) -> GenerateResult:
    """构造 GenerateResult（默认 messages 为空的历史）。"""
    return GenerateResult(
        message=Message(role=MessageRole.ASSISTANT, content=content),
        stop_reason=stop_reason,
        usage=Usage(),
    )


def _agent(llm: Any, **cfg: Any) -> Agent:
    """构造 Agent（可选带一个 dummy 工具集，用于断言"兜底不带工具"）。"""
    config = AgentConfig(name="t", system_prompt="sys", **cfg)
    runtime = Runtime(llm=llm)
    return Agent(config, runtime)


def _agent_with_toolset(llm: Any, **cfg: Any) -> Agent:
    class _NoopTool:
        name = "noop"
        description = "noop"

        def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
            return {"status": "success"}

    registry = ToolRegistry()
    registry.register(_NoopTool())
    config = AgentConfig(name="t", system_prompt="sys", **cfg)
    return Agent(config, Runtime(llm=llm, toolset=SoulToolsetAdapter(registry)))


class TestMaxTokensContinuation:
    """stop_reason=max_tokens → 自动续写并拼接。"""

    async def test_truncated_answer_is_continued_and_joined(self) -> None:
        llm = _ScriptedLLM(
            [
                _result("第一段：结论开头", stop_reason="max_tokens"),
                _result("第二段：结论续写结尾", stop_reason="stop"),
            ]
        )
        answer = await _agent(llm).run("分析")

        assert answer == "第一段：结论开头第二段：结论续写结尾"
        assert len(llm.calls) == 2, "应发生一次续写调用"

    async def test_empty_truncated_then_continued(self) -> None:
        """修复前的真实形态：首轮 max_tokens 且文本为空 → 续写拿到内容。"""
        llm = _ScriptedLLM(
            [
                _result("", stop_reason="max_tokens"),
                _result("续写得到的真实数据：imphash=abc", stop_reason="stop"),
            ]
        )
        answer = await _agent(llm).run("分析")

        assert answer == "续写得到的真实数据：imphash=abc"

    async def test_continuation_is_capped(self) -> None:
        """续写次数受 max_tokens_continuations 限制（防空转烧预算）。"""
        llm = _ScriptedLLM(
            [
                _result("A", stop_reason="max_tokens"),
                _result("B", stop_reason="max_tokens"),
                _result("C", stop_reason="max_tokens"),
                _result("D", stop_reason="max_tokens"),
            ]
        )
        answer = await _agent(llm, max_tokens_continuations=2).run("分析")

        assert answer == "ABC"
        assert len(llm.calls) == 3  # 1 次主调用 + 2 次续写

    async def test_continuation_empty_chunk_stops(self) -> None:
        """续写仍返回空 → 立刻停止续写，走后续兜底逻辑。"""
        llm = _ScriptedLLM(
            [
                _result("", stop_reason="max_tokens"),
                _result("", stop_reason="max_tokens"),
                _result("兜底总结：用已有信息给出结论", stop_reason="stop"),
            ]
        )
        answer = await _agent(llm, max_tokens_continuations=3).run("分析")

        assert answer == "兜底总结：用已有信息给出结论"


class TestFinalAnswerExtraction:
    """最终答复提取：跳过空文本部件，取最后一条含非空文本的 assistant。"""

    async def test_empty_text_part_falls_back_to_previous_assistant(self) -> None:
        """末条 assistant 只有空 TextPart → 回退到上一条有内容的 assistant。"""
        agent = _agent(_ScriptedLLM([]))
        agent.messages = [
            Message(role=MessageRole.USER, content="分析"),
            Message(role=MessageRole.ASSISTANT, content="有数据的结论"),
            Message(role=MessageRole.ASSISTANT, content=[TextPart(text="")]),
        ]
        assert agent._extract_final_answer() == "有数据的结论"

    async def test_all_empty_assistant_messages_yield_empty_then_error(self) -> None:
        """全部 assistant 都是空文本 → 提取为空 → 走兜底并最终报错（不静默）。"""
        llm = _ScriptedLLM([_result([TextPart(text="")], stop_reason="stop"), _result("")])
        agent = _agent(llm)
        with pytest.raises(EmptyFinalAnswerError):
            await agent.run("分析")

    async def test_parts_joined_with_newline(self) -> None:
        llm = _ScriptedLLM([_result([TextPart(text="A"), TextPart(text="B")])])
        assert await _agent(llm).run("hi") == "A\nB"

    async def test_zero_turns_returns_empty(self) -> None:
        """max_turns=0：一次 LLM 都没调用 → 保持原契约（返回空串）。"""
        llm = _ScriptedLLM([])
        agent = _agent(llm, max_turns=0)

        assert await agent.run("hi") == ""
        assert llm.calls == []
        assert [m.role for m in agent.messages] == [MessageRole.USER]


class TestEmptyAnswerFallback:
    """空答复兜底：一次不带工具的总结调用。"""

    async def test_fallback_without_tools_recovers_answer(self) -> None:
        llm = _ScriptedLLM(
            [
                _result("", stop_reason="stop"),
                _result("用已有信息给出的结论", stop_reason="stop"),
            ]
        )
        agent = _agent_with_toolset(llm)
        answer = await agent.run("分析")

        assert answer == "用已有信息给出的结论"
        assert agent.answer_fallback_used is True
        assert len(llm.calls) == 2
        assert llm.calls[0]["tools"] is not None, "首轮应带工具"
        assert llm.calls[1]["tools"] is None, "兜底总结调用不得带工具"

    async def test_still_empty_raises_readable_error(self) -> None:
        llm = _ScriptedLLM([_result("", stop_reason="stop"), _result("")])
        agent = _agent(llm)

        with pytest.raises(EmptyFinalAnswerError) as excinfo:
            await agent.run("分析")

        message = str(excinfo.value)
        assert "最终答复为空" in message
        assert "stop_reason" in message

    async def test_fallback_call_failure_is_reported_as_error(self) -> None:
        """兜底调用自身抛异常 → 不吞掉结论，转为可读错误。"""

        class _BoomLLM:
            def __init__(self) -> None:
                self.count = 0

            async def generate(
                self,
                messages: list[Message],
                model: str | None = None,
                tools: list[Tool] | None = None,
            ) -> GenerateResult:
                self.count += 1
                if self.count == 1:
                    return _result("", stop_reason="stop")
                raise RuntimeError("网络中断")

        with pytest.raises(EmptyFinalAnswerError):
            await _agent(_BoomLLM()).run("分析")


def test_parse_tool_call_arguments_unchanged() -> None:
    """回归：工具参数解析行为未被本次改动影响。"""
    assert parse_tool_call_arguments('{"a": 1}') == ({"a": 1}, None)
    args, err = parse_tool_call_arguments("not-json")
    assert args == {} and err is not None


def test_agentruntime_alias_still_available() -> None:
    """兼容别名保留。"""
    assert AgentRuntime is Runtime
