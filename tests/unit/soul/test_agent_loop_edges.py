"""测试模块：winreverse.soul.agent 循环边界。

覆盖 run() 的 on_assistant_text 回调（异常吞掉/空白文本不推送）、
total_usage 累计与 steps 计数、list 内容最终答复拼接、
context_snapshot（有/无 compactor、字典隔离）与 _should_continue 分支真值表。
"""

from __future__ import annotations

from types import SimpleNamespace

from kosong.types import GenerateResult, Message, MessageRole, TextPart, ToolCall, Usage
from winreverse.soul.agent import Agent, AgentConfig, AgentState, Runtime, StepResult


class _ScriptedLLM:
    """按脚本顺序返回 GenerateResult 的最小 LLM 桩。"""

    def __init__(self, responses: list[GenerateResult]) -> None:
        self._responses = list(responses)
        self._call_count = 0

    async def generate(self, messages, model=None, tools=None) -> GenerateResult:
        _ = messages, model, tools
        if self._call_count >= len(self._responses):
            return GenerateResult(
                message=Message(role=MessageRole.ASSISTANT, content="done"),
                stop_reason="stop",
                usage=Usage(),
            )
        response = self._responses[self._call_count]
        self._call_count += 1
        return response


def _gr(
    content: str,
    stop_reason: str = "stop",
    usage: Usage | None = Usage(),
    tool_calls: list[ToolCall] | None = None,
) -> GenerateResult:
    return GenerateResult(
        message=Message(
            role=MessageRole.ASSISTANT,
            content=content,
            tool_calls=tool_calls or [],
        ),
        stop_reason=stop_reason,
        usage=usage,
    )


def _tool_call() -> ToolCall:
    return ToolCall(id="c1", function=ToolCall.FunctionBody(name="t", arguments="{}"))


def _two_step_agent(**cfg) -> Agent:
    """首步 tool_use（无 toolset → 工具结果为 error）→ 次步收尾的两步脚本。"""
    return _agent(
        [
            _gr(
                "思考中",
                stop_reason="tool_use",
                usage=Usage(input_tokens=10, output_tokens=5),
                tool_calls=[_tool_call()],
            ),
            _gr("final", usage=Usage(input_tokens=7, output_tokens=2)),
        ],
        **cfg,
    )


def _agent(responses: list[GenerateResult], **cfg) -> Agent:
    config = AgentConfig(name="t", system_prompt="s", **cfg)
    return Agent(config, Runtime(llm=_ScriptedLLM(responses)))


class TestOnAssistantText:
    """run() 的 assistant 文本实时回调。"""

    async def test_callback_receives_each_assistant_text(self) -> None:
        texts: list[str] = []
        agent = _two_step_agent()
        agent.on_assistant_text = texts.append
        await agent.run("hi")
        assert texts == ["思考中", "final"]

    async def test_callback_exception_does_not_break_run(self) -> None:
        def boom(_text: str) -> None:
            raise RuntimeError("TUI 崩了")

        agent = _agent([_gr("ok")])
        agent.on_assistant_text = boom
        assert await agent.run("hi") == "ok"
        assert agent.state == AgentState.FINISHED

    async def test_whitespace_only_text_not_pushed(self) -> None:
        texts: list[str] = []
        agent = _agent([_gr("  \n")])
        agent.on_assistant_text = texts.append
        await agent.run("hi")
        assert texts == []


class TestUsageAccumulation:
    """step() 的 total_usage 累计。"""

    async def test_usage_summed_across_steps(self) -> None:
        agent = _two_step_agent()
        await agent.run("hi")
        assert agent.total_usage == {"input": 17, "output": 7, "steps": 2}

    async def test_usage_none_keeps_counters_at_zero(self) -> None:
        agent = _agent([_gr("ok", usage=None)])
        await agent.run("hi")
        assert agent.total_usage == {"input": 0, "output": 0, "steps": 1}


class TestContextSnapshot:
    """context_snapshot：TUI 状态栏轮询契约。"""

    def test_without_compactor_reports_zero_used(self) -> None:
        agent = _agent([])
        agent.messages.append(Message(role=MessageRole.USER, content="x"))
        snap = agent.context_snapshot()
        assert snap["messages"] == 1
        assert snap["used_tokens"] == 0
        assert snap["remaining_tokens"] == snap["max_context_size"]
        assert snap["usage_ratio"] == 0.0
        assert snap["trigger_ratio"] == 0.8
        assert snap["compaction_count"] == 0

    def test_with_compactor_estimates_and_records_model_fallback(self) -> None:
        seen: dict[str, object] = {}

        def fake_estimate(messages: list[Message], model: str) -> int:
            seen["model"] = model
            seen["count"] = len(messages)
            return 25_000

        agent = _agent([], model=None)
        agent._runtime.compactor = SimpleNamespace(estimate_tokens=fake_estimate)
        agent.messages.append(Message(role=MessageRole.USER, content="x"))
        snap = agent.context_snapshot()
        assert seen["model"] == "cl100k_base"  # config.model 为 None 时回退 tokenizer 名
        assert seen["count"] == 1
        assert snap["used_tokens"] == 25_000
        assert snap["remaining_tokens"] == 75_000
        assert snap["usage_ratio"] == 0.25

    def test_total_usage_in_snapshot_is_a_copy(self) -> None:
        agent = _agent([])
        snap = agent.context_snapshot()
        snap["total_usage"]["input"] = 999
        assert agent.total_usage["input"] == 0


class TestShouldContinue:
    """_should_continue 分支真值表（run() 进入时 state 已置 RUNNING）。"""

    @staticmethod
    def _running_agent(**cfg) -> Agent:
        agent = _agent([], **cfg)
        agent.state = AgentState.RUNNING
        return agent

    @staticmethod
    def _result(stop_reason: str, tool_calls: list[ToolCall]) -> StepResult:
        return StepResult(
            response=Message(role=MessageRole.ASSISTANT, content=""),
            tool_calls=tool_calls,
            tool_results=[],
            stop_reason=stop_reason,
        )

    def test_stop_and_end_turn_end_loop(self) -> None:
        agent = self._running_agent()
        for reason in ("stop", "end_turn"):
            assert agent._should_continue(self._result(reason, [])) is False

    def test_state_not_running_ends_loop(self) -> None:
        agent = self._running_agent()
        agent.state = AgentState.FINISHED
        assert agent._should_continue(self._result("tool_use", [_tool_call()])) is False

    def test_tool_use_with_calls_continues(self) -> None:
        agent = self._running_agent()
        assert agent._should_continue(self._result("tool_use", [_tool_call()])) is True

    def test_last_turn_never_continues(self) -> None:
        agent = self._running_agent(max_turns=3)
        agent.current_turn = 2  # max_turns - 1
        assert agent._should_continue(self._result("length", [])) is False
        # tool_use 分支优先于轮次上限判断（循环上限由 range(max_turns) 兜底）
        assert agent._should_continue(self._result("tool_use", [_tool_call()])) is True

    def test_other_stop_reason_falls_back_to_tool_calls(self) -> None:
        agent = self._running_agent(max_turns=3)
        agent.current_turn = 0
        assert agent._should_continue(self._result("length", [_tool_call()])) is True
        assert agent._should_continue(self._result("length", [])) is False


class TestFinalAnswerFromParts:
    """最终答复：assistant 消息为多部件 list 内容时按换行拼接。"""

    async def test_list_content_parts_joined_with_newline(self) -> None:
        message = Message(
            role=MessageRole.ASSISTANT,
            content=[TextPart(text="第一段"), TextPart(text="第二段")],
        )
        agent = _agent([GenerateResult(message=message, stop_reason="stop", usage=Usage())])
        assert await agent.run("hi") == "第一段\n第二段"


async def test_run_zero_turns_returns_empty() -> None:
    """max_turns=0 时循环不执行，历史无 assistant 消息，最终答复为空串。"""
    agent = _agent([], max_turns=0)
    assert await agent.run("hi") == ""
    assert agent.state == AgentState.FINISHED
    assert [m.role for m in agent.messages] == [MessageRole.USER]
