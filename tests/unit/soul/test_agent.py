"""测试模块：winreverse.soul.agent

覆盖 Agent 类的 run/step 循环、parse_tool_call_arguments、Runtime、_should_continue。
使用 mock LLM 避免真实 API 调用。
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kosong.types import (
    GenerateResult,
    Message,
    MessageRole,
    Tool,
    ToolCall,
    Usage,
)
from winreverse.engine.bus import ToolRegistry
from winreverse.soul.agent import (
    Agent,
    AgentConfig,
    AgentRuntime,
    AgentState,
    Runtime,
    StepResult,
    parse_tool_call_arguments,
)
from winreverse.soul.toolset import SoulToolsetAdapter

# =============================================================================
# Mock LLM 实现
# =============================================================================


class _MockLLM:
    """Mock LLM 生成器，按预设脚本返回结果。"""

    def __init__(self, responses: list[GenerateResult]) -> None:
        self._responses = list(responses)
        self._call_count = 0

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Tool] | None = None,
    ) -> GenerateResult:
        _ = messages, model, tools
        if self._call_count >= len(self._responses):
            # 超出预设时返回终止消息
            return GenerateResult(
                message=Message(role=MessageRole.ASSISTANT, content="已完成"),
                stop_reason="stop",
                usage=Usage(),
            )
        response = self._responses[self._call_count]
        self._call_count += 1
        return response


def _make_generate_result(
    content: str = "",
    tool_calls: list[ToolCall] | None = None,
    stop_reason: str = "stop",
) -> GenerateResult:
    """构造 GenerateResult 辅助函数。"""
    return GenerateResult(
        message=Message(
            role=MessageRole.ASSISTANT,
            content=content,
            tool_calls=tool_calls or [],
        ),
        stop_reason=stop_reason,
        usage=Usage(),
    )


def _make_tool_call(name: str, arguments: dict[str, Any], call_id: str = "call_1") -> ToolCall:
    """构造 ToolCall 辅助函数。"""
    return ToolCall(
        id=call_id,
        function=ToolCall.FunctionBody(name=name, arguments=json.dumps(arguments)),
    )


# =============================================================================
# AgentConfig 测试
# =============================================================================


class TestAgentConfig:
    """AgentConfig 配置测试。"""

    def test_create_minimal(self) -> None:
        """创建最小化配置。"""
        config = AgentConfig(name="test", system_prompt="你是助手")
        assert config.name == "test"
        assert config.system_prompt == "你是助手"
        assert config.tools == []
        assert config.model is None
        assert config.agent_type == "default"
        assert config.max_turns == 50

    def test_create_full(self) -> None:
        """创建完整配置。"""
        config = AgentConfig(
            name="reverse",
            system_prompt="你是逆向专家",
            tools=["pe.parse"],
            model="gpt-4",
            agent_type="reverse",
            max_turns=10,
        )
        assert config.tools == ["pe.parse"]
        assert config.model == "gpt-4"
        assert config.agent_type == "reverse"
        assert config.max_turns == 10


# =============================================================================
# AgentState 枚举测试
# =============================================================================


class TestAgentState:
    """AgentState 枚举测试。"""

    def test_state_values(self) -> None:
        """枚举值正确。"""
        assert AgentState.IDLE.value == "idle"
        assert AgentState.RUNNING.value == "running"
        assert AgentState.WAITING_APPROVAL.value == "waiting_approval"
        assert AgentState.FINISHED.value == "finished"
        assert AgentState.FAILED.value == "failed"


# =============================================================================
# parse_tool_call_arguments 测试
# =============================================================================


class TestParseToolCallArguments:
    """parse_tool_call_arguments 函数测试。"""

    def test_none_returns_empty_dict(self) -> None:
        """None 返回空字典。"""
        args, err = parse_tool_call_arguments(None)
        assert args == {}
        assert err is None

    def test_dict_returned_directly(self) -> None:
        """dict 直接返回。"""
        original = {"key": "value"}
        args, err = parse_tool_call_arguments(original)
        assert args is original
        assert err is None

    def test_empty_string_returns_empty_dict(self) -> None:
        """空字符串返回空字典。"""
        args, err = parse_tool_call_arguments("")
        assert args == {}
        assert err is None

    def test_whitespace_string_returns_empty_dict(self) -> None:
        """空白字符串返回空字典。"""
        args, err = parse_tool_call_arguments("   ")
        assert args == {}
        assert err is None

    def test_valid_json_string(self) -> None:
        """合法 JSON 字符串解析成功。"""
        args, err = parse_tool_call_arguments('{"key": "value", "num": 42}')
        assert args == {"key": "value", "num": 42}
        assert err is None

    def test_invalid_json_string(self) -> None:
        """非法 JSON 字符串返回错误。"""
        args, err = parse_tool_call_arguments("{invalid json}")
        assert args == {}
        assert err is not None
        assert "Invalid JSON" in err

    def test_json_array_returns_error(self) -> None:
        """JSON 数组返回错误（必须是对象）。"""
        args, err = parse_tool_call_arguments("[1, 2, 3]")
        assert args == {}
        assert err is not None
        assert "JSON object" in err

    def test_unsupported_type(self) -> None:
        """不支持的类型返回错误。"""
        args, err = parse_tool_call_arguments(123)
        assert args == {}
        assert err is not None
        assert "Unsupported" in err


# =============================================================================
# Runtime 测试
# =============================================================================


class TestRuntime:
    """Runtime 运行时测试。"""

    def test_init_defaults(self) -> None:
        """默认初始化。"""
        runtime = Runtime()
        assert runtime.llm is None
        assert runtime.toolset is None
        assert runtime.app_config is None

    @pytest.mark.asyncio
    async def test_call_llm_without_llm_raises(self) -> None:
        """未配置 LLM 时调用抛出异常。"""
        runtime = Runtime()
        with pytest.raises(RuntimeError, match="LLM manager not initialized"):
            await runtime.call_llm("agent-1", [])

    @pytest.mark.asyncio
    async def test_call_llm_with_mock(self) -> None:
        """使用 mock LLM 调用成功。"""
        mock_llm = _MockLLM([_make_generate_result(content="hello")])
        runtime = Runtime(llm=mock_llm)

        result = await runtime.call_llm("agent-1", [Message(role=MessageRole.USER, content="hi")])

        # kosong Message.content 可能是 str 或 list[ContentPart]
        content = result.message.content
        if isinstance(content, list):
            text_parts = [p.text for p in content if hasattr(p, "text")]
            assert "hello" in "".join(text_parts)
        else:
            assert content == "hello"

    @pytest.mark.asyncio
    async def test_call_llm_without_toolset(self) -> None:
        """无 toolset 时不传 tools 参数。"""
        mock_llm = _MockLLM([_make_generate_result(content="ok")])
        runtime = Runtime(llm=mock_llm)

        result = await runtime.call_llm("agent-1", [])

        content = result.message.content
        if isinstance(content, list):
            text_parts = [p.text for p in content if hasattr(p, "text")]
            assert "ok" in "".join(text_parts)
        else:
            assert content == "ok"

    @pytest.mark.asyncio
    async def test_call_llm_with_toolset(self) -> None:
        """有 toolset 时传递 kosong Tools 给 LLM。"""

        # 构造一个带工具的 registry
        class _Tool:
            name = "test.tool"
            description = "test"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {"status": "success"}

        registry = ToolRegistry()
        registry.register(_Tool())
        adapter = SoulToolsetAdapter(registry)

        mock_llm = _MockLLM([_make_generate_result(content="ok")])
        runtime = Runtime(llm=mock_llm, toolset=adapter)

        result = await runtime.call_llm("agent-1", [])

        content = result.message.content
        if isinstance(content, list):
            text_parts = [p.text for p in content if hasattr(p, "text")]
            assert "ok" in "".join(text_parts)
        else:
            assert content == "ok"

    @pytest.mark.asyncio
    async def test_execute_tool_without_toolset_raises(self) -> None:
        """未配置 toolset 时 execute_tool 抛出异常。"""
        runtime = Runtime()
        with pytest.raises(RuntimeError, match="no toolset configured"):
            await runtime.execute_tool("agent-1", "test.tool", {})

    @pytest.mark.asyncio
    async def test_execute_tool_with_toolset(self) -> None:
        """通过 toolset 调用工具。"""

        class _Tool:
            name = "test.tool"
            description = "test"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {"status": "success", "echo": input_data.get("msg")}

        registry = ToolRegistry()
        registry.register(_Tool())
        adapter = SoulToolsetAdapter(registry)
        runtime = Runtime(toolset=adapter)

        output = await runtime.execute_tool("agent-1", "test.tool", {"msg": "hello"})

        assert "hello" in output
        assert "success" in output

    @pytest.mark.asyncio
    async def test_execute_tool_with_non_dict_arguments(self) -> None:
        """非 dict 参数被替换为空字典。"""

        class _Tool:
            name = "test.tool"
            description = "test"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {"status": "success", "received": input_data}

        registry = ToolRegistry()
        registry.register(_Tool())
        adapter = SoulToolsetAdapter(registry)
        runtime = Runtime(toolset=adapter)

        # 传入非 dict 参数应被替换为 {}
        output = await runtime.execute_tool("agent-1", "test.tool", "not a dict")

        assert "success" in output

    def test_agent_runtime_alias(self) -> None:
        """AgentRuntime 是 Runtime 的别名。"""
        assert AgentRuntime is Runtime


# =============================================================================
# Agent.run 测试
# =============================================================================


class TestAgentRun:
    """Agent.run 主循环测试。"""

    @pytest.mark.asyncio
    async def test_simple_response(self) -> None:
        """LLM 直接返回文本，无工具调用。"""
        mock_llm = _MockLLM(
            [
                _make_generate_result(content="你好，我是助手", stop_reason="stop"),
            ]
        )
        runtime = Runtime(llm=mock_llm)
        agent = Agent(
            config=AgentConfig(name="test", system_prompt="你是助手", max_turns=5),
            runtime=runtime,
        )

        result = await agent.run("你好")

        assert result == "你好，我是助手"
        assert agent.state == AgentState.FINISHED
        assert len(agent.messages) == 2  # user + assistant

    @pytest.mark.asyncio
    async def test_tool_call_then_finish(self) -> None:
        """LLM 调用工具后返回最终结果。"""

        # 构造带工具的 runtime
        class _EchoTool:
            name = "echo"
            description = "回显工具"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {"status": "success", "echoed": input_data.get("msg", "")}

        registry = ToolRegistry()
        registry.register(_EchoTool())
        adapter = SoulToolsetAdapter(registry)

        mock_llm = _MockLLM(
            [
                _make_generate_result(
                    content="",
                    tool_calls=[_make_tool_call("echo", {"msg": "hello"})],
                    stop_reason="tool_use",
                ),
                _make_generate_result(content="已回显: hello", stop_reason="stop"),
            ]
        )
        runtime = Runtime(llm=mock_llm, toolset=adapter)
        agent = Agent(
            config=AgentConfig(name="test", system_prompt="你是助手", max_turns=5),
            runtime=runtime,
        )

        result = await agent.run("回显 hello")

        assert "已回显" in result
        assert agent.state == AgentState.FINISHED
        # 消息历史: user + assistant(tool_call) + tool(result) + assistant(final)
        assert len(agent.messages) == 4

    @pytest.mark.asyncio
    async def test_max_turns_reached(self) -> None:
        """达到 max_turns 后停止。"""
        # LLM 始终返回 tool_use，强制达到 max_turns
        mock_llm = _MockLLM(
            [
                _make_generate_result(
                    content=f"turn {i}",
                    tool_calls=[_make_tool_call("noop", {})],
                    stop_reason="tool_use",
                )
                for i in range(10)
            ]
        )

        # 无工具的 runtime，工具调用会失败
        runtime = Runtime(llm=mock_llm)
        agent = Agent(
            config=AgentConfig(name="test", system_prompt="", max_turns=3),
            runtime=runtime,
        )

        await agent.run("test")

        # 达到 max_turns 后停止
        assert agent.state == AgentState.FINISHED
        assert agent.current_turn == 2  # 0-indexed

    @pytest.mark.asyncio
    async def test_end_turn_stop_reason(self) -> None:
        """stop_reason='end_turn' 立即停止。"""
        mock_llm = _MockLLM(
            [
                _make_generate_result(content="结束", stop_reason="end_turn"),
            ]
        )
        runtime = Runtime(llm=mock_llm)
        agent = Agent(
            config=AgentConfig(name="test", system_prompt="", max_turns=5),
            runtime=runtime,
        )

        result = await agent.run("结束")

        assert result == "结束"
        assert agent.state == AgentState.FINISHED

    @pytest.mark.asyncio
    async def test_invalid_tool_arguments(self) -> None:
        """工具参数解析失败时返回错误结果。"""
        # 构造带无效参数的 tool_call
        invalid_tool_call = ToolCall(
            id="call_1",
            function=ToolCall.FunctionBody(name="echo", arguments="{invalid json}"),
        )

        class _EchoTool:
            name = "echo"
            description = "回显"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {"status": "success"}

        registry = ToolRegistry()
        registry.register(_EchoTool())
        adapter = SoulToolsetAdapter(registry)

        mock_llm = _MockLLM(
            [
                _make_generate_result(
                    content="",
                    tool_calls=[invalid_tool_call],
                    stop_reason="tool_use",
                ),
                _make_generate_result(content="参数错误已处理", stop_reason="stop"),
            ]
        )
        runtime = Runtime(llm=mock_llm, toolset=adapter)
        agent = Agent(
            config=AgentConfig(name="test", system_prompt="", max_turns=5),
            runtime=runtime,
        )

        result = await agent.run("test")

        # 第二轮应该正常返回
        assert "参数错误已处理" in result

    @pytest.mark.asyncio
    async def test_tool_execution_exception(self) -> None:
        """工具执行抛异常时被捕获，返回错误结果。"""

        class _RaiseTool:
            name = "raise.tool"
            description = "总是抛异常"

            def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
                raise RuntimeError("tool failed")

        registry = ToolRegistry()
        registry.register(_RaiseTool())
        adapter = SoulToolsetAdapter(registry)

        mock_llm = _MockLLM(
            [
                _make_generate_result(
                    content="",
                    tool_calls=[_make_tool_call("raise.tool", {})],
                    stop_reason="tool_use",
                ),
                _make_generate_result(content="工具异常已处理", stop_reason="stop"),
            ]
        )
        runtime = Runtime(llm=mock_llm, toolset=adapter)
        agent = Agent(
            config=AgentConfig(name="test", system_prompt="", max_turns=5),
            runtime=runtime,
        )

        result = await agent.run("test")

        assert "工具异常已处理" in result


# =============================================================================
# StepResult 模型测试
# =============================================================================


class TestStepResult:
    """StepResult pydantic 模型测试。"""

    def test_create_minimal(self) -> None:
        """创建最小化实例。"""
        step = StepResult(response=Message(role=MessageRole.ASSISTANT, content="hi"))
        assert step.tool_calls == []
        assert step.tool_results == []
        assert step.stop_reason == "stop"

    def test_create_with_tool_calls(self) -> None:
        """创建带 tool_calls 的实例。"""
        tool_call = _make_tool_call("test", {})
        step = StepResult(
            response=Message(role=MessageRole.ASSISTANT, content=""),
            tool_calls=[tool_call],
            stop_reason="tool_use",
        )
        assert len(step.tool_calls) == 1
        assert step.stop_reason == "tool_use"


# =============================================================================
# Agent 初始化测试
# =============================================================================


class TestAgentInit:
    """Agent 初始化测试。"""

    def test_init_sets_unique_id(self) -> None:
        """每次初始化生成唯一 ID。"""
        runtime = Runtime()
        config = AgentConfig(name="test", system_prompt="")
        agent1 = Agent(config, runtime)
        agent2 = Agent(config, runtime)
        assert agent1.id != agent2.id

    def test_init_default_state_idle(self) -> None:
        """初始状态为 IDLE。"""
        agent = Agent(AgentConfig(name="test", system_prompt=""), Runtime())
        assert agent.state == AgentState.IDLE

    def test_init_empty_messages(self) -> None:
        """初始消息历史为空。"""
        agent = Agent(AgentConfig(name="test", system_prompt=""), Runtime())
        assert agent.messages == []

    def test_init_current_turn_zero(self) -> None:
        """初始 current_turn 为 0。"""
        agent = Agent(AgentConfig(name="test", system_prompt=""), Runtime())
        assert agent.current_turn == 0
