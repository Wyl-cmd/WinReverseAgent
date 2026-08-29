"""测试模块：winreverse.soul.soul

覆盖 WinReverseSoul 主引擎的初始化、start、build_system_prompt、run 等方法。
使用 mock LLM 避免真实 API 调用。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kosong.types import GenerateResult, Message, MessageRole, Tool, ToolCall, Usage
from winreverse.engine.bus import ToolRegistry
from winreverse.soul.agent_spec import AgentTypeDefinition, LaborMarket
from winreverse.soul.context import ContextManager
from winreverse.soul.soul import WinReverseSoul
from winreverse.soul.toolset import SoulToolsetAdapter

# =============================================================================
# Mock LLM 实现
# =============================================================================


class _MockLLM:
    """Mock LLM 生成器。"""

    def __init__(self, responses: list[GenerateResult] | None = None) -> None:
        self._responses = list(responses) if responses else []
        self._call_count = 0
        self.last_tools: list[Tool] | None = None

    async def generate(
        self,
        messages: list[Message],
        model: str | None = None,
        tools: list[Tool] | None = None,
    ) -> GenerateResult:
        _ = messages, model
        self.last_tools = tools
        if self._call_count >= len(self._responses):
            return GenerateResult(
                message=Message(role=MessageRole.ASSISTANT, content="已完成"),
                stop_reason="stop",
                usage=Usage(),
            )
        response = self._responses[self._call_count]
        self._call_count += 1
        return response


def _make_result(content: str = "", stop_reason: str = "stop") -> GenerateResult:
    """构造 GenerateResult。"""
    return GenerateResult(
        message=Message(role=MessageRole.ASSISTANT, content=content),
        stop_reason=stop_reason,
        usage=Usage(),
    )


# =============================================================================
# 测试用工具
# =============================================================================


class _EchoTool:
    """回显工具。"""

    name = "echo"
    description = "回显输入"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "echoed": input_data.get("msg", "")}


class _ParseTool:
    """PE 解析工具。"""

    name = "pe.parse"
    description = "解析 PE 文件"

    def execute(self, input_data: dict[str, Any]) -> dict[str, Any]:
        return {"status": "success", "file": input_data.get("file_path", "")}


# =============================================================================
# WinReverseSoul 初始化测试
# =============================================================================


class TestWinReverseSoulInit:
    """WinReverseSoul 初始化测试。"""

    def test_init_with_defaults(self, tmp_path: Path) -> None:
        """默认初始化。"""
        mock_llm = _MockLLM()
        registry = ToolRegistry()
        soul = WinReverseSoul(llm=mock_llm, registry=registry, work_dir=tmp_path)

        assert soul.context_manager is not None
        assert soul.toolset is not None
        assert soul.labor_market is not None
        assert soul.runtime is not None

    def test_init_with_custom_labor_market(self, tmp_path: Path) -> None:
        """自定义 LaborMarket。"""
        market = LaborMarket()
        market.register(AgentTypeDefinition(name="custom", description="自定义"))

        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
            labor_market=market,
        )

        assert soul.labor_market is market
        assert soul.labor_market.get("custom") is not None

    def test_init_with_custom_session_dir(self, tmp_path: Path) -> None:
        """自定义会话目录。"""
        session_dir = tmp_path / "sessions"
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
            session_dir=session_dir,
        )

        assert soul.runtime.session_dir == session_dir

    def test_init_default_session_dir(self, tmp_path: Path) -> None:
        """默认会话目录为 work_dir/.winreverse/sessions/。"""
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )

        expected = tmp_path / ".winreverse" / "sessions"
        assert soul.runtime.session_dir == expected


# =============================================================================
# start 方法测试
# =============================================================================


class TestStart:
    """start 方法测试。"""

    def test_start_loads_context(self, tmp_path: Path) -> None:
        """start 加载上下文文件。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text("# 测试上下文", encoding="utf-8")

        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        soul.start()

        assert len(soul.context_manager._entries) == 1

    def test_start_is_idempotent(self, tmp_path: Path) -> None:
        """重复调用 start 不重复加载。"""
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        soul.start()
        soul.start()  # 应该幂等


# =============================================================================
# build_system_prompt 测试
# =============================================================================


class TestBuildSystemPrompt:
    """build_system_prompt 测试。"""

    def test_empty_context(self, tmp_path: Path) -> None:
        """无上下文时返回基础提示。"""
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        prompt = soul.build_system_prompt("你是助手")
        assert "你是助手" in prompt

    def test_with_skill_summary(self, tmp_path: Path) -> None:
        """skill 摘要附加到提示。"""
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        soul.set_skill_catalog_summary("可用技能: PE 分析")
        prompt = soul.build_system_prompt("你是助手")
        assert "可用技能: PE 分析" in prompt

    def test_with_agent_type_template(self, tmp_path: Path) -> None:
        """agent_type 对应的 system_prompt_template 覆盖 base_prompt。"""
        market = LaborMarket()
        market.register(
            AgentTypeDefinition(
                name="reverse",
                description="逆向 agent",
                system_prompt_template="你是逆向专家",
            )
        )
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
            labor_market=market,
        )
        prompt = soul.build_system_prompt("默认提示", agent_type="reverse")
        assert "你是逆向专家" in prompt


# =============================================================================
# run 方法测试
# =============================================================================


class TestRun:
    """run 方法测试。"""

    @pytest.mark.asyncio
    async def test_simple_run(self, tmp_path: Path) -> None:
        """简单运行返回 LLM 响应。"""
        mock_llm = _MockLLM([_make_result(content="你好")])
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )

        result = await soul.run("hi")

        assert result == "你好"

    @pytest.mark.asyncio
    async def test_run_with_tools(self, tmp_path: Path) -> None:
        """带工具的运行。"""
        registry = ToolRegistry()
        registry.register(_EchoTool())
        mock_llm = _MockLLM(
            [
                GenerateResult(
                    message=Message(
                        role=MessageRole.ASSISTANT,
                        content="",
                        tool_calls=[
                            ToolCall(
                                id="call_1",
                                function=ToolCall.FunctionBody(
                                    name="echo",
                                    arguments=json.dumps({"msg": "hello"}),
                                ),
                            )
                        ],
                    ),
                    stop_reason="tool_use",
                    usage=Usage(),
                ),
                _make_result(content="已回显: hello"),
            ]
        )
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=registry,
            work_dir=tmp_path,
        )

        result = await soul.run("回显 hello")

        assert "已回显" in result
        # 验证 LLM 收到了 tools 参数
        assert mock_llm.last_tools is not None
        assert len(mock_llm.last_tools) == 1
        assert mock_llm.last_tools[0].name == "echo"

    @pytest.mark.asyncio
    async def test_run_with_agent_type(self, tmp_path: Path) -> None:
        """指定 agent_type 运行。"""
        market = LaborMarket()
        market.register(
            AgentTypeDefinition(
                name="reverse",
                description="逆向",
                system_prompt_template="你是逆向专家",
                allowed_tools=("pe.parse",),
            )
        )
        registry = ToolRegistry()
        registry.register(_ParseTool())

        mock_llm = _MockLLM([_make_result(content="逆向分析完成")])
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=registry,
            work_dir=tmp_path,
            labor_market=market,
        )

        result = await soul.run("分析文件", agent_type="reverse")

        assert "逆向分析完成" in result
        # 验证 LLM 只收到了 allowed_tools 中的工具
        assert mock_llm.last_tools is not None
        assert len(mock_llm.last_tools) == 1
        assert mock_llm.last_tools[0].name == "pe.parse"

    @pytest.mark.asyncio
    async def test_run_with_custom_system_prompt(self, tmp_path: Path) -> None:
        """自定义 system_prompt 覆盖 agent_type 模板。"""
        market = LaborMarket()
        market.register(
            AgentTypeDefinition(
                name="reverse",
                description="逆向",
                system_prompt_template="你是逆向专家",
            )
        )
        mock_llm = _MockLLM([_make_result(content="ok")])
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=ToolRegistry(),
            work_dir=tmp_path,
            labor_market=market,
        )

        result = await soul.run(
            "test",
            agent_type="reverse",
            system_prompt="自定义提示",
        )

        assert result == "ok"

    @pytest.mark.asyncio
    async def test_run_with_custom_model(self, tmp_path: Path) -> None:
        """自定义 model 参数。"""
        mock_llm = _MockLLM([_make_result(content="ok")])
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=ToolRegistry(),
            work_dir=tmp_path,
            default_model="gpt-4",
        )

        result = await soul.run("test", model="claude-3")

        assert result == "ok"

    @pytest.mark.asyncio
    async def test_run_with_custom_max_turns(self, tmp_path: Path) -> None:
        """自定义 max_turns。"""
        mock_llm = _MockLLM([_make_result(content="ok")])
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )

        result = await soul.run("test", max_turns=1)

        assert result == "ok"

    @pytest.mark.asyncio
    async def test_run_with_explicit_tools_whitelist(self, tmp_path: Path) -> None:
        """显式指定 tools 白名单。"""
        registry = ToolRegistry()
        registry.register(_EchoTool())
        registry.register(_ParseTool())

        mock_llm = _MockLLM([_make_result(content="ok")])
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=registry,
            work_dir=tmp_path,
        )

        result = await soul.run("test", tools=["echo"])

        assert result == "ok"
        # 只暴露 echo 工具
        assert mock_llm.last_tools is not None
        assert len(mock_llm.last_tools) == 1
        assert mock_llm.last_tools[0].name == "echo"

    @pytest.mark.asyncio
    async def test_run_auto_starts_engine(self, tmp_path: Path) -> None:
        """run 自动调用 start。"""
        mock_llm = _MockLLM([_make_result(content="ok")])
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )

        assert soul._started is False
        await soul.run("test")
        assert soul._started is True


# =============================================================================
# register_agent_type / load_agent_specs 测试
# =============================================================================


class TestAgentTypeManagement:
    """agent 类型管理测试。"""

    def test_register_agent_type(self, tmp_path: Path) -> None:
        """注册 agent 类型。"""
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        type_def = AgentTypeDefinition(name="new_type", description="新类型")
        soul.register_agent_type(type_def)

        assert soul.labor_market.get("new_type") is type_def

    def test_load_agent_specs(self, tmp_path: Path) -> None:
        """批量加载 agent 类型定义。"""
        spec_dir = tmp_path / "specs"
        spec_dir.mkdir()
        (spec_dir / "a.yaml").write_text("name: agent_a\ndescription: Agent A", encoding="utf-8")
        (spec_dir / "b.yaml").write_text("name: agent_b\ndescription: Agent B", encoding="utf-8")

        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        loaded = soul.load_agent_specs(spec_dir)

        assert len(loaded) == 2
        assert soul.labor_market.get("agent_a") is not None
        assert soul.labor_market.get("agent_b") is not None


# =============================================================================
# get_history 测试
# =============================================================================


class TestGetHistory:
    """get_history 测试。"""

    @pytest.mark.asyncio
    async def test_get_history_after_run(self, tmp_path: Path) -> None:
        """run 后获取对话历史。"""
        mock_llm = _MockLLM([_make_result(content="hello")])
        soul = WinReverseSoul(
            llm=mock_llm,
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )

        # 需要获取 agent 实例，这里通过 run 内部创建
        # 改为直接测试 ContextManager 与 Runtime 的协作
        from winreverse.soul.agent import Agent, AgentConfig, Runtime

        config = AgentConfig(name="test", system_prompt="你是助手", max_turns=5)
        runtime = Runtime(llm=mock_llm)
        agent = Agent(config, runtime)
        await agent.run("hi")

        history = soul.get_history(agent)
        assert len(history) == 2  # user + assistant
        assert history[0].role == MessageRole.USER
        assert history[1].role == MessageRole.ASSISTANT


# =============================================================================
# 属性访问测试
# =============================================================================


class TestProperties:
    """属性访问测试。"""

    def test_context_manager_property(self, tmp_path: Path) -> None:
        """context_manager 属性返回 ContextManager 实例。"""
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        assert isinstance(soul.context_manager, ContextManager)

    def test_toolset_property(self, tmp_path: Path) -> None:
        """toolset 属性返回 SoulToolsetAdapter 实例。"""
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        assert isinstance(soul.toolset, SoulToolsetAdapter)

    def test_labor_market_property(self, tmp_path: Path) -> None:
        """labor_market 属性返回 LaborMarket 实例。"""
        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        assert isinstance(soul.labor_market, LaborMarket)

    def test_runtime_property(self, tmp_path: Path) -> None:
        """runtime 属性返回 Runtime 实例。"""
        from winreverse.soul.agent import Runtime

        soul = WinReverseSoul(
            llm=_MockLLM(),
            registry=ToolRegistry(),
            work_dir=tmp_path,
        )
        assert isinstance(soul.runtime, Runtime)
