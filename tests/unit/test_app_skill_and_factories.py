"""被测模块: winreverse.app（run_skill / run_skill_sync 与工厂函数）。

覆盖点: run_skill 把 skill 名与参数透传给 executor.run、parameters=None 归一为 {}、
run_skill_sync 同步桥返回执行器结果且不吞异常、create_agent 默认/显式配置、
create_agent_from_config 挂接 app_config。executor 用假对象注入（依赖注入，非平台守卫）。
winreverse.app 导入链缺 yara 等 Windows 运行时依赖 → Linux 下如实报
collection error（基线接受态），待 Windows 实机实跑回填。
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from winreverse.app import Agent, AgentConfig, create_agent, create_agent_from_config


class _FakeExecutor:
    """记录 run() 调用并返回哨兵结果的假执行器。"""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def run(self, skill_name: str, parameters: dict[str, Any]) -> Any:
        self.calls.append((skill_name, parameters))
        return {"ok": True, "skill": skill_name}


def _agent_with_executor() -> tuple[Agent, _FakeExecutor]:
    """已初始化标记 + 假执行器注入（绕开真实 LLM/注册表初始化）。"""
    agent = create_agent()
    executor = _FakeExecutor()
    agent._initialized = True
    agent._executor = executor
    return agent, executor


class TestRunSkill:
    """Skill 执行链路（异步 + 同步桥）。"""

    def test_run_skill_passes_name_and_params(self) -> None:
        agent, executor = _agent_with_executor()
        result = asyncio.run(agent.run_skill("memdump", {"pid": 4242}))
        assert executor.calls == [("memdump", {"pid": 4242})]
        assert result == {"ok": True, "skill": "memdump"}

    def test_run_skill_none_params_normalized_to_empty_dict(self) -> None:
        agent, executor = _agent_with_executor()
        asyncio.run(agent.run_skill("listmodules", None))
        assert executor.calls == [("listmodules", {})]

    def test_run_skill_sync_returns_executor_result(self) -> None:
        agent, executor = _agent_with_executor()
        result = agent.run_skill_sync("strings", {"min_len": 5})
        assert executor.calls == [("strings", {"min_len": 5})]
        assert result == {"ok": True, "skill": "strings"}

    def test_run_skill_does_not_swallow_executor_errors(self) -> None:
        class _BrokenExecutor:
            async def run(self, skill_name: str, parameters: dict[str, Any]) -> Any:
                raise RuntimeError("executor exploded")

        agent = create_agent()
        agent._initialized = True
        agent._executor = _BrokenExecutor()
        with pytest.raises(RuntimeError, match="executor exploded"):
            agent.run_skill_sync("boom")


class TestFactories:
    """create_agent / create_agent_from_config 工厂行为。"""

    def test_create_agent_default_config(self) -> None:
        agent = create_agent()
        assert isinstance(agent, Agent)
        assert agent.config.model == ""
        assert agent.config.work_dir == "."
        assert agent.config.max_turns == 50
        assert agent.config.yolo is False

    def test_create_agent_carries_explicit_config(self) -> None:
        config = AgentConfig(
            model="gpt-x", api_key="k", work_dir="/w", yolo=True, max_turns=7
        )
        agent = create_agent(config)
        assert agent.config is config

    def test_create_agent_from_config_attaches_app_config(self) -> None:
        app_config = AgentConfig(work_dir="/w").to_app_config()
        agent = create_agent_from_config(app_config)
        assert isinstance(agent, Agent)
        assert agent.app_config is app_config
        # 未初始化前组件保持惰性
        assert agent._registry is None
        assert agent._skill_registry is None
        assert agent._initialized is False
