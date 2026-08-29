"""测试模块：winreverse.app

测试 Agent 主入口（业务层）骨架。
覆盖：
- AgentConfig 默认值与自定义构造
- Agent.run() 返回码
- create_agent 工厂函数
- run_from_config 从字典启动
- Agent.shutdown() 不抛异常
"""

from __future__ import annotations

import pytest

from winreverse import __version__
from winreverse.app import Agent, AgentConfig, create_agent, run_from_config


class TestAgentConfig:
    """AgentConfig 配置类测试"""

    def test_default_values(self) -> None:
        """默认配置值应正确。"""
        config = AgentConfig()
        assert config.model == ""
        assert config.api_key == ""
        assert config.work_dir == "."
        assert config.yolo is False
        assert config.max_turns == 50

    def test_custom_values(self) -> None:
        """自定义配置值应正确设置。"""
        config = AgentConfig(
            model="gpt-4",
            api_key="sk-test",
            work_dir="/tmp/work",
            yolo=True,
            max_turns=100,
        )
        assert config.model == "gpt-4"
        assert config.api_key == "sk-test"
        assert config.work_dir == "/tmp/work"
        assert config.yolo is True
        assert config.max_turns == 100


class TestAgent:
    """Agent 主类测试"""

    def test_agent_creation_with_default_config(self) -> None:
        """用默认配置创建 Agent 应成功。"""
        agent = Agent()
        assert isinstance(agent.config, AgentConfig)
        assert agent.config.model == ""

    def test_agent_creation_with_custom_config(self) -> None:
        """用自定义配置创建 Agent 应成功。"""
        config = AgentConfig(model="gpt-4", api_key="test-key")
        agent = Agent(config=config)
        assert agent.config.model == "gpt-4"
        assert agent.config.api_key == "test-key"

    def test_agent_run_returns_zero(self) -> None:
        """Agent.run() 应返回 0 退出码。"""
        agent = Agent()
        result = agent.run()
        assert result == 0

    def test_agent_run_prints_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Agent.run() 应打印版本号。"""
        agent = Agent()
        agent.run()
        captured = capsys.readouterr()
        assert __version__ in captured.out

    def test_agent_shutdown_does_not_raise(self) -> None:
        """Agent.shutdown() 应不抛异常。"""
        agent = Agent()
        # 应不抛异常
        agent.shutdown()


class TestCreateAgentFactory:
    """create_agent 工厂函数测试"""

    def test_create_agent_with_none_config(self) -> None:
        """传入 None 应使用默认配置。"""
        agent = create_agent(None)
        assert isinstance(agent, Agent)
        assert agent.config.model == ""

    def test_create_agent_with_custom_config(self) -> None:
        """传入自定义配置应使用该配置。"""
        config = AgentConfig(model="claude-opus")
        agent = create_agent(config)
        assert agent.config.model == "claude-opus"

    def test_create_agent_returns_agent_instance(self) -> None:
        """返回值应是 Agent 实例。"""
        agent = create_agent()
        assert isinstance(agent, Agent)


class TestRunFromConfig:
    """run_from_config 函数测试"""

    def test_run_from_config_with_empty_dict(self) -> None:
        """空字典应使用默认配置。"""
        result = run_from_config({})
        assert result == 0

    def test_run_from_config_with_custom_values(self) -> None:
        """自定义值应被正确应用。"""
        result = run_from_config(
            {
                "model": "gpt-4",
                "api_key": "sk-test",
                "work_dir": "/tmp",
                "yolo": True,
                "max_turns": 200,
            }
        )
        assert result == 0

    def test_run_from_config_partial_dict(self) -> None:
        """部分字段应使用默认值填充。"""
        result = run_from_config({"model": "gpt-4"})
        assert result == 0
