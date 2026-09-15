"""被测模块: winreverse.app — create_agent_from_config_file（config.toml → Agent 工厂）。

覆盖点: 从显式 TOML 路径加载 AppConfig 并注入 Agent（llm.model / api_key 透传、
agent.work_dir 透传）、构造期保持惰性（不触发 _ensure_initialized）、配置文件缺失时
按 load_or_default 契约回退默认配置（skills_dir 默认值）。
winreverse.app 导入链缺 yara 等 Windows 运行时依赖 → Linux 下如实报 collection
error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

from pathlib import Path

from winreverse.app import Agent, create_agent_from_config_file


class TestCreateAgentFromConfigFile:
    def test_loads_toml_and_builds_lazy_agent(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.toml"
        config_path.write_text(
            '[llm]\nmodel = "kimi-k2"\napi_key = "sk-test"\n\n[agent]\nwork_dir = "C:\\\\cases"\n',
            encoding="utf-8",
        )

        agent = create_agent_from_config_file(config_path)

        assert isinstance(agent, Agent)
        assert agent.app_config is not None
        assert agent.app_config.llm.model == "kimi-k2"
        assert agent.app_config.llm.api_key == "sk-test"
        assert agent.app_config.agent.work_dir == "C:\\cases"
        # 惰性契约：工厂只装配，不触发 _ensure_initialized（不建 Soul / registry）
        assert agent._initialized is False
        assert agent._skill_registry is None

    def test_missing_config_file_falls_back_to_defaults(self, tmp_path: Path) -> None:
        """load_or_default 契约：文件缺失不抛异常，回退默认配置。"""
        agent = create_agent_from_config_file(tmp_path / "absent.toml")

        assert isinstance(agent, Agent)
        assert agent.app_config is not None
        assert agent.app_config.agent.skills_dir == "skills"
        assert agent.app_config.agent.yolo is False
