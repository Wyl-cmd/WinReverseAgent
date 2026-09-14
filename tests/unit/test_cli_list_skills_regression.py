"""被测模块: winreverse.cli（list-skills 惰性初始化崩溃回归）。

覆盖点: list-skills 命令走真实 Agent 惰性初始化，锁住已修复的
'NoneType' object has no attribute 'list_skills'。
winreverse.app 导入链缺 yara 等 Windows 运行时依赖 → Linux 下如实报
collection error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import winreverse.cli as cli_module
from winreverse.app import Agent, create_agent_from_config
from winreverse.cli import app as cli_app
from winreverse.config import AppConfig

runner = CliRunner()


class TestListSkillsRegression:
    """list-skills 'NoneType' object has no attribute 'list_skills' 崩溃回归。"""

    def test_list_skills_via_cli_does_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """命令体走真实 Agent（注入替身 LLM，文档化接缝），初始化缺失即崩溃。"""
        # 收集失败路径证据：未初始化 Agent 的 registry 就是 None（原始缺陷根因）
        fresh = create_agent_from_config(AppConfig())
        assert fresh._skill_registry is None

        def _factory(config):
            return Agent(app_config=config, llm=object())

        monkeypatch.setattr(cli_module, "create_agent_from_config", _factory)
        result = runner.invoke(cli_app, ["list-skills"])
        assert result.exit_code == 0, result.output
        # 项目 skills/ 自带 5 个 YAML；空目录时命令也应优雅打印提示而非崩溃
        assert "已注册 Skill" in result.output or "未找到任何 Skill" in result.output
