"""测试模块：winreverse.cli 真机缺陷回归（list-skills 崩溃 / Windows --help 编码崩溃）。

覆盖：
- list-skills：真实 Agent（惰性初始化）下不再触发
  'NoneType' object has no attribute 'list_skills'（AttributeError）；
  另有 Linux 可跑的惰性契约回归（真实 Agent 链依赖 Windows 专有 wheel 时跳过）
- _reconfigure_streams_utf8：win32 下重配置 stdout/stderr 为 UTF-8+replace，
  非 win32 不动流，流不支持/拒绝重配置时不抛异常
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from winreverse.cli import _reconfigure_streams_utf8, app
from winreverse.config import AgentConfig, AppConfig

runner = CliRunner()


class _RecordingStream:
    """记录 reconfigure 调用参数的假流（无真实编码层）。"""

    def __init__(self, *, support_reconfigure: bool = True, raise_on_call: bool = False) -> None:
        self.calls: list[dict[str, str]] = []
        self._support = support_reconfigure
        self._raise = raise_on_call

    def reconfigure(self, **kwargs: str) -> None:
        self.calls.append(kwargs)
        if self._raise:
            raise ValueError("unsupported")


class TestListSkillsLazyInitRegression:
    """list-skills 崩溃回归：真实 Agent 的 _skill_registry 初始为 None。"""

    def _invoke_with_real_agent(self, tmp_path: Path) -> tuple[object, object]:
        """用真实 Agent（惰性初始化语义）走 list-skills 命令。"""
        try:
            from winreverse.app import Agent
        except ImportError as e:
            pytest.skip(f"winreverse.app 导入链缺 Windows 专有依赖，真实 Agent 回归仅实机运行: {e}")
        app_config = AppConfig(agent=AgentConfig(work_dir=str(tmp_path), skills_dir="skills"))
        holder: dict[str, object] = {}

        def _factory(_config: AppConfig) -> object:
            agent = Agent(app_config=_config)
            holder["agent"] = agent
            return agent

        with (
            patch("winreverse.cli.load_or_default", return_value=app_config),
            patch("winreverse.cli.create_agent_from_config", side_effect=_factory),
        ):
            result = runner.invoke(app, ["list-skills"])
        return result, holder.get("agent")

    def test_no_skills_dir_exits_cleanly(self, tmp_path: Path) -> None:
        """skills 目录缺失时应可读提示而非 AttributeError 崩溃。"""
        result, _agent = self._invoke_with_real_agent(tmp_path)
        assert not isinstance(result.exception, AttributeError), result.exception
        assert result.exit_code == 0
        assert "未找到" in result.stdout

    def test_agent_is_initialized_after_command(self, tmp_path: Path) -> None:
        """命令应触发惰性初始化：registry 建立、initialized 置位。"""
        result, agent = self._invoke_with_real_agent(tmp_path)
        assert result.exit_code == 0
        assert agent is not None
        assert agent._initialized is True
        assert agent._skill_registry is not None

    def test_with_skill_yaml_lists_it(self, tmp_path: Path) -> None:
        """skills 目录下有合法 YAML 时应列出该 Skill。"""
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "regression.yaml").write_text(
            'name: "回归测试Skill"\n'
            'description: "list-skills 回归用"\n'
            'target: "测试"\n'
            "prompt_template: |\n"
            "  测试模板\n",
            encoding="utf-8",
        )
        result, _ = self._invoke_with_real_agent(tmp_path)
        assert not isinstance(result.exception, AttributeError), result.exception
        assert result.exit_code == 0
        assert "回归测试Skill" in result.stdout
        assert "list-skills 回归用" in result.stdout


class TestListSkillsLazyAgentContract:
    """Linux 可跑的同型回归：CLI 必须兼容"registry 初始为 None"的惰性 Agent。

    _LazyAgent 忠实复刻 winreverse.app.Agent 的对外契约
    （__post_init__ 不建 registry，_ensure_initialized() 才建立），
    被测逻辑仍是 CLI 命令本身；真实 Agent 版本见上（实机运行）。
    """

    class _LazyAgent:
        def __init__(self, skills: list[dict[str, str]]) -> None:
            self._skills = skills
            self._skill_registry = None  # 与真实 Agent 的惰性初始态一致
            self.ensure_called = False

        def _ensure_initialized(self) -> None:
            self.ensure_called = True
            self._skill_registry = SimpleNamespace(list_skills=lambda: self._skills)

    def _invoke(self, tmp_path: Path, skills: list[dict[str, str]]) -> tuple[object, object]:
        agent = self._LazyAgent(skills)
        app_config = AppConfig(agent=AgentConfig(work_dir=str(tmp_path), skills_dir="skills"))
        with (
            patch("winreverse.cli.load_or_default", return_value=app_config),
            patch("winreverse.cli.create_agent_from_config", return_value=agent),
        ):
            result = runner.invoke(app, ["list-skills"])
        return result, agent

    def test_lazy_agent_without_fix_would_crash(self, tmp_path: Path) -> None:
        """惰性 Agent 下命令不得触发 NoneType.list_skills（原缺陷模式）。"""
        result, agent = self._invoke(
            tmp_path, [{"name": "pe_analyzer", "description": "PE 文件分析"}]
        )
        assert not isinstance(result.exception, AttributeError), result.exception
        assert result.exit_code == 0
        assert agent.ensure_called is True
        assert "pe_analyzer" in result.stdout
        assert "PE 文件分析" in result.stdout

    def test_lazy_agent_empty_registry(self, tmp_path: Path) -> None:
        """惰性 Agent + 空 registry 时输出未找到提示且不崩溃。"""
        result, agent = self._invoke(tmp_path, [])
        assert result.exit_code == 0
        assert agent.ensure_called is True
        assert "未找到" in result.stdout


class TestReconfigureStreamsUtf8:
    """Windows charmap 编码崩溃（--help UnicodeEncodeError）回归。"""

    def test_win32_reconfigures_both_streams(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """win32 平台应把 stdout/stderr 重配置为 UTF-8 + replace。"""
        out, err = _RecordingStream(), _RecordingStream()
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        _reconfigure_streams_utf8()
        assert out.calls == [{"encoding": "utf-8", "errors": "replace"}]
        assert err.calls == [{"encoding": "utf-8", "errors": "replace"}]

    def test_non_win32_leaves_streams_untouched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """非 Windows 平台不得改动流（本工具不为 Linux 改行为）。"""
        out, err = _RecordingStream(), _RecordingStream()
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        _reconfigure_streams_utf8()
        assert out.calls == []
        assert err.calls == []

    def test_tolerates_stream_without_reconfigure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无 reconfigure 能力的流（捕获替代对象）应被跳过而非崩溃。"""
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "stdout", object())
        monkeypatch.setattr(sys, "stderr", object())
        _reconfigure_streams_utf8()  # 不应抛 AttributeError

    def test_tolerates_reconfigure_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """reconfigure 抛错（如非法编码组合）时静默跳过，不得阻断启动。"""
        out = _RecordingStream(raise_on_call=True)
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", _RecordingStream())
        _reconfigure_streams_utf8()
        assert len(out.calls) == 1
