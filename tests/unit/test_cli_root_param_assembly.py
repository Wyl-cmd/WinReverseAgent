"""被测模块: winreverse.cli 根命令（skill 参数装配 / _get_project_root / 版本回调）。

覆盖点: -P key=value 解析与 -f/-p 预置参数装配、坏参数 fail-fast、
项目根逐级上溯定位、_stdout_is_interactive 判定、--version 回调。
全部走 CliRunner + 替身 Agent（LLM 边界），不触碰 Windows 专有依赖，
Linux 可实跑（依 WINREVERSE_TASKS.md L5-L6 不加平台守卫）。
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import winreverse.cli as cli_module
from winreverse.cli import app as cli_app

runner = CliRunner()


class _RecordingAgent:
    """替身 Agent：只记录 run_skill_sync 入参（被测逻辑是 CLI 侧参数装配）。"""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def run_skill_sync(self, name: str, params: dict) -> SimpleNamespace:
        self.calls.append((name, dict(params)))
        return SimpleNamespace(flow_results=[], final_answer="done")


class TestSkillParamAssembly:
    """skill 命令参数装配：-P 解析 / -f -p 快捷方式 / 坏参数退出码。"""

    def test_bad_param_format_fails_fast_before_agent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """-P 缺 '=' 时退出码 1，且不创建 Agent（fail-fast 在工厂调用之前）。"""
        created = []

        def _factory(config):
            created.append(config)
            raise AssertionError("坏参数不应走到创建 Agent")

        monkeypatch.setattr(cli_module, "create_agent_from_config", _factory)
        result = runner.invoke(cli_app, ["skill", "PE 文件分析", "-P", "not-a-kv"])
        assert result.exit_code == 1
        assert "参数格式错误" in result.output
        assert "not-a-kv" in result.output
        assert created == []

    def test_params_assembled_from_p_f_p(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """-f/-p 映射为 file_path/process_name，-P 追加自定义键，值原样传递。"""
        agent = _RecordingAgent()
        monkeypatch.setattr(cli_module, "create_agent_from_config", lambda config: agent)
        target = tmp_path / "sample.exe"
        target.write_bytes(b"MZ")
        result = runner.invoke(
            cli_app,
            [
                "skill",
                "PE 文件分析",
                "-f",
                str(target),
                "-p",
                "notepad.exe",
                "-P",
                "depth=3",
                "-P",
                "verbose=true",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "最终答复: done" in result.output
        assert agent.calls == [
            (
                "PE 文件分析",
                {
                    "depth": "3",
                    "verbose": "true",
                    "file_path": str(target),
                    "process_name": "notepad.exe",
                },
            )
        ]

    def test_duplicate_p_key_last_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """同名 -P 键重复时后者覆盖前者（dict 赋值语义）。"""
        agent = _RecordingAgent()
        monkeypatch.setattr(cli_module, "create_agent_from_config", lambda config: agent)
        result = runner.invoke(cli_app, ["skill", "s", "-P", "k=1", "-P", "k=2"])
        assert result.exit_code == 0, result.output
        assert agent.calls[0][1]["k"] == "2"


class TestProjectRootAndInteractive:
    """_get_project_root 上溯定位与 _stdout_is_interactive 判定。"""

    def test_root_found_via_pyproject_marker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cwd 子目录向上找到含 pyproject.toml 的祖先即项目根。"""
        (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        subdir = tmp_path / "a" / "b"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)
        assert cli_module._get_project_root() == tmp_path

    def test_root_falls_back_to_cwd_without_marker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """无任何标记文件时回退当前目录本身。"""
        deep = tmp_path / "x"
        deep.mkdir()
        monkeypatch.chdir(deep)
        assert cli_module._get_project_root() == deep

    def test_interactive_true_when_stdout_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Tty:
            def isatty(self) -> bool:
                return True

        monkeypatch.setattr(sys, "stdout", _Tty())
        assert cli_module._stdout_is_interactive() is True

    def test_interactive_false_when_piped_or_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Pipe:
            def isatty(self) -> bool:
                return False

        monkeypatch.setattr(sys, "stdout", _Pipe())
        assert cli_module._stdout_is_interactive() is False
        monkeypatch.setattr(sys, "stdout", None)
        assert cli_module._stdout_is_interactive() is False


class TestVersionCallback:
    """--version / -V：打印版本后以 Exit 正常退出。"""

    def test_version_long_and_short_flags(self) -> None:
        for flag in ("--version", "-V"):
            result = runner.invoke(cli_app, [flag])
            assert result.exit_code == 0, result.output
            assert "WinReverseAgent v" in result.output
