"""被测模块: winreverse.cli 根命令收尾路径（真机 coverage 缺 31 行）。

覆盖点: 裸启动非 tty 提示回落、skill 的 SkillNotFoundError 空 registry 分支与
--show-flow 空流分支、gui 命令 GUIUnavailableError 异常回落、
tools check 无更新 / update 三失败分支 / verify 缺 manifest 与未通过报告、
_check_result_to_dict 序列化。全部走 CliRunner + 替身（只 stub 外部协作者
ToolUpdater / WheelUpdater / VersionChecker / run_gui / Agent 工厂），
不触碰 Windows 专有依赖，Linux 可实跑（依 WINREVERSE_TASKS.md L5-L6 不加平台守卫）。
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import ClassVar

import pytest
from typer.testing import CliRunner

import winreverse.cli as cli_module
import winreverse.gui.app as gui_app_module
import winreverse.tools.updater as tools_updater_module
import winreverse.tools.version_checker as version_checker_module
from winreverse.cli import app as cli_app
from winreverse.skill.loader import SkillNotFoundError

runner = CliRunner()


# =============================================================================
# main 回调：无子命令 + stdout 非交互式 → 提示跳过 TUI（140-141）
# =============================================================================


class TestMainCallbackFallback:
    def test_bare_invocation_non_tty_prints_hint(self) -> None:
        """无参数启动且 stdout 非 tty（CliRunner 捕获即非 tty）时，不启动 TUI，
        打印跳过提示与 --help 指引。"""
        result = runner.invoke(cli_app, [])
        assert result.exit_code == 0
        assert "跳过 TUI 启动" in result.output
        assert "winreverse --help" in result.output


# =============================================================================
# skill 命令收尾：SkillNotFoundError 空 registry（228）/ --show-flow 空流（245）
# =============================================================================


class _NotFoundAgent:
    """run_skill_sync 抛 SkillNotFoundError 且 registry 为空的替身 Agent。"""

    def run_skill_sync(self, name: str, params: dict) -> None:
        raise SkillNotFoundError(f"Skill '{name}' 未注册")

    @property
    def _skill_registry(self):
        return SimpleNamespace(list_skills=lambda: [])


class TestSkillTailBranches:
    def test_skill_not_found_with_empty_registry_lists_hint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Skill 未注册且 registry 为空时，提示检查 skills_dir 后退出码 1（228）。"""
        monkeypatch.setattr(cli_module, "create_agent_from_config", lambda config: _NotFoundAgent())
        result = runner.invoke(cli_app, ["skill", "不存在的技能"])
        assert result.exit_code == 1
        assert "Skill '不存在的技能' 未注册" in result.output
        assert "未找到任何已注册 Skill" in result.output

    def test_show_flow_with_empty_flow_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--show-flow 但 Skill 无预置执行流时，打印占位提示并输出最终答复（245）。"""
        agent = SimpleNamespace(
            run_skill_sync=lambda name, params: SimpleNamespace(
                flow_results=[], final_answer="分析完成"
            )
        )
        monkeypatch.setattr(cli_module, "create_agent_from_config", lambda config: agent)
        result = runner.invoke(cli_app, ["skill", "PE 文件分析", "--show-flow"])
        assert result.exit_code == 0
        assert "该 Skill 无预置执行流" in result.output
        assert "最终答复: 分析完成" in result.output


# =============================================================================
# gui 命令：GUIUnavailableError 异常回落（291, 293-299）
# =============================================================================


class TestGuiUnavailableFallback:
    def test_gui_unavailable_prints_install_guide_and_exits_1(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """run_gui 抛 GUIUnavailableError 时，打印安装指引并退出码 1，-c 透传。"""
        received: list[object] = []

        def _boom(config_path):
            received.append(config_path)
            raise gui_app_module.GUIUnavailableError("dearpygui 未安装。")

        monkeypatch.setattr(gui_app_module, "run_gui", _boom)
        config_file = tmp_path / "wra.toml"
        config_file.write_text("x = 1", encoding="utf-8")
        result = runner.invoke(cli_app, ["gui", "-c", str(config_file)])
        assert result.exit_code == 1
        assert "dearpygui 未安装。" in result.output
        assert "安装指引" in result.output
        assert "winreverse settings" in result.output
        assert received == [config_file]


# =============================================================================
# tools check：manifest 存在但无可用更新（341-342）
# =============================================================================


class _StubToolUpdater:
    """替身 ToolUpdater：构造参数透传记录，方法返回由类属性注入。"""

    check_updates_result: ClassVar[list] = []
    update_result: SimpleNamespace | None = None
    list_installed_result: ClassVar[list] = []
    rollback_result: SimpleNamespace | None = None
    update_all_report: SimpleNamespace | None = None

    def __init__(self, manifest_path=None, project_root=None) -> None:
        self.manifest_path = manifest_path
        self.project_root = project_root

    def check_updates(self):
        return self.check_updates_result

    def list_installed(self):
        return self.list_installed_result

    def update(self, name: str):
        return self.update_result

    def update_all(self):
        return self.update_all_report

    def rollback(self, name: str):
        return self.rollback_result


class TestToolsCheckNoUpdates:
    def test_check_all_up_to_date(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        """manifest 存在且无可用更新时，打印最新提示并正常返回（341-342）。"""
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "manifest.yaml").write_text("tools: []\n", encoding="utf-8")
        monkeypatch.setattr(cli_module, "_get_project_root", lambda: tmp_path)
        monkeypatch.setattr(tools_updater_module, "ToolUpdater", _StubToolUpdater)
        _StubToolUpdater.check_updates_result = []
        result = runner.invoke(cli_app, ["tools", "check"])
        assert result.exit_code == 0
        assert "所有外部工具均为最新" in result.output


# =============================================================================
# tools update：wheel manifest 缺失（397-398）/ 批量聚合（406-409）/
# 单 wheel 失败（413-414）/ 单工具失败（428-429）
# ==============================================================================


class TestToolsUpdateTailBranches:
    def test_wheel_mode_missing_manifest_exits_1(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """-w 模式下 wheels manifest 不存在时，报错退出码 1（397-398）。"""
        monkeypatch.setattr(cli_module, "_get_project_root", lambda: tmp_path)
        result = runner.invoke(cli_app, ["tools", "update", "capstone", "-w"])
        assert result.exit_code == 1
        assert "wheels manifest 不存在" in result.output

    def test_wheel_mode_update_all_aggregates_failures(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """-w 无工具名时批量更新，聚合成功/失败计数并按失败置退出码（406-409）。"""
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "wheels_manifest.yaml").write_text("wheels: []\n", encoding="utf-8")
        monkeypatch.setattr(cli_module, "_get_project_root", lambda: tmp_path)

        class _WheelUpdater:
            def __init__(self, wheels_manifest=None, wheels_dir=None) -> None:
                pass

            def update_all(self):
                return {"capstone": True, "yara": False}

        monkeypatch.setattr(version_checker_module, "WheelUpdater", _WheelUpdater)
        result = runner.invoke(cli_app, ["tools", "update", "-w"])
        assert result.exit_code == 1
        assert "成功 1，失败 1" in result.output

    def test_wheel_mode_single_update_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """-w 指定依赖且更新失败时，打印失败并退出码 1（413-414）。"""
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "wheels_manifest.yaml").write_text("wheels: []\n", encoding="utf-8")
        monkeypatch.setattr(cli_module, "_get_project_root", lambda: tmp_path)

        class _WheelUpdater:
            def __init__(self, wheels_manifest=None, wheels_dir=None) -> None:
                pass

            def update(self, name: str) -> bool:
                return False

        monkeypatch.setattr(version_checker_module, "WheelUpdater", _WheelUpdater)
        result = runner.invoke(cli_app, ["tools", "update", "capstone", "-w"])
        assert result.exit_code == 1
        assert "更新失败: capstone" in result.output

    def test_rollback_failure_exits_1(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        """rollback 结果失败时，打印消息并退出码 1（511-512）。"""
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "manifest.yaml").write_text("tools: []\n", encoding="utf-8")
        monkeypatch.setattr(cli_module, "_get_project_root", lambda: tmp_path)
        monkeypatch.setattr(tools_updater_module, "ToolUpdater", _StubToolUpdater)
        _StubToolUpdater.rollback_result = SimpleNamespace(success=False, message="无可用备份")
        result = runner.invoke(cli_app, ["tools", "rollback", "x64dbg"])
        assert result.exit_code == 1
        assert "无可用备份" in result.output

    def test_tool_mode_single_update_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """非 wheel 模式指定工具且更新失败时，打印消息并退出码 1（428-429）。"""
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "manifest.yaml").write_text("tools: []\n", encoding="utf-8")
        monkeypatch.setattr(cli_module, "_get_project_root", lambda: tmp_path)
        monkeypatch.setattr(tools_updater_module, "ToolUpdater", _StubToolUpdater)
        _StubToolUpdater.update_result = SimpleNamespace(success=False, message="下载校验失败")
        result = runner.invoke(cli_app, ["tools", "update", "x64dbg"])
        assert result.exit_code == 1
        assert "下载校验失败" in result.output


# =============================================================================
# tools verify：缺 manifest（447-448）/ 结果表行渲染（471）/ 未通过退出码（491）
# =============================================================================


class TestToolsVerifyTailBranches:
    def test_verify_missing_tools_manifest_exits_1(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """tools manifest 不存在时，报错退出码 1（447-448）。"""
        monkeypatch.setattr(cli_module, "_get_project_root", lambda: tmp_path)
        result = runner.invoke(cli_app, ["tools", "verify"])
        assert result.exit_code == 1
        assert "tools manifest 不存在" in result.output

    def test_verify_failed_report_renders_rows_and_exits_1(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """报告未通过时渲染两类结果表并以退出码 1 收尾（471, 491）。"""
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "manifest.yaml").write_text("tools: []\n", encoding="utf-8")
        monkeypatch.setattr(cli_module, "_get_project_root", lambda: tmp_path)

        report = SimpleNamespace(
            passed=False,
            overall="FAIL",
            tool_report=SimpleNamespace(
                results=[
                    SimpleNamespace(
                        name="x64dbg", version="1.0", status="missing", message="未安装"
                    )
                ]
            ),
            wheel_report=SimpleNamespace(
                results=[
                    SimpleNamespace(name="yara-python", version="4.3", status="ok", message="匹配")
                ]
            ),
        )

        class _VersionChecker:
            def __init__(self, **kwargs) -> None:
                pass

            def check_all(self):
                return report

        monkeypatch.setattr(version_checker_module, "VersionChecker", _VersionChecker)
        result = runner.invoke(cli_app, ["tools", "verify"])
        assert result.exit_code == 1
        assert "总体状态: FAIL" in result.output
        assert "x64dbg" in result.output
        assert "yara-python" in result.output


# =============================================================================
# _check_result_to_dict：结果对象 → JSON 可序列化字典（320）
# =============================================================================


class TestCheckResultToDict:
    def test_result_converted_to_json_serializable_dict(self) -> None:
        """ToolCheckResult 形状对象转字典后字段齐全且可 json 序列化（320）。"""
        result = SimpleNamespace(name="x64dbg", version="1.0", status="ok", message="已安装")
        data = cli_module._check_result_to_dict(result)
        assert data == {
            "name": "x64dbg",
            "version": "1.0",
            "status": "ok",
            "message": "已安装",
        }
        assert json.dumps(data, ensure_ascii=False)
