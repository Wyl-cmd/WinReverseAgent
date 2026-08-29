"""测试模块：winreverse.cli

测试 Typer CLI 入口的命令行功能。
覆盖：
- --version 显示版本后退出
- info 命令显示项目信息
- settings 命令启动 Textual TUI
- skill 命令参数解析与执行
- run 命令入口
- list-skills 命令
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from winreverse import __version__
from winreverse.cli import app
from winreverse.skill.executor import SkillExecutionError, SkillRunResult
from winreverse.skill.loader import SkillNotFoundError

runner = CliRunner()


class TestVersionCommand:
    """--version 命令测试"""

    def test_version_displays_correct_version(self) -> None:
        """--version 应显示正确的版本号。"""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_version_short_flag(self) -> None:
        """-V 短标志应等价于 --version。"""
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert __version__ in result.stdout


class TestInfoCommand:
    """info 命令测试"""

    def test_info_command_succeeds(self) -> None:
        """info 命令应成功执行并显示项目信息。"""
        result = runner.invoke(app, ["info"])
        assert result.exit_code == 0
        assert "WinReverseAgent" in result.stdout
        assert __version__ in result.stdout

    def test_info_command_contains_required_fields(self) -> None:
        """info 输出应包含关键字段。"""
        result = runner.invoke(app, ["info"])
        assert result.exit_code == 0
        assert "版本" in result.stdout
        assert "Python" in result.stdout
        assert "Windows" in result.stdout
        assert "MIT" in result.stdout


class TestSettingsCommand:
    """settings 命令测试"""

    @patch("winreverse.tui.SettingsApp")
    def test_settings_command_succeeds(
        self,
        mock_settings_app: MagicMock,
    ) -> None:
        """settings 命令应成功启动 TUI 应用。"""
        mock_instance = MagicMock()
        mock_settings_app.return_value = mock_instance

        result = runner.invoke(app, ["settings"])

        assert result.exit_code == 0
        mock_settings_app.assert_called_once()
        mock_instance.run.assert_called_once()

    @patch("winreverse.tui.SettingsApp")
    def test_settings_command_passes_config(
        self,
        mock_settings_app: MagicMock,
    ) -> None:
        """settings 命令应将 AppConfig 传递给 SettingsApp。"""
        mock_instance = MagicMock()
        mock_settings_app.return_value = mock_instance

        result = runner.invoke(app, ["settings"])

        assert result.exit_code == 0
        call_args = mock_settings_app.call_args
        assert call_args is not None
        assert "config" in call_args.kwargs

    @patch("winreverse.tui.SettingsApp")
    def test_settings_command_with_config_option(
        self,
        mock_settings_app: MagicMock,
        tmp_path: Path,
    ) -> None:
        """settings 命令应支持 --config 选项加载指定配置文件。"""
        config_file = tmp_path / "custom.toml"
        config_file.write_text(
            '[llm]\nprovider = "openai"\nmodel = "gpt-4"\n',
            encoding="utf-8",
        )

        mock_instance = MagicMock()
        mock_settings_app.return_value = mock_instance

        result = runner.invoke(app, ["settings", "-c", str(config_file)])

        assert result.exit_code == 0
        call_args = mock_settings_app.call_args
        assert call_args is not None
        passed_config = call_args.kwargs["config"]
        assert passed_config.llm.provider == "openai"
        assert passed_config.llm.model == "gpt-4"


class TestSkillCommand:
    """skill 命令测试"""

    def test_skill_command_accepts_name(self) -> None:
        """skill 命令应接受 Skill 名称参数。"""
        # 使用不存在的 Skill 名，验证参数解析（会因 Skill 未注册而退出码 1）
        result = runner.invoke(app, ["skill", "nonexistent_skill"])
        assert result.exit_code == 1
        assert "nonexistent_skill" in result.stdout

    def test_skill_command_with_process_option(self) -> None:
        """skill 命令应接受 --process 选项。"""
        result = runner.invoke(app, ["skill", "nonexistent", "--process", "game.exe"])
        # 参数被解析（执行会因 Skill 未注册而失败，但参数应出现在输出中）
        assert "game.exe" in result.stdout

    def test_skill_command_short_process_flag(self) -> None:
        """skill 命令应支持 -p 短标志。"""
        result = runner.invoke(app, ["skill", "nonexistent", "-p", "target.exe"])
        assert "target.exe" in result.stdout

    def test_skill_command_with_file_option(self) -> None:
        """skill 命令应接受 -f/--file 选项。"""
        result = runner.invoke(app, ["skill", "nonexistent", "-f", "test.exe"])
        assert "test.exe" in result.stdout

    def test_skill_command_with_param_option(self) -> None:
        """skill 命令应支持 --param key=value 多次指定。"""
        result = runner.invoke(
            app,
            [
                "skill",
                "nonexistent",
                "--param",
                "key1=value1",
                "-P",
                "key2=value2",
            ],
        )
        # 参数应出现在输出中
        assert "key1" in result.stdout
        assert "value1" in result.stdout

    def test_skill_command_invalid_param_format(self) -> None:
        """参数格式错误（无 = 号）应退出码 1。"""
        result = runner.invoke(app, ["skill", "nonexistent", "--param", "invalid_param"])
        assert result.exit_code == 1
        assert "参数格式错误" in result.stdout

    @patch("winreverse.cli.create_agent_from_config")
    def test_skill_command_executes_skill_successfully(
        self,
        mock_create_agent: MagicMock,
    ) -> None:
        """成功执行 Skill 时应显示结果。"""
        # 构造 mock Agent
        mock_agent = MagicMock()
        mock_result = SkillRunResult(
            skill_name="test_skill",
            final_answer="分析完成: 64 位 PE",
            flow_results=[],
            rendered_prompt="test",
        )
        mock_agent.run_skill_sync.return_value = mock_result
        mock_create_agent.return_value = mock_agent

        result = runner.invoke(app, ["skill", "test_skill", "-f", "test.exe"])

        assert result.exit_code == 0
        assert "分析完成" in result.stdout
        assert "64 位 PE" in result.stdout
        # 验证 Agent 被正确调用
        mock_agent.run_skill_sync.assert_called_once_with("test_skill", {"file_path": "test.exe"})

    @patch("winreverse.cli.create_agent_from_config")
    def test_skill_command_skill_not_found_lists_available(
        self,
        mock_create_agent: MagicMock,
    ) -> None:
        """Skill 未注册时应列出可用 Skill。"""
        mock_agent = MagicMock()
        mock_agent.run_skill_sync.side_effect = SkillNotFoundError("missing")
        mock_agent._skill_registry.list_skills.return_value = [
            {"name": "pe_analyzer", "description": "PE 分析"},
            {"name": "memory_scan", "description": "内存扫描"},
        ]
        mock_create_agent.return_value = mock_agent

        result = runner.invoke(app, ["skill", "missing"])

        assert result.exit_code == 1
        assert "未注册" in result.stdout
        assert "pe_analyzer" in result.stdout
        assert "memory_scan" in result.stdout

    @patch("winreverse.cli.create_agent_from_config")
    def test_skill_command_execution_error(
        self,
        mock_create_agent: MagicMock,
    ) -> None:
        """Skill 执行错误时应显示错误信息。"""
        mock_agent = MagicMock()
        mock_agent.run_skill_sync.side_effect = SkillExecutionError("参数错误")
        mock_create_agent.return_value = mock_agent

        result = runner.invoke(app, ["skill", "test_skill"])

        assert result.exit_code == 1
        assert "SkillExecutionError" in result.stdout or "参数错误" in result.stdout

    @patch("winreverse.cli.create_agent_from_config")
    def test_skill_command_show_flow_option(
        self,
        mock_create_agent: MagicMock,
    ) -> None:
        """--show-flow 选项应显示预置流结果。"""
        from winreverse.skill.executor import FlowStepResult

        mock_agent = MagicMock()
        mock_result = SkillRunResult(
            skill_name="test",
            final_answer="done",
            flow_results=[
                FlowStepResult(
                    action="pe.parse",
                    arguments={"file_path": "test.exe"},
                    output='{"status": "success", "bits": 64}',
                    is_error=False,
                ),
                FlowStepResult(
                    action="error.tool",
                    arguments={},
                    output="失败",
                    is_error=True,
                ),
            ],
            rendered_prompt="test",
        )
        mock_agent.run_skill_sync.return_value = mock_result
        mock_create_agent.return_value = mock_agent

        result = runner.invoke(app, ["skill", "test", "--show-flow"])

        assert result.exit_code == 0
        assert "预置执行流结果" in result.stdout
        assert "pe.parse" in result.stdout
        assert "ERROR" in result.stdout
        assert "OK" in result.stdout


class TestRunCommand:
    """run 命令测试"""

    @patch("winreverse.cli.create_agent_from_config")
    @patch("winreverse.tui.launch_main_app")
    def test_run_command_starts_tui(
        self,
        mock_launch: MagicMock,
        mock_create_agent: MagicMock,
    ) -> None:
        """run 命令默认应启动 TUI 主操作台。"""
        mock_agent = MagicMock()
        mock_create_agent.return_value = mock_agent

        result = runner.invoke(app, ["run"])

        assert result.exit_code == 0
        mock_launch.assert_called_once()
        # 验证传递了 agent 参数
        call_kwargs = mock_launch.call_args
        assert call_kwargs.kwargs.get("agent") is mock_agent or call_kwargs.args[0] is mock_agent

    @patch("winreverse.cli.create_agent_from_config")
    def test_run_command_repl_flag_starts_repl(self, mock_create_agent: MagicMock) -> None:
        """run --repl 应启动旧版 REPL。"""
        mock_agent = MagicMock()
        mock_agent.run_repl.return_value = 0
        mock_create_agent.return_value = mock_agent

        result = runner.invoke(app, ["run", "--repl"])

        assert result.exit_code == 0
        mock_agent.run_repl.assert_called_once()


class TestListSkillsCommand:
    """list-skills 命令测试"""

    @patch("winreverse.cli.create_agent_from_config")
    def test_list_skills_command_shows_skills(
        self,
        mock_create_agent: MagicMock,
    ) -> None:
        """list-skills 命令应列出可用 Skill。"""
        mock_agent = MagicMock()
        mock_agent._skill_registry.list_skills.return_value = [
            {"name": "pe_analyzer", "description": "PE 文件分析"},
            {"name": "memory_scan", "description": "内存扫描"},
        ]
        mock_create_agent.return_value = mock_agent

        result = runner.invoke(app, ["list-skills"])

        assert result.exit_code == 0
        assert "pe_analyzer" in result.stdout
        assert "PE 文件分析" in result.stdout
        assert "memory_scan" in result.stdout

    @patch("winreverse.cli.create_agent_from_config")
    def test_list_skills_command_empty(self, mock_create_agent: MagicMock) -> None:
        """无 Skill 时应提示。"""
        mock_agent = MagicMock()
        mock_agent._skill_registry.list_skills.return_value = []
        mock_create_agent.return_value = mock_agent

        result = runner.invoke(app, ["list-skills"])

        assert result.exit_code == 0
        assert "未找到" in result.stdout or "skills_dir" in result.stdout


class TestCliHelp:
    """CLI 帮助测试"""

    def test_help_command_succeeds(self) -> None:
        """--help 应显示帮助信息。"""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        # Typer 的 --help 会输出 Usage 信息
        assert "Usage" in result.stdout or "winreverse" in result.stdout.lower()

    def test_no_args_launches_tui(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无参数（双击 exe）直接进入 TUI 主操作台。"""
        called: dict[str, object] = {}
        monkeypatch.setattr("winreverse.cli._stdout_is_interactive", lambda: True)
        monkeypatch.setattr(
            "winreverse.tui.launch_main_app",
            lambda **kwargs: called.update(launched=True, **kwargs),
        )
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert called.get("launched") is True

    def test_help_lists_all_commands(self) -> None:
        """--help 应列出所有命令。"""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "info" in result.stdout
        assert "skill" in result.stdout
        assert "run" in result.stdout
        assert "settings" in result.stdout
        assert "list-skills" in result.stdout


class TestToolsSubcommandGroup:
    """tools 子命令组测试（文档 §5.8.3 要求）。"""

    def test_tools_help_lists_subcommands(self) -> None:
        """tools --help 应列出所有子命令。"""
        result = runner.invoke(app, ["tools", "--help"])
        assert result.exit_code == 0
        assert "check" in result.stdout
        assert "update" in result.stdout
        assert "verify" in result.stdout
        assert "rollback" in result.stdout
        assert "list" in result.stdout

    @patch("winreverse.cli._get_project_root")
    def test_tools_check_no_manifest(self, mock_root: MagicMock, tmp_path: Path) -> None:
        """无 manifest 时 tools check 应跳过并提示。"""
        mock_root.return_value = tmp_path
        result = runner.invoke(app, ["tools", "check"])
        assert result.exit_code == 0
        assert "跳过" in result.stdout or "不存在" in result.stdout

    @patch("winreverse.cli._get_project_root")
    def test_tools_check_with_tools_manifest(self, mock_root: MagicMock, tmp_path: Path) -> None:
        """有 tools manifest 时应执行更新检查。"""
        # 创建 manifest 文件
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        manifest = tools_dir / "manifest.yaml"
        manifest.write_text(
            'tools:\n  - name: "tshark"\n    version: "4.0.0"\n'
            '    latest_known: "4.6.0"\n    entry: "tshark.exe"\n'
            '    install_path: "tools/tshark/"\n    required: true\n',
            encoding="utf-8",
        )
        mock_root.return_value = tmp_path

        result = runner.invoke(app, ["tools", "check"])
        assert result.exit_code == 0
        assert "tshark" in result.stdout
        assert "4.0.0" in result.stdout
        assert "4.6.0" in result.stdout

    @patch("winreverse.cli._get_project_root")
    def test_tools_list_no_manifest(self, mock_root: MagicMock, tmp_path: Path) -> None:
        """无 manifest 时 tools list 应提示不存在。"""
        mock_root.return_value = tmp_path
        result = runner.invoke(app, ["tools", "list"])
        assert result.exit_code == 0
        assert "不存在" in result.stdout

    @patch("winreverse.cli._get_project_root")
    def test_tools_list_with_manifest(self, mock_root: MagicMock, tmp_path: Path) -> None:
        """有 manifest 时 tools list 应列出工具状态。"""
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        manifest = tools_dir / "manifest.yaml"
        manifest.write_text(
            'tools:\n  - name: "yara"\n    version: "4.3.0"\n'
            '    entry: "yara.exe"\n    install_path: "tools/yara/"\n'
            "    required: true\n",
            encoding="utf-8",
        )
        mock_root.return_value = tmp_path

        result = runner.invoke(app, ["tools", "list"])
        assert result.exit_code == 0
        assert "yara" in result.stdout
        assert "4.3.0" in result.stdout

    @patch("winreverse.cli._get_project_root")
    def test_tools_update_no_manifest(self, mock_root: MagicMock, tmp_path: Path) -> None:
        """无 manifest 时 tools update 应失败。"""
        mock_root.return_value = tmp_path
        result = runner.invoke(app, ["tools", "update"])
        assert result.exit_code == 1
        assert "不存在" in result.stdout

    @patch("winreverse.cli._get_project_root")
    @patch("winreverse.tools.updater.ToolUpdater")
    def test_tools_update_single_tool(
        self,
        mock_updater_cls: MagicMock,
        mock_root: MagicMock,
        tmp_path: Path,
    ) -> None:
        """tools update <name> 应调用 ToolUpdater.update。"""
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        manifest = tools_dir / "manifest.yaml"
        manifest.write_text(
            'tools:\n  - name: "tshark"\n    version: "4.0.0"\n'
            '    entry: "tshark.exe"\n    install_path: "tools/tshark/"\n',
            encoding="utf-8",
        )
        mock_root.return_value = tmp_path

        mock_updater = MagicMock()
        mock_updater.update.return_value = MagicMock(success=True, message="更新成功")
        mock_updater_cls.return_value = mock_updater

        result = runner.invoke(app, ["tools", "update", "tshark"])
        assert result.exit_code == 0
        assert "更新成功" in result.stdout
        mock_updater.update.assert_called_once_with("tshark")

    @patch("winreverse.cli._get_project_root")
    @patch("winreverse.tools.updater.ToolUpdater")
    def test_tools_update_all(
        self,
        mock_updater_cls: MagicMock,
        mock_root: MagicMock,
        tmp_path: Path,
    ) -> None:
        """tools update（无参数）应调用 update_all。"""
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        manifest = tools_dir / "manifest.yaml"
        manifest.write_text(
            'tools:\n  - name: "tshark"\n    version: "4.0.0"\n'
            '    entry: "tshark.exe"\n    install_path: "tools/tshark/"\n',
            encoding="utf-8",
        )
        mock_root.return_value = tmp_path

        mock_updater = MagicMock()
        mock_report = MagicMock()
        mock_report.success_count = 1
        mock_report.failure_count = 0
        mock_report.results = [MagicMock(name="tshark", success=True, message="OK")]
        mock_updater.update_all.return_value = mock_report
        mock_updater_cls.return_value = mock_updater

        result = runner.invoke(app, ["tools", "update"])
        assert result.exit_code == 0
        mock_updater.update_all.assert_called_once()

    @patch("winreverse.cli._get_project_root")
    @patch("winreverse.tools.version_checker.WheelUpdater")
    def test_tools_update_wheel(
        self,
        mock_wheel_cls: MagicMock,
        mock_root: MagicMock,
        tmp_path: Path,
    ) -> None:
        """tools update <name> -w 应更新 Python 依赖。"""
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        wheels_manifest = vendor_dir / "wheels_manifest.yaml"
        wheels_manifest.write_text(
            'wheels:\n  - name: "pymem"\n    version: "1.13"\n',
            encoding="utf-8",
        )
        mock_root.return_value = tmp_path

        mock_wheel = MagicMock()
        mock_wheel.update.return_value = True
        mock_wheel_cls.return_value = mock_wheel

        result = runner.invoke(app, ["tools", "update", "pymem", "-w"])
        assert result.exit_code == 0
        assert "更新成功" in result.stdout
        mock_wheel.update.assert_called_once_with("pymem")

    @patch("winreverse.cli._get_project_root")
    @patch("winreverse.tools.version_checker.VersionChecker")
    def test_tools_verify(
        self,
        mock_checker_cls: MagicMock,
        mock_root: MagicMock,
        tmp_path: Path,
    ) -> None:
        """tools verify 应执行完整性校验并显示结果。"""
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        manifest = tools_dir / "manifest.yaml"
        manifest.write_text(
            'tools:\n  - name: "yara"\n    version: "4.3.0"\n'
            '    entry: "yara.exe"\n    install_path: "tools/yara/"\n',
            encoding="utf-8",
        )
        mock_root.return_value = tmp_path

        mock_checker = MagicMock()
        mock_report = MagicMock()
        mock_report.overall = "ok"
        mock_report.passed = True
        mock_report.tool_report.results = []
        mock_report.wheel_report.results = []
        mock_checker.check_all.return_value = mock_report
        mock_checker_cls.return_value = mock_checker

        result = runner.invoke(app, ["tools", "verify"])
        assert result.exit_code == 0
        assert "总体状态" in result.stdout
        assert "ok" in result.stdout or "通过" in result.stdout

    @patch("winreverse.cli._get_project_root")
    @patch("winreverse.tools.version_checker.VersionChecker")
    def test_tools_verify_with_export(
        self,
        mock_checker_cls: MagicMock,
        mock_root: MagicMock,
        tmp_path: Path,
    ) -> None:
        """tools verify -e 应导出报告到 JSON 文件。"""
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        manifest = tools_dir / "manifest.yaml"
        manifest.write_text(
            'tools:\n  - name: "yara"\n    version: "4.3.0"\n'
            '    entry: "yara.exe"\n    install_path: "tools/yara/"\n',
            encoding="utf-8",
        )
        mock_root.return_value = tmp_path

        mock_checker = MagicMock()
        mock_report = MagicMock()
        mock_report.overall = "ok"
        mock_report.passed = True
        mock_report.tool_report.results = []
        mock_report.wheel_report.results = []
        mock_checker.check_all.return_value = mock_report
        mock_checker_cls.return_value = mock_checker

        export_path = tmp_path / "report.json"
        result = runner.invoke(app, ["tools", "verify", "-e", str(export_path)])
        assert result.exit_code == 0
        assert export_path.exists()
        assert "报告已导出" in result.stdout

    @patch("winreverse.cli._get_project_root")
    @patch("winreverse.tools.updater.ToolUpdater")
    def test_tools_rollback(
        self,
        mock_updater_cls: MagicMock,
        mock_root: MagicMock,
        tmp_path: Path,
    ) -> None:
        """tools rollback <name> 应调用 ToolUpdater.rollback。"""
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        manifest = tools_dir / "manifest.yaml"
        manifest.write_text(
            'tools:\n  - name: "tshark"\n    version: "4.0.0"\n'
            '    entry: "tshark.exe"\n    install_path: "tools/tshark/"\n',
            encoding="utf-8",
        )
        mock_root.return_value = tmp_path

        mock_updater = MagicMock()
        mock_updater.rollback.return_value = MagicMock(success=True, message="回滚成功")
        mock_updater_cls.return_value = mock_updater

        result = runner.invoke(app, ["tools", "rollback", "tshark"])
        assert result.exit_code == 0
        assert "回滚成功" in result.stdout
        mock_updater.rollback.assert_called_once_with("tshark")

    @patch("winreverse.cli._get_project_root")
    def test_tools_rollback_no_manifest(self, mock_root: MagicMock, tmp_path: Path) -> None:
        """无 manifest 时 tools rollback 应失败。"""
        mock_root.return_value = tmp_path
        result = runner.invoke(app, ["tools", "rollback", "tshark"])
        assert result.exit_code == 1
        assert "不存在" in result.stdout
