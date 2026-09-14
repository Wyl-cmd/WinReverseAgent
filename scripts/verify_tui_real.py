"""TUI 应用启动与组件可用性验证脚本（不依赖 LLM）。

验证：
- MainApp 可实例化
- SettingsApp 可实例化
- 关键组件（PhaseBar/ToolPanel/FindingsPanel/EventLog）可渲染
- 斜杠命令注册正确
- SettingsScreen 可被 push

使用 Textual 的 run_test() 异步测试模式，不真正进入交互循环。
"""

from __future__ import annotations

import asyncio
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


async def test_main_app() -> bool:
    """测试 MainApp 主操作台。

    Returns:
        True: 通过
        False: 失败
    """
    print("—— MainApp 主操作台测试 ——")
    try:
        from winreverse.tui.main_app import MainApp

        app = MainApp()
        print("  [OK] MainApp 实例化成功")

        async with app.run_test() as pilot:
            await pilot.pause()
            print("  [OK] MainApp 启动成功（run_test）")

            # 验证关键组件存在
            from winreverse.tui.panels import EventLog, FindingsPanel, PhaseBar, ToolPanel

            try:
                app.query_one("#header-bar")
                print("  [OK] Header 组件存在")
            except Exception:
                print("  [FAIL] Header 组件缺失")
                return False

            try:
                app.query_one(PhaseBar)
                print("  [OK] PhaseBar 组件存在")
            except Exception:
                print("  [FAIL] PhaseBar 组件缺失")
                return False

            try:
                app.query_one(ToolPanel)
                print("  [OK] ToolPanel 组件存在")
            except Exception:
                print("  [FAIL] ToolPanel 组件缺失")
                return False

            try:
                app.query_one(FindingsPanel)
                print("  [OK] FindingsPanel 组件存在")
            except Exception:
                print("  [FAIL] FindingsPanel 组件缺失")
                return False

            try:
                app.query_one(EventLog)
                print("  [OK] EventLog 组件存在")
            except Exception:
                print("  [FAIL] EventLog 组件缺失")
                return False

            # 验证 Input 存在
            from textual.widgets import Input

            try:
                app.query_one(Input)
                print("  [OK] Input 输入框存在")
            except Exception:
                print("  [FAIL] Input 输入框缺失")
                return False

            # 验证斜杠命令列表
            slash_cmds = getattr(app, "_SLASH_COMMANDS", {})
            if slash_cmds:
                print(f"  [OK] 斜杠命令已注册: {list(slash_cmds.keys())}")
                # 验证关键命令存在
                required_cmds = ["/help", "/skills", "/tools", "/settings", "/quit"]
                for cmd in required_cmds:
                    if cmd not in slash_cmds:
                        print(f"  [FAIL] 缺少斜杠命令: {cmd}")
                        return False
                print(f"  [OK] 关键斜杠命令全部存在: {required_cmds}")
            else:
                print("  [FAIL] 斜杠命令未注册")
                return False

            # 测试 /settings 命令推送 SettingsScreen
            try:
                app._cmd_settings()
                await pilot.pause()
                # 验证 SettingsScreen 被推送

                current = app.screen
                screen_name = type(current).__name__
                if "Settings" in screen_name:
                    print(f"  [OK] /settings 命令成功推送: {screen_name}")
                else:
                    print(f"  [WARN] /settings 后当前 Screen: {screen_name}")
                # 退出 SettingsScreen
                app.pop_screen()
                await pilot.pause()
            except Exception as e:
                print(f"  [FAIL] /settings 命令异常: {type(e).__name__}: {e}")
                return False

        print("  [OK] MainApp 测试通过")
        return True
    except Exception as e:
        print(f"  [FAIL] MainApp 测试异常: {type(e).__name__}: {e}")
        traceback.print_exc()
        return False


async def test_settings_app() -> bool:
    """测试 SettingsApp 设置页面。

    Returns:
        True: 通过
        False: 失败
    """
    print()
    print("—— SettingsApp 设置页面测试 ——")
    try:
        from textual.widgets import TabbedContent

        from winreverse.tui.app import SettingsApp
        from winreverse.tui.screens.llm_config import LLMConfigPane
        from winreverse.tui.screens.skill_list import SkillListPane
        from winreverse.tui.screens.tool_center import ToolCenterPane

        app = SettingsApp()
        print("  [OK] SettingsApp 实例化成功")

        async with app.run_test() as pilot:
            await pilot.pause()
            print("  [OK] SettingsApp 启动成功")

            # 验证 TabbedContent 存在（query_one 找不到时抛异常，由 except 捕获）
            try:
                app.query_one(TabbedContent)
                print("  [OK] TabbedContent 存在")
            except Exception:
                print("  [FAIL] TabbedContent 缺失")
                return False

            # 验证三个 Tab 内容存在
            try:
                app.query_one(LLMConfigPane)
                print("  [OK] LLM 配置 Tab 存在")
            except Exception:
                print("  [FAIL] LLM 配置 Tab 缺失")
                return False

            try:
                app.query_one(SkillListPane)
                print("  [OK] Skill 列表 Tab 存在")
            except Exception:
                print("  [FAIL] Skill 列表 Tab 缺失")
                return False

            try:
                app.query_one(ToolCenterPane)
                print("  [OK] 工具管理 Tab 存在")
            except Exception:
                print("  [FAIL] 工具管理 Tab 缺失")
                return False

            # 验证状态栏存在
            from textual.widgets import Static

            try:
                app.query_one("#settings-status-bar", Static)
                print("  [OK] 状态栏存在")
            except Exception:
                print("  [FAIL] 状态栏缺失")
                return False

        print("  [OK] SettingsApp 测试通过")
        return True
    except Exception as e:
        print(f"  [FAIL] SettingsApp 测试异常: {type(e).__name__}: {e}")
        traceback.print_exc()
        return False


async def main() -> int:
    """主测试函数。"""
    print("=" * 70)
    print("WinReverseAgent TUI 可视化界面验证")
    print("=" * 70)
    print()

    results = []
    results.append(("MainApp 主操作台", await test_main_app()))
    results.append(("SettingsApp 设置页面", await test_settings_app()))

    print()
    print("=" * 70)
    print("测试汇总")
    print("=" * 70)
    for name, ok in results:
        status = "[OK]" if ok else "[FAIL]"
        print(f"  {status} {name}")

    all_pass = all(ok for _, ok in results)
    if all_pass:
        print("\n[OK] TUI 界面全部测试通过")
        return 0
    print("\n[FAIL] 存在测试失败")
    return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except Exception:
        traceback.print_exc()
        exit_code = 1
    sys.exit(exit_code)
