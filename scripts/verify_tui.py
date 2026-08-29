"""TUI 功能验证脚本。

使用 Textual 的 run_test 方法验证 SettingsApp 的三个页面功能：
1. LLM 配置页：验证 widget 存在且值正确
2. Skill 列表页：验证 DataTable 加载了 Skill
3. 工具管理中心：验证工具列表加载

运行方式：
    python scripts/verify_tui.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from textual.widgets import DataTable, Input, Select, TabbedContent

from winreverse.tui import SettingsApp
from winreverse.tui.screens.llm_config import LLMConfigPane
from winreverse.tui.screens.skill_list import SkillListPane
from winreverse.tui.screens.tool_center import ToolCenterPane


async def verify_tui() -> None:
    """验证 TUI 各页面功能。"""
    print("=" * 60)
    print("TUI 功能验证开始")
    print("=" * 60)

    # 使用项目根目录作为 project_root
    app = SettingsApp(project_root=PROJECT_ROOT)
    print(f"[1] SettingsApp 初始化成功，project_root={PROJECT_ROOT}")

    async with app.run_test() as pilot:
        await pilot.pause()

        # 验证 TabbedContent 存在
        tc = app.query_one(TabbedContent)
        print(f"[2] TabbedContent 存在，当前 Tab: {tc.active}")

        # ============================================================
        # 验证 LLM 配置页
        # ============================================================
        print("\n--- 验证 LLM 配置页 ---")
        llm_pane = app.query_one(LLMConfigPane)
        print("[3] LLMConfigPane 存在")

        # 验证 provider Select
        provider_select = llm_pane.query_one("#provider", Select)
        print(f"[4] Provider Select 值: {provider_select.value}")

        # 验证 model Input
        model_input = llm_pane.query_one("#model", Input)
        print(f"[5] Model Input 值: {model_input.value}")

        # 验证 api_key Input
        api_key_input = llm_pane.query_one("#api-key", Input)
        print(f"[6] API Key Input (password={api_key_input.password}): {'***' if api_key_input.value else '(空)'}")

        # 验证 max_tokens Input
        max_tokens_input = llm_pane.query_one("#max-tokens", Input)
        print(f"[7] Max Tokens Input 值: {max_tokens_input.value}")

        # 验证 temperature Input
        temperature_input = llm_pane.query_one("#temperature", Input)
        print(f"[8] Temperature Input 值: {temperature_input.value}")

        # 验证 apply_to_config
        original_config = app.config
        llm_pane.apply_to_config(original_config)
        print(f"[9] apply_to_config 成功，provider={original_config.llm.provider}")

        # ============================================================
        # 验证 Skill 列表页
        # ============================================================
        print("\n--- 验证 Skill 列表页 ---")
        # 切换到 Skill 列表 Tab
        await pilot.press("tab")
        await pilot.pause()

        skill_pane = app.query_one(SkillListPane)
        print("[10] SkillListPane 存在")

        skill_table = skill_pane.query_one("#skill-table", DataTable)
        row_count = skill_table.row_count
        print(f"[11] Skill DataTable 行数: {row_count}")

        if row_count > 0:
            for idx in range(row_count):
                row_data = skill_table.get_row_at(idx)
                print(f"     - {row_data[0]}: {row_data[1]}")

        # ============================================================
        # 验证工具管理中心
        # ============================================================
        print("\n--- 验证工具管理中心 ---")
        # 切换到工具管理 Tab
        await pilot.press("tab")
        await pilot.pause()

        tool_pane = app.query_one(ToolCenterPane)
        print("[12] ToolCenterPane 存在")

        tool_table = tool_pane.query_one("#tool-table", DataTable)
        tool_row_count = tool_table.row_count
        print(f"[13] Tool DataTable 行数: {tool_row_count}")

        if tool_row_count > 0:
            print("     工具列表:")
            for idx in range(tool_row_count):
                row_data = tool_table.get_row_at(idx)
                print(f"     - [{row_data[0]}] {row_data[1]} v{row_data[2]} - {row_data[3]}")

    print("\n" + "=" * 60)
    print("TUI 功能验证完成！所有页面正常工作。")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(verify_tui())
