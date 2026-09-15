"""winreverse.gui.app — DearPyGui 配置窗口。

只做字段绑定与布局，全部业务逻辑在 presenter（可单测）。
dearpygui 延迟导入：模块加载不依赖 dpg，仅 run_gui() 需要。

窗口布局：
- LLM 配置页：provider / model / api_key（掩码）/ base_url / max_tokens / temperature
- Agent 配置页：max_turns / yolo / agent_type / 上下文压缩四项
- 工具管理页：外部工具 + vendor wheels 状态表（table + table_row 结构）
- 底部：保存 / 重载 按钮 + 状态栏

`run_gui(..., check=True)` 为无头自检模式：创建 context 并构建完整 UI 树
后立即销毁，不开窗口不进主循环——用于打包冒烟验证（可捕获布局/组件
错误，无需显示器交互）。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_WINDOW_WIDTH = 760
_WINDOW_HEIGHT = 560


class GUIUnavailableError(RuntimeError):
    """dearpygui 不可用（未安装）。"""


def _require_dpg() -> Any:
    """导入并返回 dearpygui 模块，缺失时给出安装指引。"""
    try:
        import dearpygui.dearpygui as dpg
    except ImportError as e:
        raise GUIUnavailableError(
            "dearpygui 未安装。请通过 vendor/wheels 离线安装：\n"
            "  pip install --no-index --find-links=vendor/wheels/ dearpygui==2.3.1\n"
            "或运行 'uv sync' 同步全部依赖。"
        ) from e
    return dpg


def _form_row(dpg: Any, label: str, tag: str, default: Any, **kwargs: Any) -> None:
    """表单行：左标签 + 右控件（horizontal group，替代不可用的 table 裸子项）。"""
    with dpg.group(horizontal=True):
        dpg.add_text(label)
        dpg.add_input_text(tag=tag, default_value=str(default), **kwargs)


def _logo_path() -> Path | None:
    """定位 GUI 窗口图标（frozen 用 exe 旁 assets，源码用项目根 assets）。"""
    import sys

    if getattr(sys, "frozen", False):
        candidate = Path(sys.executable).parent / "assets" / "logo.png"
    else:
        candidate = Path(__file__).resolve().parents[2] / "assets" / "logo.png"
    return candidate if candidate.is_file() else None


def run_gui(config_path: Path | None = None, *, check: bool = False) -> None:
    """启动配置 GUI（阻塞至窗口关闭）。

    Args:
        config_path: 配置文件路径（None 用默认路径）
        check: 无头自检模式——构建完整 UI 树后立即销毁，不开窗口不进主循环
    """
    dpg = _require_dpg()

    from winreverse.gui import presenter

    resolved_path, form = presenter.load_form(config_path)

    dpg.create_context()
    try:
        _build_ui(dpg, resolved_path, form)
        if check:
            return
        dpg.create_viewport(
            title="WinReverseAgent 配置",
            width=_WINDOW_WIDTH,
            height=_WINDOW_HEIGHT,
        )
        logo = _logo_path()
        if logo is not None and logo.is_file():
            dpg.set_viewport_small_icon(str(logo))
            dpg.set_viewport_large_icon(str(logo))
        dpg.setup_viewport()
        dpg.show_viewport()
        dpg.start_dearpygui()
    finally:
        dpg.destroy_context()


def _build_ui(dpg: Any, resolved_path: Path, form: Any) -> None:
    """构建完整 UI 树（run_gui 与无头自检共用）。"""
    with dpg.window(no_scrollbar=True, width=_WINDOW_WIDTH, height=_WINDOW_HEIGHT) as main_window:
        with dpg.tab_bar():
            # ---------------- LLM 配置 ----------------
            with dpg.tab(label="LLM 配置"), dpg.child_window(autosize_x=True, height=-60):
                dpg.add_spacer(height=4)
                dpg.add_text(
                    "协议: OpenAI 兼容（/v1/chat/completions），国内模型均可接入",
                    color=(150, 170, 200),
                )
                _form_row(
                    dpg,
                    "Base URL",
                    "llm.base_url",
                    form.llm.base_url,
                    width=340,
                    hint="如 https://api.moonshot.cn/v1，留空用官方端点",
                )
                _form_row(
                    dpg,
                    "Model",
                    "llm.model",
                    form.llm.model,
                    width=340,
                    hint="如 kimi-k2 / deepseek-chat / gpt-4o",
                )
                _form_row(
                    dpg,
                    "API Key",
                    "llm.api_key",
                    form.llm.api_key,
                    width=340,
                    password=True,
                    hint="留空则从环境变量 OPENAI_API_KEY 读取",
                )
                with dpg.group(horizontal=True):
                    dpg.add_text("Max Tokens")
                    dpg.add_input_int(tag="llm.max_tokens", default_value=form.llm.max_tokens)
                with dpg.group(horizontal=True):
                    dpg.add_text("Temperature")
                    dpg.add_input_float(
                        tag="llm.temperature",
                        default_value=form.llm.temperature,
                        format="%.2f",
                    )

            # ---------------- Agent 配置 ----------------
            with dpg.tab(label="Agent / 上下文"), dpg.child_window(autosize_x=True, height=-60):
                dpg.add_spacer(height=4)
                with dpg.group(horizontal=True):
                    dpg.add_text("最大轮次")
                    dpg.add_input_int(tag="agent.max_turns", default_value=form.agent.max_turns)
                _form_row(
                    dpg,
                    "默认 Agent 类型",
                    "agent.default_agent_type",
                    form.agent.default_agent_type,
                    width=280,
                )
                with dpg.group(horizontal=True):
                    dpg.add_text("上下文窗口上限（token）")
                    dpg.add_input_int(
                        tag="agent.max_context_size",
                        default_value=form.agent.max_context_size,
                    )
                with dpg.group(horizontal=True):
                    dpg.add_text("压缩策略")
                    dpg.add_combo(
                        ("simple", "selective", "layered"),
                        default_value=form.agent.compaction_strategy,
                        tag="agent.compaction_strategy",
                    )
                with dpg.group(horizontal=True):
                    dpg.add_text("压缩触发比例")
                    dpg.add_slider_float(
                        tag="agent.compaction_trigger_ratio",
                        default_value=form.agent.compaction_trigger_ratio,
                        min_value=0.1,
                        max_value=1.0,
                        format="%.2f",
                    )
                dpg.add_checkbox(
                    label="启用自动上下文压缩",
                    default_value=form.agent.auto_compact,
                    tag="agent.auto_compact",
                )
                dpg.add_checkbox(
                    label="跳过危险操作确认（YOLO）",
                    default_value=form.agent.yolo,
                    tag="agent.yolo",
                )

            # ---------------- 工具管理 ----------------
            with dpg.tab(label="工具管理"):
                with dpg.table(
                    header_row=True,
                    borders_innerH=True,
                    row_background=True,
                    tag="tools_table",
                ):
                    for column in ("类型", "名称", "版本", "状态", "必选"):
                        dpg.add_table_column(label=column)
                    for item in [*list_tools_status(), *list_wheels_status()]:
                        with dpg.table_row():
                            dpg.add_text("工具" if item["kind"] == "tool" else "依赖")
                            dpg.add_text(str(item["name"]))
                            dpg.add_text(str(item["version"]))
                            status = "已安装" if item["installed"] else "未安装"
                            color = (92, 184, 92) if item["installed"] else (217, 83, 79)
                            dpg.add_text(status, color=color)
                            dpg.add_text("是" if item["required"] else "否")
                dpg.add_button(
                    label="刷新状态",
                    callback=lambda: _refresh_tools_table(dpg, "tools_table"),
                )

        # ---------------- 底部操作栏 ----------------
        dpg.add_spacer(height=8)
        status_text = dpg.add_text(f"配置文件: {resolved_path}", color=(150, 150, 150))
        with dpg.group(horizontal=True):
            dpg.add_button(
                label="保存配置", callback=lambda: _on_save(dpg, resolved_path, status_text)
            )
            dpg.add_button(
                label="重载", callback=lambda: _on_reload(dpg, resolved_path, status_text)
            )

    dpg.set_primary_window(main_window, True)


def list_tools_status() -> list[dict[str, Any]]:
    """转发 presenter 工具状态（供 UI 构建使用）。"""
    from winreverse.gui import presenter

    return presenter.list_tools_status()


def list_wheels_status() -> list[dict[str, Any]]:
    """转发 presenter wheel 状态（供 UI 构建使用）。"""
    from winreverse.gui import presenter

    return presenter.list_wheels_status()


def _refresh_tools_table(dpg: Any, tools_table: str) -> None:
    """重新填充工具状态表。"""
    from winreverse.gui import presenter

    for item in [*presenter.list_tools_status(), *presenter.list_wheels_status()]:
        with dpg.table_row(parent=tools_table):
            dpg.add_text("工具" if item["kind"] == "tool" else "依赖")
            dpg.add_text(str(item["name"]))
            dpg.add_text(str(item["version"]))
            status = "已安装" if item["installed"] else "未安装"
            color = (92, 184, 92) if item["installed"] else (217, 83, 79)
            dpg.add_text(status, color=color)
            dpg.add_text("是" if item["required"] else "否")


def _on_save(dpg: Any, config_path: Path, status_tag: int) -> None:
    """读取表单值并保存配置。"""
    from winreverse.gui import presenter

    form = presenter.FormModel(
        llm=presenter.LLMForm(
            provider=dpg.get_value("llm.provider"),
            model=dpg.get_value("llm.model"),
            api_key=dpg.get_value("llm.api_key"),
            base_url=dpg.get_value("llm.base_url"),
            max_tokens=int(dpg.get_value("llm.max_tokens")),
            temperature=float(dpg.get_value("llm.temperature")),
        ),
        agent=presenter.AgentForm(
            max_turns=int(dpg.get_value("agent.max_turns")),
            yolo=bool(dpg.get_value("agent.yolo")),
            default_agent_type=dpg.get_value("agent.default_agent_type"),
            max_context_size=int(dpg.get_value("agent.max_context_size")),
            compaction_strategy=dpg.get_value("agent.compaction_strategy"),
            auto_compact=bool(dpg.get_value("agent.auto_compact")),
            compaction_trigger_ratio=float(dpg.get_value("agent.compaction_trigger_ratio")),
        ),
    )
    try:
        saved = presenter.save_form(form, config_path)
    except Exception as e:
        dpg.configure_item(status_tag, default_value=f"保存失败: {e}", color=(217, 83, 79))
        return
    dpg.configure_item(status_tag, default_value=f"已保存: {saved}", color=(92, 184, 92))


def _on_reload(dpg: Any, config_path: Path, status_tag: int) -> None:
    """重新加载配置并回填表单。"""
    from winreverse.gui import presenter

    _path, form = presenter.load_form(config_path)
    dpg.set_value("llm.provider", form.llm.provider)
    dpg.set_value("llm.model", form.llm.model)
    dpg.set_value("llm.api_key", form.llm.api_key)
    dpg.set_value("llm.base_url", form.llm.base_url)
    dpg.set_value("llm.max_tokens", form.llm.max_tokens)
    dpg.set_value("llm.temperature", form.llm.temperature)
    dpg.set_value("agent.max_turns", form.agent.max_turns)
    dpg.set_value("agent.yolo", form.agent.yolo)
    dpg.set_value("agent.default_agent_type", form.agent.default_agent_type)
    dpg.set_value("agent.max_context_size", form.agent.max_context_size)
    dpg.set_value("agent.compaction_strategy", form.agent.compaction_strategy)
    dpg.set_value("agent.auto_compact", form.agent.auto_compact)
    dpg.set_value("agent.compaction_trigger_ratio", form.agent.compaction_trigger_ratio)
    dpg.configure_item(status_tag, default_value="已重载", color=(92, 184, 92))
    logger.info("GUI 配置已重载: %s", config_path)
