"""测试模块：winreverse.gui.app —— 无头自检与回调链路（guest 实机验收）。

dearpygui 直连 import：Linux 侧无该依赖时如实 collection error（不 skip、不桩替）。
主路径 run_gui(check=True)：create_context → _build_ui → destroy_context，
不开窗口不进主循环；本文件在该模式与直接驱动 _build_ui 下断言：
字段绑定、掩码/提示配置、窗口几何、工具表行数、保存/重载/刷新回调、图标定位。
"""

from __future__ import annotations

import sys
from pathlib import Path

import dearpygui.dearpygui as dpg
import pytest
from pydantic import ValidationError

from winreverse.gui import app, presenter
from winreverse.gui.presenter import AgentForm, FormModel, LLMForm

_GUI_TAGS = (
    "llm.base_url",
    "llm.model",
    "llm.api_key",
    "llm.max_tokens",
    "llm.temperature",
    "agent.max_turns",
    "agent.default_agent_type",
    "agent.max_context_size",
    "agent.compaction_strategy",
    "agent.compaction_trigger_ratio",
    "agent.auto_compact",
    "agent.yolo",
    "tools_table",
)


def _make_config(tmp_path: Path) -> Path:
    """写入一份非默认值配置，供断言控件绑定的是文件里的真实值。"""
    cfg = tmp_path / "config.toml"
    presenter.save_form(
        FormModel(
            llm=LLMForm(
                base_url="https://api.test/v1",
                model="probe-model",
                api_key="sk-probe",
                max_tokens=1234,
                temperature=0.55,
            ),
            agent=AgentForm(
                max_turns=13,
                yolo=True,
                max_context_size=123456,
                compaction_strategy="selective",
                auto_compact=False,
                compaction_trigger_ratio=0.5,
            ),
        ),
        cfg,
    )
    return cfg


def _find_status_item() -> int:
    """按状态栏文本前缀定位底部状态 item（无显式 tag）。

    text item 的 get_value 返回文本；无值 item（容器/按钮等）get_value 抛
    SystemExit，逐项跳过。
    """
    for item in dpg.get_all_items():
        try:
            value = dpg.get_value(item)
        except SystemExit:
            continue
        if isinstance(value, str) and value.startswith("配置文件: "):
            return item
    raise AssertionError("未找到状态栏文本 item")


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, FormModel]:
    """构建完整 UI 树并保证销毁（泄漏的 context 会污染后续用例）。"""
    resolved, form = presenter.load_form(_make_config(tmp_path))
    dpg.create_context()
    app._build_ui(dpg, resolved, form)
    yield resolved, form
    dpg.destroy_context()


@pytest.fixture
def tree_with_provider(tree: tuple[Path, FormModel]) -> tuple[Path, FormModel]:
    """在补齐缺失的 "llm.provider" 控件后交付（缺陷登记：GUI 树不含该控件）。"""
    with dpg.window():
        dpg.add_input_text(tag="llm.provider", default_value="openai", show=False)
    return tree


def test_run_gui_check_mode_headless_build_and_destroy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """check=True：建一次 context、建树后即销毁；绝不进 viewport/主循环。"""
    calls = {"create": 0, "destroy": 0, "viewport": 0, "start": 0, "show": 0}
    real = {
        "create": dpg.create_context,
        "destroy": dpg.destroy_context,
        "viewport": dpg.create_viewport,
        "start": dpg.start_dearpygui,
        "show": dpg.show_viewport,
    }

    def bump(key: str, fn, *args, **kw):
        calls[key] += 1
        return fn(*args, **kw)

    monkeypatch.setattr(dpg, "create_context", lambda: bump("create", real["create"]))
    monkeypatch.setattr(dpg, "destroy_context", lambda: bump("destroy", real["destroy"]))
    monkeypatch.setattr(
        dpg, "create_viewport", lambda **kw: bump("viewport", real["viewport"], **kw)
    )
    monkeypatch.setattr(dpg, "start_dearpygui", lambda: bump("start", real["start"]))
    monkeypatch.setattr(dpg, "show_viewport", lambda: bump("show", real["show"]))

    cfg = _make_config(tmp_path)
    assert app.run_gui(cfg, check=True) is None
    assert app.run_gui(cfg, check=True) is None  # 可重复进入，context 无泄漏

    assert calls["create"] == 2
    assert calls["destroy"] == 2
    assert calls["viewport"] == 0
    assert calls["start"] == 0
    assert calls["show"] == 0


def test_build_ui_binds_form_values(tree: tuple[Path, FormModel]) -> None:
    """全部控件 tag 存在，控件值与配置文件值逐项绑定一致。"""
    _resolved, form = tree
    for tag in _GUI_TAGS:
        assert dpg.does_item_exist(tag), f"缺少控件: {tag}"
    assert dpg.get_value("llm.base_url") == form.llm.base_url
    assert dpg.get_value("llm.model") == form.llm.model
    assert dpg.get_value("llm.api_key") == form.llm.api_key
    assert dpg.get_value("llm.max_tokens") == form.llm.max_tokens
    assert dpg.get_value("llm.temperature") == pytest.approx(form.llm.temperature)
    assert dpg.get_value("agent.max_turns") == form.agent.max_turns
    assert dpg.get_value("agent.default_agent_type") == form.agent.default_agent_type
    assert dpg.get_value("agent.max_context_size") == form.agent.max_context_size
    assert dpg.get_value("agent.compaction_strategy") == form.agent.compaction_strategy
    assert dpg.get_value("agent.compaction_trigger_ratio") == pytest.approx(
        form.agent.compaction_trigger_ratio
    )
    assert dpg.get_value("agent.auto_compact") is form.agent.auto_compact
    assert dpg.get_value("agent.yolo") is form.agent.yolo


def test_build_ui_api_key_masked_and_base_url_hint(tree: tuple[Path, FormModel]) -> None:
    """API Key 输入框启用密码掩码，Base URL 带占位提示。"""
    assert dpg.get_item_configuration("llm.api_key")["password"] is True
    assert dpg.get_item_configuration("llm.base_url")["hint"].startswith("如 https")


def test_build_ui_tab_structure_and_window_geometry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """三个页签齐备；主窗口 760x560 且被设为 primary。"""
    captured: list[tuple[int, bool]] = []
    real_set_primary = dpg.set_primary_window

    def spy_set_primary(tag: int, flag: bool) -> None:
        captured.append((tag, flag))
        real_set_primary(tag, flag)

    monkeypatch.setattr(dpg, "set_primary_window", spy_set_primary)
    resolved, form = presenter.load_form(_make_config(tmp_path))
    dpg.create_context()
    try:
        app._build_ui(dpg, resolved, form)
        labels = {dpg.get_item_label(item) for item in dpg.get_all_items()}
        assert {"LLM 配置", "Agent / 上下文", "工具管理"} <= labels
        assert len(captured) == 1
        main_window, flag = captured[0]
        assert flag is True
        geometry = dpg.get_item_configuration(main_window)
        assert geometry["width"] == 760
        assert geometry["height"] == 560
    finally:
        dpg.destroy_context()


def test_tools_table_columns_rows_and_forwarders(tree: tuple[Path, FormModel]) -> None:
    """工具表 5 列；行数 = 工具状态 + wheel 状态；转发函数与 presenter 一致。"""
    assert app.list_tools_status() == presenter.list_tools_status()
    assert app.list_wheels_status() == presenter.list_wheels_status()
    expected = len(app.list_tools_status()) + len(app.list_wheels_status())
    children = dpg.get_item_children("tools_table")
    assert len(children[0]) == 5  # 类型/名称/版本/状态/必选
    assert len(children[1]) == expected


def test_refresh_tools_table_appends_rows(tree: tuple[Path, FormModel]) -> None:
    """刷新回调把最新状态追加进表。

    缺陷登记（现状锁定）：_refresh_tools_table 只追加不清旧行，点一次多一份
    重复行；修复后应把增量断言改为 after == expected。
    """
    expected = len(app.list_tools_status()) + len(app.list_wheels_status())
    before = len(dpg.get_item_children("tools_table")[1])
    app._refresh_tools_table(dpg, "tools_table")
    after = len(dpg.get_item_children("tools_table")[1])
    assert after - before == expected


def test_on_save_persists_form_and_reports_success(
    tree_with_provider: tuple[Path, FormModel],
) -> None:
    """保存回调读取控件值写入配置文件，状态栏报「已保存: <路径>」。"""
    resolved, _form = tree_with_provider
    dpg.set_value("llm.model", "saved-model")
    dpg.set_value("agent.max_turns", 77)
    status = _find_status_item()
    app._on_save(dpg, resolved, status)
    assert dpg.get_value(status).startswith("已保存: ")
    _path, reloaded = presenter.load_form(resolved)
    assert reloaded.llm.model == "saved-model"
    assert reloaded.agent.max_turns == 77
    assert reloaded.llm.provider == "openai"


def test_on_save_failure_reports_error(
    tree_with_provider: tuple[Path, FormModel], tmp_path: Path
) -> None:
    """保存抛错（目标是目录）时状态栏报「保存失败: <原因>」，不向外抛异常。"""
    status = _find_status_item()
    bad_target = tmp_path / "bad_cfg_dir"
    bad_target.mkdir()
    app._on_save(dpg, bad_target, status)
    assert dpg.get_value(status).startswith("保存失败: ")


def test_on_save_on_real_tree_crashes_missing_provider(tree: tuple[Path, FormModel]) -> None:
    """缺陷锁定：真 UI 树里 "llm.provider" 控件不存在，点「保存配置」即崩。

    _on_save 读取从未创建的 tag，dearpygui 对缺失 tag 抛 SystemExit（不被
    `except Exception` 捕获）→ 真窗口点保存按钮会退出事件循环。修复后本用例
    应改写为走成功分支。
    """
    _resolved, _form = tree
    status = _find_status_item()
    assert dpg.does_item_exist("llm.provider") is False
    with pytest.raises((SystemExit, ValidationError)):
        app._on_save(dpg, _resolved, status)


def test_on_reload_restores_values_from_file(
    tree_with_provider: tuple[Path, FormModel],
) -> None:
    """重载回调把表单回填为文件值，状态栏报「已重载」。"""
    resolved, _form = tree_with_provider
    dpg.set_value("llm.model", "dirty-value")
    dpg.set_value("agent.yolo", False)
    status = _find_status_item()
    app._on_reload(dpg, resolved, status)
    assert dpg.get_value("llm.model") == "probe-model"
    assert dpg.get_value("agent.yolo") is True
    assert dpg.get_value("agent.max_turns") == 13
    assert dpg.get_value(status) == "已重载"


def test_logo_path_frozen_uses_exe_side_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """frozen 模式：图标取 exe 旁 assets/logo.png；缺失返回 None。"""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / "app.exe"))
    assets = tmp_path / "bin" / "assets"
    assets.mkdir(parents=True)
    assert app._logo_path() is None  # assets 存在但无 logo.png
    logo = assets / "logo.png"
    logo.write_bytes(b"\x89PNG\r\n")
    assert app._logo_path() == logo


def test_logo_path_source_layout_points_to_project_assets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """非 frozen：图标候选是项目根 assets/logo.png，文件不存在则 None。"""
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    expected = Path(app.__file__).resolve().parents[2] / "assets" / "logo.png"
    result = app._logo_path()
    assert result == (expected if expected.is_file() else None)


def test_save_form_to_missing_path_creates_config(tmp_path: Path) -> None:
    """save_form 目标不存在时走 ensure_config_exists 建档分支再写入。"""
    fresh = tmp_path / "nested" / "fresh.toml"
    fresh.parent.mkdir(parents=True)
    form = FormModel()
    assert presenter.save_form(form, fresh) == fresh
    assert fresh.is_file()
    _path, reloaded = presenter.load_form(fresh)
    assert reloaded.llm.model == form.llm.model
    assert reloaded.agent.max_turns == form.agent.max_turns
