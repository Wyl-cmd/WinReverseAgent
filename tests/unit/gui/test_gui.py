"""测试模块：winreverse.gui

覆盖 presenter 层（表单加载/保存往返、工具状态列表）与窗口层导入守卫。
DearPyGui 窗口本身需要显示器，不做渲染测试（逻辑已在 presenter 覆盖）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.gui.presenter import (
    FormModel,
    list_tools_status,
    load_form,
    save_form,
)


class TestFormRoundtrip:
    """表单加载/保存往返测试。"""

    def test_load_creates_default_when_missing(self, tmp_path: Path) -> None:
        """配置缺失时自动创建默认配置并加载。"""
        target = tmp_path / "config.toml"
        resolved, form = load_form(target)
        assert resolved == target
        assert target.is_file()
        assert form.agent.auto_compact is True
        assert form.agent.compaction_strategy == "layered"

    def test_save_and_reload_roundtrip(self, tmp_path: Path) -> None:
        """表单修改保存后重新加载字段一致。"""
        target = tmp_path / "config.toml"
        _, form = load_form(target)
        form.llm.model = "kimi-k2"
        form.llm.api_key = "sk-test"
        form.agent.max_context_size = 200000
        form.agent.auto_compact = False
        form.agent.compaction_strategy = "selective"
        save_form(form, target)

        _, reloaded = load_form(target)
        assert reloaded.llm.model == "kimi-k2"
        assert reloaded.llm.api_key == "sk-test"
        assert reloaded.agent.max_context_size == 200000
        assert reloaded.agent.auto_compact is False
        assert reloaded.agent.compaction_strategy == "selective"

    def test_save_rejects_out_of_range(self, tmp_path: Path) -> None:
        """超范围字段赋值即被校验拒绝（validate_assignment）。"""
        target = tmp_path / "config.toml"
        _, form = load_form(target)
        with pytest.raises(ValueError):
            form.agent.max_context_size = 1  # 低于 ge=4096


class TestToolStatus:
    """工具状态列表测试。"""

    def test_list_tools_status_shape(self) -> None:
        """真实 manifest 下返回条目含 kind/name/version/installed。"""
        items = list_tools_status()
        if not items:
            pytest.skip("项目 tools/manifest.yaml 不存在（非项目根运行）")
        assert all("name" in item and "installed" in item for item in items)
        names = {item["name"] for item in items}
        assert "tshark" in names

    def test_list_tools_status_missing_manifest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """manifest 缺失时返回空列表而非抛错。"""
        monkeypatch.chdir(tmp_path)
        assert list_tools_status() == []


class TestGuiImportGuard:
    """窗口层导入守卫测试。"""

    def test_require_dpg_available_in_dev_env(self) -> None:
        """开发环境已安装 dearpygui 时正常返回模块。"""
        from winreverse.gui.app import _require_dpg

        dpg = _require_dpg()
        assert dpg is not None

    def test_form_model_defaults(self) -> None:
        """FormModel 默认值与配置默认一致。"""
        form = FormModel()
        assert form.llm.provider == "openai"
        assert form.agent.compaction_strategy == "layered"
        assert form.agent.auto_compact is True
