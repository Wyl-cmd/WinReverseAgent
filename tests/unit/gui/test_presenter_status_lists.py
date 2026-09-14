"""测试模块：winreverse.gui.presenter — 工具/wheel 状态列表的完整弧线。

补齐 test_gui.py 未覆盖的路径：list_tools_status() 的条目映射与异常兜底、
list_wheels_status() 的缺失/异常/成功三条路径。全程临时目录 + monkeypatch.chdir，
不依赖仓库真实 manifest，不联网。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from winreverse.gui.presenter import list_tools_status, list_wheels_status

_TOOLS_MANIFEST = """\
schema_version: "1.0"
tools:
  - name: fakebin
    version: "1.2.3"
    install_path: "tools/fakebin/"
    entry: "fakebin.exe"
    required: true
"""

_WHEELS_MANIFEST_TEMPLATE = """\
schema_version: "1.0"
python_version: "3.12"
platform: "win_amd64"
wheels:
  - name: fakepkg
    version: "0.1.0"
    wheel_file: "fakepkg-0.1.0-py3-none-any.whl"
    sha256: "{sha}"
    import_name: fakepkg
    required: true
"""


class TestListToolsStatus:
    """list_tools_status 的成功映射与异常兜底。"""

    def test_maps_manifest_entries_with_install_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """manifest 条目映射为 kind/name/version/installed/required 字典。"""
        monkeypatch.chdir(tmp_path)
        manifest_dir = tmp_path / "tools"
        manifest_dir.mkdir()
        (manifest_dir / "manifest.yaml").write_text(_TOOLS_MANIFEST, encoding="utf-8")
        entry_dir = manifest_dir / "fakebin"
        entry_dir.mkdir()
        (entry_dir / "fakebin.exe").write_bytes(b"MZ")

        items = list_tools_status()

        assert items == [
            {
                "kind": "tool",
                "name": "fakebin",
                "version": "1.2.3",
                "installed": True,
                "required": True,
            }
        ]

    def test_malformed_manifest_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """manifest 存在但解析失败时吞异常返回空列表。"""
        monkeypatch.chdir(tmp_path)
        manifest_dir = tmp_path / "tools"
        manifest_dir.mkdir()
        (manifest_dir / "manifest.yaml").write_text("tools: [ {unclosed", encoding="utf-8")

        assert list_tools_status() == []


class TestListWheelsStatus:
    """list_wheels_status 的缺失/异常/成功三条路径。"""

    def test_missing_manifest_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """wheels manifest 缺失时返回空列表而非抛错。"""
        monkeypatch.chdir(tmp_path)
        assert list_wheels_status() == []

    def test_malformed_manifest_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """wheels manifest 存在但解析失败时吞异常返回空列表。"""
        monkeypatch.chdir(tmp_path)
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "wheels_manifest.yaml").write_text("wheels: - oops", encoding="utf-8")

        assert list_wheels_status() == []

    def test_maps_wheel_entries_with_check_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """wheel 文件与 sha256 匹配时映射为 installed=True 的状态字典。"""
        monkeypatch.chdir(tmp_path)
        vendor = tmp_path / "vendor"
        wheels_dir = vendor / "wheels"
        wheels_dir.mkdir(parents=True)
        wheel_bytes = b"fake wheel payload"
        sha = hashlib.sha256(wheel_bytes).hexdigest()
        (vendor / "wheels_manifest.yaml").write_text(
            _WHEELS_MANIFEST_TEMPLATE.format(sha=sha), encoding="utf-8"
        )
        (wheels_dir / "fakepkg-0.1.0-py3-none-any.whl").write_bytes(wheel_bytes)

        items = list_wheels_status()

        assert items == [
            {
                "kind": "wheel",
                "name": "fakepkg",
                "version": "0.1.0",
                "installed": True,
                "required": True,
                "status": "ok",
            }
        ]
