"""测试模块：winreverse.tools.version_checker.WheelUpdater

测试 WheelUpdater 的已实现方法：
- fetch_latest_versions: 查询 PyPI 最新版本（mock 网络请求）
- update: 通过 pip install --upgrade 更新（mock subprocess）
- update_all: 批量更新（mock subprocess）
- _load_wheels_manifest: 加载 manifest
- _fetch_pypi_latest: PyPI API 查询（mock 网络请求）
- _get_installed_version: 获取已安装版本（mock subprocess）
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winreverse.tools.version_checker import WheelUpdater


@pytest.fixture
def wheels_manifest_file(tmp_path: Path) -> Path:
    """创建临时 wheels_manifest.yaml 文件。"""
    manifest = tmp_path / "wheels_manifest.yaml"
    manifest.write_text(
        "wheels:\n"
        "  - name: pymem\n"
        '    version: "1.14.0"\n'
        '    wheel_file: "pymem-1.14.0-py3-none-any.whl"\n'
        '    sha256: "abc123"\n'
        '    import_name: "pymem"\n'
        "    required: true\n"
        "  - name: pefile\n"
        '    version: "2024.8.26"\n'
        '    wheel_file: "pefile-2024.8.26-py3-none-any.whl"\n'
        '    sha256: "def456"\n'
        '    import_name: "pefile"\n'
        "    required: true\n",
        encoding="utf-8",
    )
    return manifest


@pytest.fixture
def wheels_dir(tmp_path: Path) -> Path:
    """创建临时 wheels 目录。"""
    d = tmp_path / "vendor" / "wheels"
    d.mkdir(parents=True)
    return d


@pytest.fixture
def wheel_updater(wheels_manifest_file: Path, wheels_dir: Path) -> WheelUpdater:
    """创建 WheelUpdater 实例。"""
    return WheelUpdater(
        wheels_manifest=wheels_manifest_file,
        wheels_dir=wheels_dir,
    )


class TestWheelUpdaterLoadManifest:
    """_load_wheels_manifest 方法测试。"""

    def test_load_valid_manifest(self, wheel_updater: WheelUpdater) -> None:
        """应正确加载 wheels 列表。"""
        wheels = wheel_updater._load_wheels_manifest()
        assert len(wheels) == 2
        assert wheels[0]["name"] == "pymem"
        assert wheels[1]["name"] == "pefile"

    def test_load_missing_manifest(self, tmp_path: Path, wheels_dir: Path) -> None:
        """manifest 不存在时应返回空列表。"""
        updater = WheelUpdater(
            wheels_manifest=tmp_path / "nonexistent.yaml",
            wheels_dir=wheels_dir,
        )
        assert updater._load_wheels_manifest() == []


class TestWheelUpdaterFetchLatestVersions:
    """fetch_latest_versions 方法测试。"""

    def test_fetch_latest_versions_success(
        self,
        wheel_updater: WheelUpdater,
    ) -> None:
        """成功查询时应返回最新版本字典。"""
        # mock _fetch_pypi_latest 返回固定版本
        with patch.object(wheel_updater, "_fetch_pypi_latest", side_effect=["1.15.0", "2024.8.27"]):
            result = wheel_updater.fetch_latest_versions()

        assert result["pymem"] == "1.15.0"
        assert result["pefile"] == "2024.8.27"

    def test_fetch_latest_versions_partial_failure(
        self,
        wheel_updater: WheelUpdater,
    ) -> None:
        """部分查询失败时应回退到 manifest 中的版本。"""
        with patch.object(wheel_updater, "_fetch_pypi_latest", side_effect=[None, "2024.8.27"]):
            result = wheel_updater.fetch_latest_versions()

        # pymem 查询失败，应回退到 manifest 中的版本
        assert result["pymem"] == "1.14.0"
        assert result["pefile"] == "2024.8.27"


class TestWheelUpdaterFetchPypiLatest:
    """_fetch_pypi_latest 方法测试。"""

    def test_fetch_pypi_latest_success(self, wheel_updater: WheelUpdater) -> None:
        """成功查询 PyPI 时应返回版本号。"""
        mock_response = MagicMock()
        # urlopen 使用 with 语句，需让 __enter__ 返回 mock_response 自身
        mock_response.__enter__.return_value = mock_response
        mock_response.read.return_value = json.dumps({"info": {"version": "1.15.0"}}).encode(
            "utf-8"
        )

        with patch("winreverse.tools.version_checker.urlopen", return_value=mock_response):
            result = wheel_updater._fetch_pypi_latest("pymem")

        assert result == "1.15.0"

    def test_fetch_pypi_latest_network_error(self, wheel_updater: WheelUpdater) -> None:
        """网络错误时应返回 None。"""
        from urllib.error import URLError

        with patch("winreverse.tools.version_checker.urlopen", side_effect=URLError("timeout")):
            result = wheel_updater._fetch_pypi_latest("pymem")

        assert result is None


class TestWheelUpdaterUpdate:
    """update 方法测试。"""

    def test_update_success(self, wheel_updater: WheelUpdater) -> None:
        """成功更新时应返回 True 并更新 manifest。"""
        # mock subprocess.run 返回成功
        mock_pip_result = MagicMock()
        mock_pip_result.returncode = 0
        mock_pip_result.stdout = "Successfully installed pymem-1.15.0"
        mock_pip_result.stderr = ""

        # mock _get_installed_version 返回新版本
        with (
            patch("winreverse.tools.version_checker.subprocess.run", return_value=mock_pip_result),
            patch.object(wheel_updater, "_get_installed_version", return_value="1.15.0"),
        ):
            result = wheel_updater.update("pymem")

        assert result is True

    def test_update_pip_failure(self, wheel_updater: WheelUpdater) -> None:
        """pip 安装失败时应返回 False。"""
        mock_pip_result = MagicMock()
        mock_pip_result.returncode = 1
        mock_pip_result.stdout = ""
        mock_pip_result.stderr = "ERROR: Package not found"

        with patch("winreverse.tools.version_checker.subprocess.run", return_value=mock_pip_result):
            result = wheel_updater.update("nonexistent_package")

        assert result is False


class TestWheelUpdaterUpdateAll:
    """update_all 方法测试。"""

    def test_update_all_returns_dict(self, wheel_updater: WheelUpdater) -> None:
        """应返回 {包名: 是否成功} 字典。"""
        with patch.object(wheel_updater, "update", side_effect=[True, False]):
            result = wheel_updater.update_all()

        assert isinstance(result, dict)
        assert result["pymem"] is True
        assert result["pefile"] is False


class TestWheelUpdaterGetInstalledVersion:
    """_get_installed_version 方法测试。"""

    def test_get_installed_version_success(self) -> None:
        """成功获取版本时应返回版本号。"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Name: pymem\nVersion: 1.14.0\nSummary: Python memory access\n"

        with patch("winreverse.tools.version_checker.subprocess.run", return_value=mock_result):
            result = WheelUpdater._get_installed_version("pymem")

        assert result == "1.14.0"

    def test_get_installed_version_not_installed(self) -> None:
        """包未安装时应返回 None。"""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("winreverse.tools.version_checker.subprocess.run", return_value=mock_result):
            result = WheelUpdater._get_installed_version("nonexistent")

        assert result is None
