"""被测模块: winreverse.config.settings 收尾路径（真机 coverage 缺 4 行）。

覆盖点: get_default_config_path 的 frozen（PyInstaller 便携包）分支、
load_config 读取阶段 OSError（路径是目录）包装为 ConfigError、
save_config 写入阶段 OSError（目标为目录）包装为 ConfigError。
Linux 可实跑（依 WINREVERSE_TASKS.md L5-L6 不加平台守卫）。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from winreverse.config import settings
from winreverse.config.settings import (
    ConfigError,
    create_default_config,
    get_default_config_path,
    load_config,
    save_config,
)


class TestGetDefaultConfigPathFrozen:
    def test_frozen_returns_executable_side_config(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """frozen（便携包）模式下配置取 exe 同目录，而非 cwd/home（197）。"""
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", str(tmp_path / "WinReverseAgent.exe"))
        assert get_default_config_path() == tmp_path / "config.toml"


class TestLoadConfigOSError:
    def test_load_config_directory_path_raises_config_error(self, tmp_path: Path) -> None:
        """配置路径是目录时 open 抛 IsADirectoryError，包装为 ConfigError（253）。"""
        target = tmp_path / "config.toml"
        target.mkdir()
        with pytest.raises(ConfigError, match="无法读取配置文件"):
            load_config(target)


class TestSaveConfigOSError:
    def test_save_config_directory_target_raises_config_error(self, tmp_path: Path) -> None:
        """写入目标是目录时 open("w") 抛 OSError，包装为 ConfigError（326-327）。"""
        target = tmp_path / "config.toml"
        target.mkdir()
        with pytest.raises(ConfigError, match="无法写入配置文件"):
            save_config(create_default_config(), target)


def test_module_exports_frozen_constant_name() -> None:
    """settings 模块默认文件名常量在位（防误改名回归）。"""
    assert settings._DEFAULT_CONFIG_FILENAME == "config.toml"
