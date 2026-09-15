"""被测模块: winreverse.engine.tools.android_tools（AndroidInfoTool，真机缺 55-58）。

覆盖点: android.info 的 adb_path 分支（显式路径构造 AdbClient）与
默认构造分支、serial 转发 get_device_info、to_dict 结果回传。
既有 test_android_tools.py 未触及 AndroidInfoTool 的执行体。
Linux 官方口径为 engine/tools yara/die 链 collection error 基线；
本文件直连 import，仅以 /tmp stub 做 PYTHOPNPATH 开发期验证（不入库）。
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from winreverse.engine.tools.android_tools import AndroidInfoTool

_NS = "winreverse.engine.tools.android_tools"


class TestAndroidInfoAdbPath:
    def test_info_custom_adb_path_and_serial_forwarded(self) -> None:
        """显式 adb_path 时以该路径构造 AdbClient，serial 原样转发（55, 57-58）。"""
        with patch(f"{_NS}.AdbClient") as adb_cls:
            device = SimpleNamespace(to_dict=lambda: {"model": "Pixel 8", "android_version": "14"})
            adb_cls.return_value.get_device_info.return_value = device
            result = AndroidInfoTool().execute(
                {"serial": "EMU123", "adb_path": "/opt/platform-tools/adb"}
            )
        adb_cls.assert_called_once_with("/opt/platform-tools/adb")
        adb_cls.return_value.get_device_info.assert_called_once_with("EMU123")
        assert result["status"] == "success"

    def test_info_default_construction_without_adb_path(self) -> None:
        """缺省 adb_path 时无参构造 AdbClient（55 else 分支）。"""
        with patch(f"{_NS}.AdbClient") as adb_cls:
            device = SimpleNamespace(to_dict=lambda: {"model": "EMU"})
            adb_cls.return_value.get_device_info.return_value = device
            result = AndroidInfoTool().execute({"serial": "serial-1"})
        adb_cls.assert_called_once_with()
        adb_cls.return_value.get_device_info.assert_called_once_with("serial-1")
        assert result["status"] == "success"
