"""测试模块：winreverse.engine.tools.android_tools

覆盖点：android.* 工具对 AdbClient/VolatilityBridge 的参数转发、
输出截断上限（shell/logcat/install）、必填参数校验、注册清单唯一性。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from winreverse.engine.tools.android_tools import (
    ANDROID_TOOLS,
    AndroidAnalyzeImageTool,
    AndroidConnectTool,
    AndroidDevicesTool,
    AndroidInfoTool,
    AndroidInstallTool,
    AndroidLimeGuideTool,
    AndroidLogcatTool,
    AndroidPackagesTool,
    AndroidPairTool,
    AndroidPullTool,
    AndroidPushTool,
    AndroidScreenshotTool,
    AndroidShellTool,
)

_NS = "winreverse.engine.tools.android_tools"


def _device(serial: str) -> MagicMock:
    dev = MagicMock()
    dev.to_dict.return_value = {"serial": serial, "state": "device"}
    return dev


class TestRegistry:
    """ANDROID_TOOLS 注册清单。"""

    def test_names_unique_and_complete(self) -> None:
        names = [t.name for t in ANDROID_TOOLS]
        assert len(names) == len(set(names))
        assert "android.devices" in names
        assert "android.analyze_image" in names

    def test_all_have_description(self) -> None:
        assert all(t.description for t in ANDROID_TOOLS)


class TestAdbPathSelection:
    """adb_path 参数决定 AdbClient 构造方式。"""

    def test_devices_default_construction(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.list_devices.return_value = [_device("emulator-5554")]
            result = AndroidDevicesTool().execute({})
        adb_cls.assert_called_once_with()
        assert result["status"] == "success"
        assert result["count"] == 1
        assert result["devices"][0]["serial"] == "emulator-5554"

    def test_devices_custom_adb_path(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.list_devices.return_value = []
            AndroidDevicesTool().execute({"adb_path": "/opt/platform-tools/adb"})
        adb_cls.assert_called_once_with("/opt/platform-tools/adb")


class TestRequiredParams:
    """必填参数缺失统一走 BaseTool 兜底为 error。"""

    @pytest.mark.parametrize(
        ("tool", "input_data"),
        [
            (AndroidInfoTool(), {}),
            (AndroidShellTool(), {"serial": "s1"}),  # 缺 command
            (AndroidShellTool(), {"command": "id"}),  # 缺 serial
            (AndroidPairTool(), {"host_port": "127.0.0.1:5555"}),  # 缺 pairing_code
            (AndroidAnalyzeImageTool(), {"image_path": "/tmp/mem.lime"}),  # 缺 plugin
        ],
    )
    def test_missing_param_returns_error(self, tool, input_data: dict) -> None:
        result = tool.execute(input_data)
        assert result["status"] == "error"
        assert "缺少必需参数" in result["error_message"]


class TestAndroidShellTool:
    """android.shell：输出截断与转发。"""

    def test_output_truncated_to_8000(self) -> None:
        huge = "x" * 20000
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.shell_command.return_value = huge
            result = AndroidShellTool().execute({"serial": "s1", "command": "ls /data/local/tmp"})
        assert result["status"] == "success"
        assert len(result["output"]) == 8000
        adb_cls.return_value.shell_command.assert_called_once_with("s1", "ls /data/local/tmp")


class TestAndroidLogcatTool:
    """android.logcat：lines 类型转换与截断。"""

    def test_lines_coerced_and_truncated(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.logcat.return_value = "log" * 10000
            result = AndroidLogcatTool().execute(
                {"serial": "s1", "lines": "50", "filter_tag": "Trojan:*"}
            )
        assert result["status"] == "success"
        assert len(result["log"]) == 12000
        adb_cls.return_value.logcat.assert_called_once_with("s1", lines=50, filter_tag="Trojan:*")

    def test_default_lines(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.logcat.return_value = "ok"
            AndroidLogcatTool().execute({"serial": "s1"})
        adb_cls.return_value.logcat.assert_called_once_with("s1", lines=200, filter_tag="")


class TestAndroidInstallTool:
    """android.install：replace 默认值。"""

    def test_replace_defaults_true(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.install_apk.return_value = "Success"
            result = AndroidInstallTool().execute({"serial": "s1", "apk_path": "/tmp/agent.apk"})
        assert result["apk"] == "/tmp/agent.apk"
        adb_cls.return_value.install_apk.assert_called_once_with(
            "s1", "/tmp/agent.apk", replace=True
        )

    def test_replace_false_forwarded(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.install_apk.return_value = "Success"
            AndroidInstallTool().execute(
                {"serial": "s1", "apk_path": "/tmp/a.apk", "replace": False}
            )
        adb_cls.return_value.install_apk.assert_called_once_with("s1", "/tmp/a.apk", replace=False)

    def test_output_truncated_to_2000(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.install_apk.return_value = "y" * 9999
            result = AndroidInstallTool().execute({"serial": "s1", "apk_path": "/tmp/a.apk"})
        assert len(result["output"]) == 2000


class TestAndroidConnectPair:
    """android.connect / android.pair：无线调试入口。"""

    def test_connect(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.connect.return_value = "connected to 192.168.1.5:5555"
            result = AndroidConnectTool().execute({"host_port": "192.168.1.5:5555"})
        assert result["output"].startswith("connected")
        adb_cls.return_value.connect.assert_called_once_with("192.168.1.5:5555")

    def test_pair(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.pair.return_value = "Successfully paired"
            result = AndroidPairTool().execute(
                {"host_port": "192.168.1.5:37125", "pairing_code": "123456"}
            )
        assert "paired" in result["output"]
        adb_cls.return_value.pair.assert_called_once_with("192.168.1.5:37125", "123456")


class TestAndroidLimeGuideTool:
    """android.lime_guide：纯函数引导的透传（真实调用，不 mock）。"""

    def test_guide_contains_serial_and_custom_paths(self) -> None:
        result = AndroidLimeGuideTool().execute(
            {
                "serial": "PIXEL1",
                "kernel_release": "5.10.157-android13",
                "local_module_path": "/opt/lime.ko",
                "dump_path": "/sdcard/mem.lime",
            }
        )
        assert result["status"] == "success"
        text = str(result)
        assert "PIXEL1" in text  # 命令清单面向目标设备
        assert "/opt/lime.ko" in text
        assert "/sdcard/mem.lime" in text


class TestAndroidAnalyzeImageTool:
    """android.analyze_image：VolatilityBridge 转发。"""

    def test_analyze_forwarded(self) -> None:
        with patch(f"{_NS}.VolatilityBridge") as vol_cls:
            vol_cls.return_value.analyze.return_value.to_dict.return_value = {
                "rows": [["pslist", 1]]
            }
            result = AndroidAnalyzeImageTool().execute(
                {
                    "image_path": "/tmp/mem.lime",
                    "plugin": "pslist",
                    "vol_path": "/opt/vol.py",
                    "extra_args": ["--profile", "Linux"],
                }
            )
        assert result["rows"][0][0] == "pslist"
        vol_cls.assert_called_once_with("/opt/vol.py")
        vol_cls.return_value.analyze.assert_called_once_with(
            "/tmp/mem.lime", "pslist", extra_args=["--profile", "Linux"]
        )


class TestAndroidPackagesTool:
    """android.packages：third_party_only 固定为 True（取证关注面）。"""

    def test_forwards_serial_and_third_party_only(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.list_packages.return_value = ["com.a", "com.b"]
            result = AndroidPackagesTool().execute({"serial": "s1"})
        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["packages"] == ["com.a", "com.b"]
        adb_cls.return_value.list_packages.assert_called_once_with("s1", third_party_only=True)


class TestAndroidPullPushScreenshot:
    """android.pull / push / screenshot：路径参数转发与返回值形状。"""

    def test_pull_returns_resolved_local_path(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.pull_file.return_value = "/tmp/pulled/ef.tar"
            result = AndroidPullTool().execute(
                {"serial": "s1", "remote_path": "/data/app/ef.tar", "local_path": "/tmp/pulled"}
            )
        assert result["status"] == "success"
        assert result["local_path"] == "/tmp/pulled/ef.tar"
        adb_cls.return_value.pull_file.assert_called_once_with(
            "s1", "/data/app/ef.tar", "/tmp/pulled"
        )

    def test_push_returns_remote_path(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.push_file.return_value = "/data/local/tmp/agent.apk"
            result = AndroidPushTool().execute(
                {
                    "serial": "s1",
                    "local_path": "/tmp/agent.apk",
                    "remote_path": "/data/local/tmp/agent.apk",
                }
            )
        assert result["status"] == "success"
        assert result["remote_path"] == "/data/local/tmp/agent.apk"

    def test_screenshot_returns_png_path(self) -> None:
        with patch(f"{_NS}.AdbClient") as adb_cls:
            adb_cls.return_value.screenshot.return_value = "/tmp/evidence/screen.png"
            result = AndroidScreenshotTool().execute(
                {"serial": "s1", "local_path": "/tmp/evidence/screen.png"}
            )
        assert result["status"] == "success"
        assert result["png"] == "/tmp/evidence/screen.png"

    @pytest.mark.parametrize(
        ("tool", "input_data"),
        [
            (AndroidPullTool(), {"serial": "s1", "remote_path": "/a"}),  # 缺 local_path
            (AndroidPushTool(), {"serial": "s1", "local_path": "/a"}),  # 缺 remote_path
            (AndroidScreenshotTool(), {}),  # 缺 serial 与 local_path
        ],
    )
    def test_missing_param_returns_error(self, tool, input_data: dict) -> None:
        result = tool.execute(input_data)
        assert result["status"] == "error"
        assert "缺少必需参数" in result["error_message"]
