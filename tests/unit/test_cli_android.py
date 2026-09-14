"""测试模块：winreverse.cli.android（winreverse android 子命令组）。

覆盖：devices/info/packages/pull/shell/push/install/logcat/screenshot/
pair/connect/tcpip/lime/analyze-image 的委托参数、输出文案与 AdbError/
VolatilityError 错误出口（adb 桥接以 mock 替身注入，lime 引导用真实纯函数）。
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from winreverse.cli import app
from winreverse.forensics.android.adb import AdbError, DeviceInfo
from winreverse.forensics.android.lime import LimeGuide
from winreverse.forensics.android.volatility import VolatilityAnalysis, VolatilityError

runner = CliRunner()

ADB = "winreverse.forensics.android.adb.AdbClient"


def _device(**overrides: str) -> DeviceInfo:
    fields = {"serial": "emulator-5554", "state": "device", "model": "Pixel_6"}
    fields.update(overrides)
    return DeviceInfo(**fields)


@pytest.fixture()
def adb_cls() -> MagicMock:
    """patch AdbClient 源模块，返回 (类 mock, 实例 mock)。"""
    with patch(ADB) as cls:
        yield cls


class TestDevicesCommand:
    """android devices：设备列表渲染与错误出口。"""

    def test_lists_devices(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.list_devices.return_value = [
            _device(),
            _device(serial="1A2B3C", state="unauthorized", model=""),
        ]
        result = runner.invoke(app, ["android", "devices"])
        assert result.exit_code == 0
        assert "emulator-5554" in result.stdout
        assert "Pixel_6" in result.stdout
        assert "unauthorized" in result.stdout
        adb_cls.assert_called_once_with()  # 未传 --adb 时空参构造

    def test_no_devices_hint(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.list_devices.return_value = []
        result = runner.invoke(app, ["android", "devices"])
        assert result.exit_code == 0
        assert "未发现设备" in result.stdout

    def test_adb_error_exits_1(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.list_devices.side_effect = AdbError("找不到 adb")
        result = runner.invoke(app, ["android", "devices"])
        assert result.exit_code == 1
        assert "找不到 adb" in result.stdout

    def test_adb_path_option_forwarded(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.list_devices.return_value = []
        runner.invoke(app, ["android", "devices", "--adb", "C:\\adb\\adb.exe"])
        adb_cls.assert_called_once_with("C:\\adb\\adb.exe")


class TestInfoCommand:
    """android info：getprop 快照渲染。"""

    def test_renders_snapshot(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.get_device_info.return_value = _device(
            brand="Google",
            android_version="14",
            build_id="UQ1A.240301",
            security_patch="2024-03-05",
            api_level="34",
        )
        result = runner.invoke(app, ["android", "info", "emulator-5554"])
        assert result.exit_code == 0
        for text in ("Google", "Pixel_6", "14", "34", "UQ1A.240301", "2024-03-05"):
            assert text in result.stdout
        adb_cls.return_value.get_device_info.assert_called_once_with("emulator-5554")

    def test_adb_error_exits_1(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.get_device_info.side_effect = AdbError("设备离线")
        result = runner.invoke(app, ["android", "info", "dead"])
        assert result.exit_code == 1
        assert "设备离线" in result.stdout


class TestPackagesCommand:
    """android packages：第三方包清单。"""

    def test_lists_packages(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.list_packages.return_value = ["com.evil.rat", "com.app.x"]
        result = runner.invoke(app, ["android", "packages", "emulator-5554"])
        assert result.exit_code == 0
        assert "2 个" in result.stdout
        assert "com.evil.rat" in result.stdout
        kwargs = adb_cls.return_value.list_packages.call_args.kwargs
        assert kwargs["third_party_only"] is True


class TestFileTransferCommands:
    """android pull / push：文件传输委托与错误出口。"""

    def test_pull(self, adb_cls: MagicMock, tmp_path: Path) -> None:
        local = tmp_path / "evidence.db"
        adb_cls.return_value.pull_file.return_value = local
        result = runner.invoke(
            app, ["android", "pull", "emulator-5554", "/data/data/x.db", str(local)]
        )
        assert result.exit_code == 0
        assert "已拉取" in result.stdout
        adb_cls.return_value.pull_file.assert_called_once_with(
            "emulator-5554", "/data/data/x.db", local
        )

    def test_pull_error(self, adb_cls: MagicMock, tmp_path: Path) -> None:
        adb_cls.return_value.pull_file.side_effect = AdbError("does not exist")
        result = runner.invoke(
            app, ["android", "pull", "emulator-5554", "/nope", str(tmp_path / "o")]
        )
        assert result.exit_code == 1
        assert "拉取失败" in result.stdout

    def test_push(self, adb_cls: MagicMock, tmp_path: Path) -> None:
        local = tmp_path / "agent.apk"
        local.write_bytes(b"x")
        result = runner.invoke(
            app, ["android", "push", "emulator-5554", str(local), "/data/local/tmp/"]
        )
        assert result.exit_code == 0
        assert "已推送" in result.stdout
        adb_cls.return_value.push_file.assert_called_once_with(
            "emulator-5554", local, "/data/local/tmp/"
        )


class TestShellCommand:
    """android shell：命令执行与空输出处理。"""

    def test_returns_output(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.shell_command.return_value = "uid=0(root)"
        result = runner.invoke(app, ["android", "shell", "emulator-5554", "id"])
        assert result.exit_code == 0
        assert "uid=0(root)" in result.stdout
        adb_cls.return_value.shell_command.assert_called_once_with("emulator-5554", "id")

    def test_empty_output_hint(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.shell_command.return_value = ""
        result = runner.invoke(app, ["android", "shell", "emulator-5554", "true"])
        assert result.exit_code == 0
        assert "无输出" in result.stdout

    def test_error_exits_1(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.shell_command.side_effect = AdbError("closed")
        result = runner.invoke(app, ["android", "shell", "emulator-5554", "id"])
        assert result.exit_code == 1


class TestWirelessCommands:
    """android pair / connect / tcpip：无线调试工作流。"""

    def test_pair(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.pair.return_value = "Successfully paired to 192.168.1.8"
        result = runner.invoke(app, ["android", "pair", "192.168.1.8:5554", "123456"])
        assert result.exit_code == 0
        assert "Successfully paired" in result.stdout
        adb_cls.return_value.pair.assert_called_once_with("192.168.1.8:5554", "123456")

    def test_connect(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.connect.return_value = "connected to 192.168.1.8:5555"
        result = runner.invoke(app, ["android", "connect", "192.168.1.8:5555"])
        assert result.exit_code == 0
        assert "connected to 192.168.1.8:5555" in result.stdout

    def test_tcpip(self, adb_cls: MagicMock) -> None:
        result = runner.invoke(app, ["android", "tcpip", "emulator-5554", "--port", "6666"])
        assert result.exit_code == 0
        assert "TCP" in result.stdout
        adb_cls.return_value.tcpip_mode.assert_called_once_with("emulator-5554", 6666)


class TestCollectCommands:
    """android install / logcat / screenshot：采集与部署。"""

    def test_install(self, adb_cls: MagicMock, tmp_path: Path) -> None:
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"x")
        adb_cls.return_value.install_apk.return_value = "Success"
        result = runner.invoke(app, ["android", "install", "emulator-5554", str(apk)])
        assert result.exit_code == 0
        assert "Success" in result.stdout

    def test_logcat_with_tag(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.logcat.return_value = "D/CRM: call state"
        result = runner.invoke(
            app, ["android", "logcat", "emulator-5554", "--lines", "50", "--tag", "CRM"]
        )
        assert result.exit_code == 0
        assert "D/CRM: call state" in result.stdout
        kwargs = adb_cls.return_value.logcat.call_args.kwargs
        assert kwargs["lines"] == 50 and kwargs["filter_tag"] == "CRM"

    def test_logcat_empty(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.logcat.return_value = ""
        result = runner.invoke(app, ["android", "logcat", "emulator-5554"])
        assert result.exit_code == 0
        assert "无日志" in result.stdout

    def test_screenshot(self, adb_cls: MagicMock, tmp_path: Path) -> None:
        target = tmp_path / "s.png"
        adb_cls.return_value.screenshot.return_value = target
        result = runner.invoke(app, ["android", "screenshot", "emulator-5554", str(target)])
        assert result.exit_code == 0
        assert "已保存" in result.stdout


class TestLimeCommand:
    """android lime：真实 build_lime_guide 引导渲染（仅 mock adb 内核版本）。"""

    def test_renders_guide_with_kernel(self, adb_cls: MagicMock) -> None:
        adb_cls.return_value.get_kernel_release.return_value = "5.10.157-android13"
        with patch(
            "winreverse.forensics.android.lime.build_lime_guide",
            return_value=LimeGuide(
                serial="emulator-5554",
                kernel_release="5.10.157-android13",
                steps=["step-push", "step-insmod"],
                warnings=["需要 root"],
            ),
        ) as mock_guide:
            result = runner.invoke(app, ["android", "lime", "emulator-5554"])
        assert result.exit_code == 0
        assert "5.10.157-android13" in result.stdout
        assert "step-push" in result.stdout
        assert "需要 root" in result.stdout
        mock_guide.assert_called_once()

    def test_kernel_query_error_exits_1(self, adb_cls: MagicMock) -> None:
        """内核版本查询失败须走统一错误出口：干净退出并提示，而非裸 AdbError 崩溃。"""
        adb_cls.return_value.get_kernel_release.side_effect = AdbError("no device")
        result = runner.invoke(app, ["android", "lime", "dead"])
        assert result.exit_code == 1
        assert "no device" in result.stdout
        assert not isinstance(result.exception, AdbError)  # 不得以未处理异常形式逃逸


class TestAdbErrorExits:
    """各命令 AdbError 统一错误出口与 _get_adb 构造失败出口（回归：裸异常→exit 1+提示）。"""

    @pytest.mark.parametrize(
        ("args", "method"),
        [
            (["android", "packages", "emulator-5554"], "list_packages"),
            (["android", "push", "emulator-5554", "local.bin", "/data/local/tmp/"], "push_file"),
            (["android", "install", "emulator-5554", "sample.apk"], "install_apk"),
            (["android", "logcat", "emulator-5554"], "logcat"),
            (["android", "screenshot", "emulator-5554", "shot.png"], "screenshot"),
            (["android", "pair", "192.168.1.8:5554", "123456"], "pair"),
            (["android", "connect", "192.168.1.8:5555"], "connect"),
            (["android", "tcpip", "emulator-5554"], "tcpip_mode"),
        ],
        ids=["packages", "push", "install", "logcat", "screenshot", "pair", "connect", "tcpip"],
    )
    def test_method_error_exits_1(self, adb_cls: MagicMock, args: list[str], method: str) -> None:
        """adb 方法调用失败应打印错误并以退出码 1 结束，不抛未处理异常。"""
        setattr(adb_cls.return_value, method, MagicMock(side_effect=AdbError("设备离线")))
        result = runner.invoke(app, args)
        assert result.exit_code == 1
        assert "设备离线" in result.stdout
        assert not isinstance(result.exception, AdbError)

    def test_client_construction_error_exits_1(self, adb_cls: MagicMock) -> None:
        """_get_adb 构造失败（如 adb 不存在）应干净退出而非崩溃。"""
        adb_cls.side_effect = AdbError("找不到 adb 可执行文件")
        result = runner.invoke(app, ["android", "devices"])
        assert result.exit_code == 1
        assert "找不到 adb 可执行文件" in result.stdout
        assert not isinstance(result.exception, AdbError)


class TestAnalyzeImageCommand:
    """android analyze-image：Volatility 桥接与错误出口。"""

    def test_renders_analysis(self) -> None:
        analysis = VolatilityAnalysis(
            image="ram.lime",
            plugin="linux.pslist",
            output="Offset Name\n0x1 init",
            command="vol -f ram.lime linux.pslist",
        )
        with patch("winreverse.forensics.android.volatility.VolatilityBridge") as bridge_cls:
            bridge_cls.return_value.analyze.return_value = analysis
            result = runner.invoke(app, ["android", "analyze-image", "ram.lime", "linux.pslist"])
        assert result.exit_code == 0
        assert "vol -f ram.lime linux.pslist" in result.stdout
        assert "0x1 init" in result.stdout
        bridge_cls.return_value.analyze.assert_called_once_with(Path("ram.lime"), "linux.pslist")

    def test_volatility_error_exits_1(self) -> None:
        with patch("winreverse.forensics.android.volatility.VolatilityBridge") as bridge_cls:
            bridge_cls.return_value.analyze.side_effect = VolatilityError("插件不在白名单")
            result = runner.invoke(app, ["android", "analyze-image", "ram.lime", "evil.plugin"])
        assert result.exit_code == 1
        assert "插件不在白名单" in result.stdout
