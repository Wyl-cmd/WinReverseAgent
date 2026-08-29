"""测试模块：winreverse.forensics.android

全部 mock adb/vol 子进程，无真机依赖。覆盖：
- AdbClient（路径解析 / devices / getprop / packages / ps / pull / kernel）
- LiME 引导（步骤 + GPL 隔离声明）
- VolatilityBridge（可用性 / 白名单 / 执行与失败路径）
- AleappBridge（就位探测 / 解析调用）
- AndroidCollector（采集 → 证据链入案编排）
- 工具层（android.lime_guide / 无 adb 时错误路径）
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winreverse.forensics.android.adb import AdbClient, AdbError
from winreverse.forensics.android.aleapp import AleappBridge, AleappError
from winreverse.forensics.android.collector import AndroidCollector
from winreverse.forensics.android.lime import build_lime_guide
from winreverse.forensics.android.volatility import VolatilityBridge, VolatilityError
from winreverse.forensics.case import CaseManager

# =============================================================================
# 测试辅助
# =============================================================================


class FakeAdb(AdbClient):
    """绕过二进制解析的 adb 桩（_run 直接返回预置输出）。"""

    def __init__(self, outputs: dict[str, str] | None = None) -> None:
        self.outputs = outputs or {}
        self.calls: list[list[str]] = []

    def _run(self, args: list[str], *, timeout: int = 30) -> str:
        self.calls.append(args)
        key = " ".join(args)
        for pattern, output in self.outputs.items():
            if key.startswith(pattern) or pattern in key:
                return output
        return ""


def _make_case(tmp_path: Path) -> CaseManager:
    """构造含一个案件的 CaseManager。"""
    manager = CaseManager(tmp_path / "cases")
    manager.create_case("android 排查")
    return manager


# =============================================================================
# AdbClient
# =============================================================================


class TestAdbPathResolution:
    """adb 二进制解析测试。"""

    def test_explicit_path(self, tmp_path: Path) -> None:
        """显式路径优先。"""
        fake = tmp_path / "adb.exe"
        fake.write_bytes(b"")
        adb = AdbClient(fake)
        assert adb.adb_path == fake

    def test_missing_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """三处都找不到时报错并给指引。"""
        monkeypatch.chdir(tmp_path)  # 无 tools/adb/
        monkeypatch.setattr("shutil.which", lambda name: None)
        with pytest.raises(AdbError, match="找不到 adb"):
            AdbClient()


class TestAdbOperations:
    """adb 只读操作解析测试（FakeAdb 桩）。"""

    def test_list_devices(self) -> None:
        """devices -l 输出解析为 DeviceInfo 列表。"""
        adb = FakeAdb(
            {
                "devices -l": (
                    "List of devices attached\n"
                    "emulator-5554          device product:sdk_gphone64 model:sdk_gphone64_x86_64\n"
                    "0A123XYZ               unauthorized usb:1-1\n"
                )
            }
        )
        devices = adb.list_devices()
        assert len(devices) == 2
        assert devices[0].serial == "emulator-5554"
        assert devices[0].state == "device"
        assert devices[0].model == "sdk_gphone64_x86_64"
        assert devices[1].state == "unauthorized"

    def test_get_device_info_parses_getprop(self) -> None:
        """getprop 输出解析出关键属性。"""
        output = "\n".join(
            [
                "[ro.product.model]: [Pixel 8]",
                "[ro.product.brand]: [google]",
                "[ro.build.version.release]: [14]",
                "[ro.build.version.sdk]: [34]",
                "[ro.build.version.security_patch]: [2026-06-05]",
                "[ro.build.display.id]: [AP4A.123]",
                "[ro.build.fingerprint]: [google/xxx]",
                "[malformed line]",
            ]
        )
        adb = FakeAdb({"shell getprop": output})
        info = adb.get_device_info("SER1")
        assert info.model == "Pixel 8"
        assert info.android_version == "14"
        assert info.security_patch == "2026-06-05"
        assert info.api_level == "34"
        assert info.extra["ro.build.fingerprint"] == "google/xxx"

    def test_list_packages_third_party(self) -> None:
        """pm list -3 输出去掉 package: 前缀并排序。"""
        adb = FakeAdb({"pm list packages -3": "package:com.b\npackage:com.a\n"})
        packages = adb.list_packages("S1")
        assert packages == ["com.a", "com.b"]

    def test_list_processes(self) -> None:
        """ps -A 输出解析为进程字典列表。"""
        adb = FakeAdb(
            {
                "shell ps -A": (
                    "USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n"
                    "u0_a123       1234  1234 1234567 123456 0                   0 S com.evil.app\n"
                    "system        999    999   10000  50000 0                   0 S system_server\n"
                )
            }
        )
        procs = adb.list_processes("S1")
        assert len(procs) == 2
        assert procs[0]["pid"] == "1234"
        assert procs[0]["name"] == "com.evil.app"

    def test_pull_file(self, tmp_path: Path) -> None:
        """pull 调用后返回本地路径。"""
        adb = FakeAdb({})

        def fake_run(args: list[str], *, timeout: int = 30) -> str:
            if "pull" in args:
                Path(args[-1]).write_bytes(b"data")
            return ""

        adb._run = fake_run  # type: ignore[method-assign]
        result = adb.pull_file("S1", "/sdcard/f.txt", tmp_path / "out" / "f.txt")
        assert result == tmp_path / "out" / "f.txt"
        assert result.read_bytes() == b"data"

    def test_get_kernel_release_failure_returns_empty(self) -> None:
        """uname 查询失败返回空字符串。"""
        adb = FakeAdb({})

        def boom(args: list[str], *, timeout: int = 30) -> str:
            raise AdbError("device offline")

        adb._run = boom  # type: ignore[method-assign]
        assert adb.get_kernel_release("S1") == ""

    def test_command_failure_raises(self, tmp_path: Path) -> None:
        """adb 返回非零退出码时抛 AdbError（真实命令路径 + mock 子进程）。"""
        fake_bin = tmp_path / "adb.exe"
        fake_bin.write_bytes(b"")
        adb = AdbClient(fake_bin)
        with patch("winreverse.forensics.android.adb.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="device offline")
            with pytest.raises(AdbError, match="device offline"):
                adb.list_packages("S1")


# =============================================================================
# LiME 引导
# =============================================================================


class TestLimeGuide:
    """LiME 引导测试。"""

    def test_build_guide_steps(self) -> None:
        """步骤含 push/insmod/rmmod/pull，且包含 GPL 与 root 警示。"""
        guide = build_lime_guide(
            "SER1", kernel_release="6.1.0-android13", local_module_path="my_lime.ko"
        )
        assert guide.kernel_release == "6.1.0-android13"
        text = "\n".join(guide.steps)
        assert "push my_lime.ko" in text
        assert "insmod" in text and "format=lime" in text
        assert "rmmod lime" in text
        assert "pull" in text
        assert any("GPL-2.0" in w for w in guide.warnings)
        assert any("root" in w for w in guide.warnings)

    def test_guide_without_kernel_has_probe_step(self) -> None:
        """未提供内核版本时引导含查询命令。"""
        guide = build_lime_guide("SER1")
        assert any("uname -r" in s for s in guide.steps)

    def test_to_dict_serializable(self) -> None:
        """to_dict 可 JSON 序列化。"""
        import json

        guide = build_lime_guide("S")
        json.dumps(guide.to_dict())


# =============================================================================
# VolatilityBridge
# =============================================================================


class TestVolatilityBridge:
    """Volatility 3 桥接测试。"""

    def test_unavailable_gives_instructions(self) -> None:
        """PATH 无 vol 命令时给出运行时安装指引（VSL 隔离）。"""
        with patch("winreverse.forensics.android.volatility.shutil.which", return_value=None):
            bridge = VolatilityBridge()
            assert bridge.is_available() is False
            instructions = bridge.install_instructions()
            assert "pip install volatility3" in instructions
            with pytest.raises(VolatilityError, match="pip install"):
                bridge.analyze("x.dmp", "windows.pslist")

    def test_plugin_whitelist(self, tmp_path: Path) -> None:
        """非白名单插件被拒绝。"""
        bridge = VolatilityBridge(vol_path=tmp_path / "vol.exe")
        (tmp_path / "vol.exe").write_text("")
        with pytest.raises(VolatilityError, match="白名单"):
            bridge.analyze(tmp_path / "img.raw", "osint.lookup")

    def test_missing_image(self, tmp_path: Path) -> None:
        """镜像不存在报错。"""
        bridge = VolatilityBridge(vol_path=tmp_path / "vol.exe")
        (tmp_path / "vol.exe").write_text("")
        with pytest.raises(VolatilityError, match="不存在"):
            bridge.analyze(tmp_path / "nope.raw", "linux.pslist")

    def test_analyze_success(self, tmp_path: Path) -> None:
        """成功执行时返回 stdout 与复现命令。"""
        vol = tmp_path / "vol.exe"
        vol.write_text("")
        image = tmp_path / "ram.lime"
        image.write_bytes(b"raw")
        bridge = VolatilityBridge(vol_path=vol)
        with patch("winreverse.forensics.android.volatility.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="PID NAME\n1 init", stderr="")
            result = bridge.analyze(image, "linux.pslist")
        assert "linux.pslist" in result.command
        assert "init" in result.output
        json.dumps(result.to_dict())

    def test_analyze_failure_raises(self, tmp_path: Path) -> None:
        """vol 返回非零时抛错。"""
        vol = tmp_path / "vol.exe"
        vol.write_text("")
        image = tmp_path / "ram.lime"
        image.write_bytes(b"raw")
        bridge = VolatilityBridge(vol_path=vol)
        with patch("winreverse.forensics.android.volatility.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="unsatisfied")
            with pytest.raises(VolatilityError, match="unsatisfied"):
                bridge.analyze(image, "linux.pslist")


# =============================================================================
# AleappBridge
# =============================================================================


class TestAleappBridge:
    """ALEAPP 桥接测试。"""

    def test_unavailable_gives_setup_instructions(self, tmp_path: Path) -> None:
        """源码未就位时给出 git clone 指引。"""
        bridge = AleappBridge(tmp_path / "vendor" / "aleapp")
        assert bridge.is_available() is False
        assert "git clone" in bridge.setup_instructions()
        with pytest.raises(AleappError, match="git clone"):
            bridge.analyze(tmp_path, tmp_path / "out")

    def test_analyze_success(self, tmp_path: Path) -> None:
        """就位后调用 aleapp.py 解析。"""
        aleapp_dir = tmp_path / "vendor" / "aleapp"
        aleapp_dir.mkdir(parents=True)
        (aleapp_dir / "aleapp.py").write_text("# entry", encoding="utf-8")
        target = tmp_path / "extract"
        target.mkdir()
        out = tmp_path / "report"
        bridge = AleappBridge(aleapp_dir)
        with patch("winreverse.forensics.android.aleapp.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = bridge.analyze(target, out)
        assert result.report_dir == str(out)
        assert "aleapp.py" in result.command

    def test_analyze_missing_target(self, tmp_path: Path) -> None:
        """目标不存在报错。"""
        aleapp_dir = tmp_path / "vendor" / "aleapp"
        aleapp_dir.mkdir(parents=True)
        (aleapp_dir / "aleapp.py").write_text("# entry", encoding="utf-8")
        bridge = AleappBridge(aleapp_dir)
        with pytest.raises(AleappError, match="提取数据不存在"):
            bridge.analyze(tmp_path / "nope", tmp_path / "out")


# =============================================================================
# AndroidCollector 编排
# =============================================================================


class TestAndroidCollector:
    """AndroidCollector 采集 → 证据链编排测试。"""

    def _make_collector(self, tmp_path: Path) -> tuple[AndroidCollector, CaseManager, str]:
        """构造采集器与案件，返回 (collector, manager, case_id)。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        adb = FakeAdb({})
        collector = AndroidCollector(manager, adb, work_root=tmp_path / "work")
        return collector, manager, case.case_id

    def test_collect_device_info(self, tmp_path: Path) -> None:
        """设备信息快照落盘并入案，哈希基线建立。"""
        collector, manager, case_id = self._make_collector(tmp_path)
        collector._adb = FakeAdb(
            {
                "shell getprop": (
                    "[ro.product.model]: [Pixel 8]\n"
                    "[ro.build.version.release]: [14]\n"
                    "[ro.build.version.security_patch]: [2026-06-05]\n"
                )
            }
        )
        result = collector.collect_device_info(case_id, "SER1")
        assert result.evidence_id.startswith("ev_")
        assert "Pixel 8" in result.summary
        case = manager.load_case(case_id)
        assert len(case.evidences) == 1
        assert case.evidences[0].type.value == "android_data"
        # 验证证据链完整
        assert manager.verify_case(case_id).passed is True

    def test_collect_packages_and_processes(self, tmp_path: Path) -> None:
        """应用清单与进程快照均入案。"""
        collector, manager, case_id = self._make_collector(tmp_path)
        collector._adb = FakeAdb(
            {
                "pm list packages -3": "package:com.a\n",
                "shell ps -A": "USER PID PPID VSZ RSS WCHAN ADDR S NAME\nu0 1 1 1 1 0 0 S init\n",
            }
        )
        r1 = collector.collect_packages(case_id, "S1")
        r2 = collector.collect_processes(case_id, "S1")
        assert "1 个" in r1.summary
        assert "1 个" in r2.summary
        assert len(manager.load_case(case_id).evidences) == 2

    def test_collect_file(self, tmp_path: Path) -> None:
        """文件拉取入案（pull 后本地产物登记）。"""
        collector, manager, case_id = self._make_collector(tmp_path)
        adb = FakeAdb({})

        def fake_pull(serial: str, remote: str, local: Path) -> Path:
            local.mkdir(parents=True, exist_ok=True)
            target = local / "f.txt"
            target.write_bytes(b"content")
            return local

        adb.pull_file = fake_pull  # type: ignore[method-assign]
        collector._adb = adb
        result = collector.collect_file(case_id, "S1", "/sdcard/f.txt")
        assert "sdcard" in result.summary
        assert manager.verify_case(case_id).passed is True

    def test_lime_guide_via_collector(self, tmp_path: Path) -> None:
        """采集器生成的 LiME 引导包含内核版本。"""
        collector, _, _ = self._make_collector(tmp_path)
        adb = FakeAdb({"shell uname -r": "6.1.0-android13\n"})
        collector._adb = adb
        guide = collector.lime_guide("S1")
        assert guide.kernel_release == "6.1.0-android13"

    def test_collect_missing_case(self, tmp_path: Path) -> None:
        """案件不存在时报错。"""
        manager = CaseManager(tmp_path / "cases")
        collector = AndroidCollector(manager, FakeAdb({}), work_root=tmp_path / "work")
        from winreverse.forensics.case import CaseError

        with pytest.raises(CaseError, match="不存在"):
            collector.collect_device_info("case_20260101_000000_zzzz", "S1")


# =============================================================================
# 工具层
# =============================================================================


class TestAndroidTools:
    """android.* 工具层测试。"""

    def test_lime_guide_tool(self) -> None:
        """android.lime_guide 无需 adb 即可工作。"""
        from winreverse.engine.tools.android_tools import AndroidLimeGuideTool

        result = AndroidLimeGuideTool().execute({"serial": "S1"})
        assert result["status"] == "success"
        assert any("insmod" in s for s in result["steps"])

    def test_devices_tool_without_adb(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """无 adb 二进制时返回错误并给指引。"""
        from winreverse.engine.tools.android_tools import AndroidDevicesTool

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("shutil.which", lambda name: None)
        result = AndroidDevicesTool().execute({})
        assert result["status"] == "error"
        assert "找不到 adb" in result["error_message"]

    def test_analyze_image_tool_whitelist(self, tmp_path: Path) -> None:
        """android.analyze_image 白名单校验透传。"""
        from winreverse.engine.tools.android_tools import AndroidAnalyzeImageTool

        vol = tmp_path / "vol.exe"
        vol.write_text("")
        result = AndroidAnalyzeImageTool().execute(
            {"image_path": str(tmp_path / "x.raw"), "plugin": "evil.plugin", "vol_path": str(vol)}
        )
        assert result["status"] == "error"
        assert "白名单" in result["error_message"]


# =============================================================================
# 可写操作与无线调试（Android 11+）
# =============================================================================


class TestAdbWritableOps:
    """adb 可写操作测试（FakeAdb 桩 + mock 子进程）。"""

    def test_shell_command(self) -> None:
        """通用 shell 命令透传。"""
        adb = FakeAdb({"shell su -c ls": "app_data_dirs"})
        output = adb.shell_command("S1", "su -c ls /data/data")
        assert output == "app_data_dirs"

    def test_push_file(self, tmp_path: Path) -> None:
        """推送存在的文件；不存在的文件报错。"""
        adb = FakeAdb({})
        local = tmp_path / "agent.apk"
        local.write_bytes(b"PK")
        assert adb.push_file("S1", local, "/data/local/tmp/a.apk") == "/data/local/tmp/a.apk"
        with pytest.raises(AdbError, match="不存在"):
            adb.push_file("S1", tmp_path / "nope.apk", "/data/local/tmp/x")

    def test_install_apk(self, tmp_path: Path) -> None:
        """安装 APK 默认带 -r 覆盖参数。"""
        adb = FakeAdb({"install": "Success"})
        apk = tmp_path / "a.apk"
        apk.write_bytes(b"PK\x03\x04")
        output = adb.install_apk("S1", apk)
        assert output == "Success"
        assert any("install" in c and "-r" in c for c in adb.calls)

    def test_uninstall_and_logcat(self) -> None:
        """卸载与 logcat 透传。"""
        adb = FakeAdb({"uninstall": "Success", "shell logcat -d -t 100": "* log *"})
        assert adb.uninstall("S1", "com.x") == "Success"
        assert "log *" in adb.logcat("S1", lines=100)

    def test_screenshot_writes_png(self, tmp_path: Path) -> None:
        """截图走原始字节子进程并落盘。"""
        fake_bin = tmp_path / "adb.exe"
        fake_bin.write_bytes(b"")
        adb = AdbClient(fake_bin)
        png_magic = b"\x89PNG\r\n"
        with patch("winreverse.forensics.android.adb.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=png_magic, stderr=b"")
            result = adb.screenshot("S1", tmp_path / "s.png")
        assert result == tmp_path / "s.png"
        assert result.read_bytes() == png_magic


class TestWirelessDebugging:
    """Android 11+ 无线调试（网络远程调试）测试。"""

    def test_connect(self) -> None:
        """connect 透传 ip:port。"""
        adb = FakeAdb({"connect": "connected to 192.168.1.5:5555"})
        output = adb.connect("192.168.1.5:5555")
        assert "connected" in output
        assert any("connect" in c and "192.168.1.5:5555" in c for c in adb.calls)

    def test_pair_valid_code(self) -> None:
        """pair 透传 ip:配对端口 与 6 位码。"""
        adb = FakeAdb({"pair": "Successfully paired"})
        output = adb.pair("192.168.1.5:37025", "123456")
        assert "paired" in output
        assert any(
            "pair" in c and any("37025" in a for a in c) and any("123456" in a for a in c)
            for c in adb.calls
        )

    def test_pair_invalid_code_rejected(self) -> None:
        """非 6 位配对码直接拒绝（不调用 adb）。"""
        adb = FakeAdb({})
        with pytest.raises(AdbError, match="6 位数字"):
            adb.pair("192.168.1.5:37025", "12a456")
        with pytest.raises(AdbError, match="6 位数字"):
            adb.pair("192.168.1.5:37025", "12345")
        assert adb.calls == []

    def test_pair_bad_address_rejected(self) -> None:
        """缺端口的配对地址被拒绝。"""
        adb = FakeAdb({})
        with pytest.raises(AdbError, match="配对地址"):
            adb.pair("192.168.1.5", "123456")

    def test_tcpip_and_usb_mode(self) -> None:
        """tcpip 切换与切回。"""
        adb = FakeAdb({"tcpip": "restarting in TCP mode port: 5555", "usb": ""})
        adb.tcpip_mode("S1", 5555)
        assert any("tcpip" in c and "5555" in c for c in adb.calls)
        adb.usb_mode("S1")
        assert any("usb" in c for c in adb.calls)

    def test_disconnect(self) -> None:
        """断开全部/指定连接。"""
        adb = FakeAdb({"disconnect": "disconnected"})
        adb.disconnect()
        adb.disconnect("192.168.1.5:5555")
        assert any(c[-1:] == ["disconnect"] or "disconnect" in c for c in adb.calls)


class TestAndroidNewTools:
    """android 新增工具层测试。"""

    def test_shell_tool(self) -> None:
        """android.shell 工具透传命令。"""
        from winreverse.engine.tools.android_tools import AndroidShellTool

        with patch(
            "winreverse.forensics.android.adb.AdbClient._resolve_adb",
            return_value=Path("x") if False else None,
        ):
            # 直接注入 FakeAdb
            tool = AndroidShellTool()
            original = tool.execute
            _ = original
            import winreverse.engine.tools.android_tools as at

            fake = FakeAdb({"shell ls": "data"})
            monkey_adb = fake
            # 通过 mock AdbClient 构造
            with patch.object(at, "AdbClient", return_value=monkey_adb):
                result = tool.execute({"serial": "S1", "command": "ls /data"})
            assert result["status"] == "success"
            assert "data" in result["output"]

    def test_pair_tool_rejects_bad_code(self) -> None:
        """android.pair 工具拒绝非法配对码。"""
        import winreverse.engine.tools.android_tools as at
        from winreverse.engine.tools.android_tools import AndroidPairTool

        fake = FakeAdb({})
        with patch.object(at, "AdbClient", return_value=fake):
            result = AndroidPairTool().execute(
                {"host_port": "192.168.1.5:37025", "pairing_code": "abc"}
            )
        assert result["status"] == "error"
        assert "6 位数字" in result["error_message"]

    def test_connect_tool(self) -> None:
        """android.connect 工具透传。"""
        import winreverse.engine.tools.android_tools as at
        from winreverse.engine.tools.android_tools import AndroidConnectTool

        fake = FakeAdb({"connect": "connected to 1.2.3.4:5555"})
        with patch.object(at, "AdbClient", return_value=fake):
            result = AndroidConnectTool().execute({"host_port": "1.2.3.4:5555"})
        assert result["status"] == "success"
        assert "connected" in result["output"]
