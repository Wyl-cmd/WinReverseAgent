"""测试模块：winreverse.cli.net（winreverse net 子命令组）。

覆盖：interfaces/capture/read/edit 的参数委托、输出文案、tshark 缺失与
NetworkToolError 错误出口、read 行数上限（>200 截断提示）与字段提取拆分。
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from winreverse.cli import app
from winreverse.forensics.network import (
    NetworkInterface,
    NetworkToolError,
    PcapReadResult,
)

runner = CliRunner()

TSHARK = "winreverse.forensics.network.TsharkBridge"
EDITCAP = "winreverse.forensics.network.EditcapBridge"


@pytest.fixture()
def bridge_cls() -> MagicMock:
    """patch TsharkBridge 源模块。"""
    with patch(TSHARK) as cls:
        yield cls


class TestInterfacesCommand:
    """net interfaces：接口枚举渲染与错误出口。"""

    def test_lists_interfaces(self, bridge_cls: MagicMock) -> None:
        bridge_cls.return_value.list_interfaces.return_value = [
            NetworkInterface(index=0, name="eth0", description="以太网"),
            NetworkInterface(index=1, name="lo", description="", loopback=True),
        ]
        result = runner.invoke(app, ["net", "interfaces"])
        assert result.exit_code == 0
        assert "eth0" in result.stdout
        assert "以太网" in result.stdout
        assert "2" in result.stdout
        bridge_cls.assert_called_once_with()  # 未传 --tshark 时空参构造

    def test_no_tshark_exits_1(self) -> None:
        with patch(TSHARK, side_effect=NetworkToolError("找不到 tshark")):
            result = runner.invoke(app, ["net", "interfaces"])
        assert result.exit_code == 1
        assert "找不到 tshark" in result.stdout

    def test_list_error_exits_1(self, bridge_cls: MagicMock) -> None:
        bridge_cls.return_value.list_interfaces.side_effect = NetworkToolError("tshark 失败")
        result = runner.invoke(app, ["net", "interfaces"])
        assert result.exit_code == 1
        assert "tshark 失败" in result.stdout


class TestCaptureCommand:
    """net capture：抓包参数委托与权限错误出口。"""

    def test_capture_forwards_arguments(self, bridge_cls: MagicMock, tmp_path: Path) -> None:
        out = tmp_path / "c.pcap"
        bridge_cls.return_value.live_capture.return_value = out
        result = runner.invoke(
            app,
            ["net", "capture", "0", "-o", str(out), "-d", "10", "-f", "host 1.2.3.4"],
        )
        assert result.exit_code == 0
        assert "pcap 已保存" in result.stdout
        kwargs = bridge_cls.return_value.live_capture.call_args.kwargs
        assert kwargs["interface"] == "0"
        assert kwargs["duration_seconds"] == 10
        assert kwargs["capture_filter"] == "host 1.2.3.4"

    def test_capture_permission_error(self, bridge_cls: MagicMock, tmp_path: Path) -> None:
        bridge_cls.return_value.live_capture.side_effect = NetworkToolError("无抓包权限")
        result = runner.invoke(app, ["net", "capture", "0", "-o", str(tmp_path / "c.pcap")])
        assert result.exit_code == 1
        assert "无抓包权限" in result.stdout
        assert "管理员权限" in result.stdout


class TestReadCommand:
    """net read：pcap 解析、字段提取与 200 行截断。"""

    def test_reads_pcap(self, bridge_cls: MagicMock, tmp_path: Path) -> None:
        pcap = tmp_path / "c.pcap"
        bridge_cls.return_value.read_pcap.return_value = PcapReadResult(
            file=str(pcap), packet_count=3, lines=["a", "b", "c"]
        )
        result = runner.invoke(app, ["net", "read", str(pcap), "-Y", "http.request"])
        assert result.exit_code == 0
        assert "3 行" in result.stdout
        kwargs = bridge_cls.return_value.read_pcap.call_args.kwargs
        assert kwargs["display_filter"] == "http.request"
        assert kwargs["fields"] is None

    def test_fields_option_split(self, bridge_cls: MagicMock, tmp_path: Path) -> None:
        pcap = tmp_path / "c.pcap"
        bridge_cls.return_value.read_pcap.return_value = PcapReadResult(
            file=str(pcap), packet_count=0
        )
        runner.invoke(app, ["net", "read", str(pcap), "--fields", "ip.src, http.host"])
        kwargs = bridge_cls.return_value.read_pcap.call_args.kwargs
        assert kwargs["fields"] == ["ip.src", "http.host"]

    def test_truncates_over_200_lines(self, bridge_cls: MagicMock, tmp_path: Path) -> None:
        pcap = tmp_path / "c.pcap"
        bridge_cls.return_value.read_pcap.return_value = PcapReadResult(
            file=str(pcap), packet_count=205, lines=[f"line-{i}" for i in range(205)]
        )
        result = runner.invoke(app, ["net", "read", str(pcap)])
        assert result.exit_code == 0
        assert "line-199" in result.stdout
        assert "line-200" not in result.stdout  # 只显示前 200 行
        assert "仅显示前 200" in result.stdout

    def test_parse_error_exits_1(self, bridge_cls: MagicMock, tmp_path: Path) -> None:
        bridge_cls.return_value.read_pcap.side_effect = NetworkToolError("文件不存在")
        result = runner.invoke(app, ["net", "read", str(tmp_path / "no.pcap")])
        assert result.exit_code == 1
        assert "文件不存在" in result.stdout


class TestEditCommand:
    """net edit：editcap 文件级编辑委托与错误出口。"""

    def test_edit_forwards_arguments(self, tmp_path: Path) -> None:
        src, dst = tmp_path / "in.pcap", tmp_path / "out.pcap"
        with patch(EDITCAP) as editor_cls:
            editor_cls.return_value.edit_pcap.return_value = dst
            result = runner.invoke(
                app, ["net", "edit", str(src), str(dst), "--first", "100", "--dedup"]
            )
        assert result.exit_code == 0
        assert "已输出" in result.stdout
        kwargs = editor_cls.return_value.edit_pcap.call_args.kwargs
        assert kwargs["keep_first_n"] == 100
        assert kwargs["remove_duplicates"] is True

    def test_edit_error_exits_1(self, tmp_path: Path) -> None:
        with patch(EDITCAP) as editor_cls:
            editor_cls.return_value.edit_pcap.side_effect = NetworkToolError("editcap 失败")
            result = runner.invoke(
                app, ["net", "edit", str(tmp_path / "in.pcap"), str(tmp_path / "o.pcap")]
            )
        assert result.exit_code == 1
        assert "editcap 失败" in result.stdout
