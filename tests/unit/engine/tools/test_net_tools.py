"""测试模块：winreverse.engine.tools.net_tools

覆盖点：net.* 四个工具对 TsharkBridge/EditcapBridge 的参数转发与
默认值处理、必填参数校验、BaseTool 异常兜底、NET_TOOLS 注册清单。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

try:
    import yara  # noqa: F401

    from winreverse.engine.tools.net_tools import (
        NET_TOOLS,
        NetEditPcapTool,
        NetInterfacesTool,
        NetLiveCaptureTool,
        NetReadPcapTool,
    )
except ModuleNotFoundError as exc:
    # engine.tools 包 __init__ 级联引入 yara/pymem 等 Windows 侧 C 扩展，缺失时整体跳过；
    # 用哨兵检查保证多个测试文件的跳过行为与收集顺序无关
    pytest.skip(f"平台依赖缺失，跳过 net_tools 测试：{exc}", allow_module_level=True)

_NS = "winreverse.engine.tools.net_tools"


def _iface(name: str) -> MagicMock:
    """构造带 to_dict 的接口对象。"""
    iface = MagicMock()
    iface.to_dict.return_value = {"number": 1, "name": name}
    return iface


class TestRegistry:
    """NET_TOOLS 注册清单。"""

    def test_registry_contains_all_tools_with_unique_names(self) -> None:
        names = [t.name for t in NET_TOOLS]
        assert len(names) == len(set(names))
        assert set(names) == {
            "net.interfaces",
            "net.live_capture",
            "net.read_pcap",
            "net.edit_pcap",
        }
        assert all(t.description for t in NET_TOOLS)


class TestNetInterfacesTool:
    """net.interfaces。"""

    def test_lists_interfaces(self) -> None:
        with patch(f"{_NS}.TsharkBridge") as bridge_cls:
            bridge = bridge_cls.return_value
            bridge.tshark_path = "/usr/bin/tshark"
            bridge.list_interfaces.return_value = [_iface("eth0"), _iface("wlan0")]
            result = NetInterfacesTool().execute({})
        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["interfaces"][0]["name"] == "eth0"
        assert result["tshark"] == "/usr/bin/tshark"
        bridge_cls.assert_called_once_with()  # 未指定路径用默认构造

    def test_custom_tshark_path_forwarded(self) -> None:
        with patch(f"{_NS}.TsharkBridge") as bridge_cls:
            bridge_cls.return_value.tshark_path = "/opt/tshark"
            bridge_cls.return_value.list_interfaces.return_value = []
            result = NetInterfacesTool().execute({"tshark_path": "/opt/tshark"})
        bridge_cls.assert_called_once_with("/opt/tshark")
        assert result["status"] == "success"
        assert result["count"] == 0


class TestNetLiveCaptureTool:
    """net.live_capture。"""

    def test_arguments_forwarded_and_duration_coerced(self) -> None:
        with patch(f"{_NS}.TsharkBridge") as bridge_cls:
            bridge = bridge_cls.return_value
            bridge.live_capture.return_value = "/tmp/out.pcap"
            result = NetLiveCaptureTool().execute(
                {
                    "output_pcap": "/tmp/out.pcap",
                    "interface": 3,
                    "duration_seconds": "45",  # 字符串也应转 int
                    "capture_filter": "tcp port 443",
                }
            )
        assert result["status"] == "success"
        assert result["duration_seconds"] == 45
        assert result["pcap"] == "/tmp/out.pcap"
        bridge.live_capture.assert_called_once_with(
            "/tmp/out.pcap", interface=3, duration_seconds=45, capture_filter="tcp port 443"
        )

    def test_missing_output_pcap_is_error(self) -> None:
        result = NetLiveCaptureTool().execute({})
        assert result["status"] == "error"
        assert "output_pcap" in result["error_message"]

    def test_bridge_failure_is_caught(self) -> None:
        with patch(f"{_NS}.TsharkBridge") as bridge_cls:
            bridge_cls.return_value.live_capture.side_effect = RuntimeError("tshark 未安装")
            result = NetLiveCaptureTool().execute({"output_pcap": "/tmp/x.pcap"})
        assert result["status"] == "error"
        assert "tshark 未安装" in result["error_message"]


class TestNetReadPcapTool:
    """net.read_pcap。"""

    def test_reads_pcap_with_fields(self) -> None:
        parsed = {"packet_count": 10, "rows": []}
        with patch(f"{_NS}.TsharkBridge") as bridge_cls:
            bridge = bridge_cls.return_value
            bridge.read_pcap.return_value.to_dict.return_value = parsed
            result = NetReadPcapTool().execute(
                {
                    "pcap_path": "/tmp/c2.pcap",
                    "display_filter": "http.request",
                    "fields": ["ip.src", "http.host"],
                }
            )
        assert result == {**parsed, "status": "success"}
        bridge.read_pcap.assert_called_once_with(
            "/tmp/c2.pcap", display_filter="http.request", fields=["ip.src", "http.host"]
        )

    def test_non_list_fields_passed_as_none(self) -> None:
        """fields 不是列表时按 None（不提取字段）处理。"""
        with patch(f"{_NS}.TsharkBridge") as bridge_cls:
            bridge = bridge_cls.return_value
            bridge.read_pcap.return_value.to_dict.return_value = {}
            NetReadPcapTool().execute({"pcap_path": "/tmp/a.pcap", "fields": "ip.src"})
        bridge.read_pcap.assert_called_once_with("/tmp/a.pcap", display_filter="", fields=None)

    def test_missing_pcap_path_is_error(self) -> None:
        assert NetReadPcapTool().execute({})["status"] == "error"


class TestNetEditPcapTool:
    """net.edit_pcap。"""

    def test_keep_first_n_forwarded_as_int(self) -> None:
        with patch(f"{_NS}.EditcapBridge") as bridge_cls:
            bridge = bridge_cls.return_value
            bridge.edit_pcap.return_value = "/tmp/slice.pcap"
            result = NetEditPcapTool().execute(
                {
                    "input_pcap": "/tmp/in.pcap",
                    "output_pcap": "/tmp/slice.pcap",
                    "keep_first_n": "100",
                }
            )
        assert result == {"pcap": "/tmp/slice.pcap", "status": "success"}
        bridge.edit_pcap.assert_called_once_with(
            "/tmp/in.pcap", "/tmp/slice.pcap", keep_first_n=100, remove_duplicates=False
        )

    def test_no_options_passes_none(self) -> None:
        with patch(f"{_NS}.EditcapBridge") as bridge_cls:
            bridge = bridge_cls.return_value
            NetEditPcapTool().execute(
                {
                    "input_pcap": "/tmp/in.pcap",
                    "output_pcap": "/tmp/out.pcap",
                    "remove_duplicates": True,
                }
            )
        bridge.edit_pcap.assert_called_once_with(
            "/tmp/in.pcap", "/tmp/out.pcap", keep_first_n=None, remove_duplicates=True
        )

    @pytest.mark.parametrize(
        "input_data", [{"output_pcap": "/tmp/o.pcap"}, {"input_pcap": "/tmp/i.pcap"}, {}]
    )
    def test_missing_required_params_are_error(self, input_data: dict) -> None:
        result = NetEditPcapTool().execute(input_data)
        assert result["status"] == "error"
