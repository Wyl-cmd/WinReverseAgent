"""winreverse.engine.tools.net_tools — 网络分析与抓包工具。

将 forensics.network（tshark/editcap 桥接）封装为 ToolInterface 实现。

工具清单：
- net.interfaces: 列出可抓包接口
- net.live_capture: 实时抓包落盘 pcap（时长/接口/BPF 过滤）
- net.read_pcap: 解析 pcap（显示过滤/字段提取）
- net.edit_pcap: pcap 文件级编辑（editcap：取前 N 包/去重）

边界：实时改包/流量注入不在本层（需 scapy/mitmproxy，见路线图）。

参考：forensics/network.py docstring
"""

from __future__ import annotations

from typing import Any

from winreverse.engine.tools._base import BaseTool
from winreverse.forensics.network import EditcapBridge, TsharkBridge


def _bridge(tshark_path: Any) -> TsharkBridge:
    """构造 TsharkBridge（统一错误出口由 BaseTool 兜底）。"""
    return TsharkBridge(tshark_path) if tshark_path else TsharkBridge()


class NetInterfacesTool(BaseTool):
    """net.interfaces — 列出可抓包接口。"""

    name = "net.interfaces"
    description = "列出本机可抓包的网络接口（编号用于 net.live_capture 的 -i 参数，需内置 tshark）"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        tshark_path = input_data.get("tshark_path")
        bridge = _bridge(tshark_path)
        interfaces = bridge.list_interfaces()
        return {
            "tshark": str(bridge.tshark_path),
            "count": len(interfaces),
            "interfaces": [i.to_dict() for i in interfaces],
        }


class NetLiveCaptureTool(BaseTool):
    """net.live_capture — 实时抓包。"""

    name = "net.live_capture"
    description = (
        "实时抓包落盘 pcap（需管理员权限）：指定接口编号/时长秒/BPF 捕获过滤，"
        "产物可用 net.read_pcap 分析或经 case add 入证"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        output_pcap = str(self._require(input_data, "output_pcap"))
        interface = input_data.get("interface", 1)
        duration = int(input_data.get("duration_seconds", 30))
        capture_filter = str(input_data.get("capture_filter", ""))
        tshark_path = input_data.get("tshark_path")
        bridge = _bridge(tshark_path)
        result_path = bridge.live_capture(
            output_pcap,
            interface=interface,
            duration_seconds=duration,
            capture_filter=capture_filter,
        )
        return {"pcap": str(result_path), "duration_seconds": duration, "interface": str(interface)}


class NetReadPcapTool(BaseTool):
    """net.read_pcap — 解析 pcap。"""

    name = "net.read_pcap"
    description = (
        "解析 pcap（-r）：支持显示过滤（如 'http.request || dns'）与字段提取"
        "（如 ip.src/http.host），是木马 C2 流量分析的核心入口"
    )

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        pcap_path = str(self._require(input_data, "pcap_path"))
        tshark_path = input_data.get("tshark_path")
        bridge = _bridge(tshark_path)
        fields_raw = input_data.get("fields")
        fields = [str(f) for f in fields_raw] if isinstance(fields_raw, list) else None
        result = bridge.read_pcap(
            pcap_path,
            display_filter=str(input_data.get("display_filter", "")),
            fields=fields,
        )
        return result.to_dict()


class NetEditPcapTool(BaseTool):
    """net.edit_pcap — pcap 文件级编辑。"""

    name = "net.edit_pcap"
    description = "编辑 pcap 文件（editcap）：保留前 N 个包（提取 C2 流量样本段）/ 去除重复包"

    def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        input_pcap = str(self._require(input_data, "input_pcap"))
        output_pcap = str(self._require(input_data, "output_pcap"))
        bridge = (
            EditcapBridge(input_data.get("editcap_path"))
            if input_data.get("editcap_path")
            else EditcapBridge()
        )
        result_path = bridge.edit_pcap(
            input_pcap,
            output_pcap,
            keep_first_n=(
                int(input_data["keep_first_n"]) if input_data.get("keep_first_n") else None
            ),
            remove_duplicates=bool(input_data.get("remove_duplicates", False)),
        )
        return {"pcap": str(result_path)}


NET_TOOLS: list[BaseTool] = [
    NetInterfacesTool(),
    NetLiveCaptureTool(),
    NetReadPcapTool(),
    NetEditPcapTool(),
]
