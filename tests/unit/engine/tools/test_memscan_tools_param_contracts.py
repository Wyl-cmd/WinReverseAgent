"""测试模块：winreverse.engine.tools.memscan_tools — 参数转发与上限契约。

覆盖点：dump 的 min_size/max_total_mb、dump_minidump 的 full_memory/自定义路径、
strings 的 min_length、iocs 的 limit/truncated、carve_pe 的 max_count、
analyze 的 top_strings/carve 透传，以及 regions 的 100 条截断上限与清单顺序。
winreverse.engine.tools 导入链缺 yara/pymem 等 Windows 运行时依赖 → Linux 下
如实报 collection error（基线接受态），待 Windows 实机依赖就位后实跑回填。
"""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from winreverse.core import memanalysis_api, memdump_api
from winreverse.engine.tools import memscan_tools
from winreverse.engine.tools._base import BaseTool
from winreverse.engine.tools.memory_tools import _clear_sessions, _sessions
from winreverse.engine.tools.memscan_tools import MEMSCAN_TOOLS

PID = 4242


@pytest.fixture
def attached_session() -> MagicMock:
    """向会话表注入一个已附加进程的 mock Pymem（用后清理）。"""
    pm = MagicMock()
    pm.process_handle = 1234
    _sessions[PID] = pm
    yield pm
    _clear_sessions()


def _build_fake_pe(size_of_image: int = 0x2000) -> bytes:
    """构造仅头部有效的最小 PE（与既有 memscan 测试同规格的合成数据）。"""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 1700000000, 0, 0, 0xF0, 0x210E)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 56, size_of_image)
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytearray(40)


class TestDumpParamForwarding:
    """memory.dump / memory.dump_minidump 的可选参数转发契约。"""

    def test_dump_forwards_min_size_and_total_cap(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """min_size 与 max_total_mb 换算为字节后透传给 core 层。"""
        captured: dict[str, object] = {}

        def fake_dump(handle: int, output_dir: str, **kwargs: object) -> memdump_api.DumpResult:
            captured.update(kwargs)
            return memdump_api.DumpResult(output_dir=output_dir, manifest_path="m")

        monkeypatch.setattr(memdump_api, "dump_process", fake_dump)
        result = memscan_tools.MemoryDumpTool().execute(
            {"pid": PID, "min_size": 8192, "max_total_mb": 2}
        )
        assert result["status"] == "success"
        assert captured["min_size"] == 8192
        assert captured["max_total_bytes"] == 2 * 1024 * 1024

    def test_minidump_custom_path_and_full_memory_flag(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """自定义输出路径与 full_memory=false 均透传给 core 层。"""
        captured: dict[str, object] = {}

        def fake_minidump(handle: int, pid: int, output_path: str, **kwargs: object) -> Path:
            captured["pid"] = pid
            captured["output_path"] = output_path
            captured.update(kwargs)
            return Path(output_path)

        monkeypatch.setattr(memdump_api, "dump_minidump", fake_minidump)
        result = memscan_tools.MemoryMinidumpTool().execute(
            {"pid": PID, "output_path": "out/target.dmp", "full_memory": False}
        )
        assert result["status"] == "success"
        # core 层返回 Path、工具层 str() 规整（分隔符随平台），断言用 Path 比较
        assert Path(result["output_path"]) == Path("out/target.dmp")
        assert captured["pid"] == PID
        assert captured["full_memory"] is False


class TestFileToolParamContracts:
    """文件分析类工具的过滤/截断/上限契约（真实 core 层 + 合成数据）。"""

    def test_strings_min_length_filters_short_hits(self, tmp_path: Path) -> None:
        """min_length 只过滤过短命中，长字符串保留。"""
        dump_file = tmp_path / "region.bin"
        dump_file.write_bytes(b"ab\x00abcde\x00")
        result = memscan_tools.MemoryStringsTool().execute(
            {"path": str(dump_file), "min_length": 3}
        )
        assert result["status"] == "success"
        values = [s["value"] for s in result["strings"]]
        assert values == ["abcde"]
        assert result["truncated"] is False

    def test_iocs_limit_keeps_total_count_and_marks_truncated(self, tmp_path: Path) -> None:
        """limit 截断展示列表但 count 统计全量，truncated 标志如实上报。"""
        dump_file = tmp_path / "region.bin"
        dump_file.write_bytes(b"http://a.example.top/x http://b.example.top/y\x00")
        result = memscan_tools.MemoryIocsTool().execute({"path": str(dump_file), "limit": 1})
        assert result["status"] == "success"
        # 同一 URL 同时命中 url 与 domain 两类 IOC（core 层既定行为）
        assert result["count"] == 4
        assert result["by_kind"] == {"domain": 2, "url": 2}
        assert len(result["iocs"]) == 1
        assert result["iocs"][0]["kind"] == "domain"
        assert result["truncated"] is True

    def test_carve_pe_max_count_caps_results(self, tmp_path: Path) -> None:
        """max_count 限制雕刻数量：两个 PE 只报第一个。"""
        data = _build_fake_pe() + b"\x00" * 0x2000 + _build_fake_pe() + b"\x00" * 0x2000
        dump_file = tmp_path / "region.bin"
        dump_file.write_bytes(data)
        result = memscan_tools.MemoryCarvePeTool().execute({"path": str(dump_file), "max_count": 1})
        assert result["status"] == "success"
        assert result["count"] == 1
        assert len(result["pes"]) == 1

    def test_analyze_forwards_options_to_core(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """rules_path / top_strings / carve 原样透传给 analyze_dump_dir。"""
        captured: dict[str, object] = {}

        def fake_analyze(dump_dir: str, **kwargs: object) -> SimpleNamespace:
            captured["dump_dir"] = dump_dir
            captured.update(kwargs)
            return SimpleNamespace(to_dict=lambda: {"pid": PID})

        monkeypatch.setattr(memanalysis_api, "analyze_dump_dir", fake_analyze)
        result = memscan_tools.MemoryAnalyzeTool().execute(
            {
                "dump_dir": "out/dump",
                "rules_path": "rules.yar",
                "top_strings": 5,
                "carve": False,
            }
        )
        assert result["status"] == "success"
        assert result["pid"] == PID
        assert captured == {
            "dump_dir": "out/dump",
            "rules_path": "rules.yar",
            "top_strings": 5,
            "carve": False,
        }


class TestRegionsTruncationCap:
    """memory.regions 的列表输出上限（防巨型地址空间撑爆 LLM 上下文）。"""

    def test_regions_truncated_at_100_items(
        self, attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """超过 100 条可执行区域时只展示 100 条并置 truncated=true。"""
        from winreverse.core.memdump_api import (
            MEM_COMMIT,
            MEM_PRIVATE,
            PAGE_EXECUTE_READWRITE,
            MemoryRegion,
        )

        regions = [
            MemoryRegion(
                0x10000 * (i + 1),
                0x1000,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
                MEM_PRIVATE,
            )
            for i in range(101)
        ]
        monkeypatch.setattr(
            memdump_api,
            "enumerate_regions",
            lambda handle, only_committed=True: regions,
        )
        result = memscan_tools.MemoryRegionsTool().execute({"pid": PID, "include_all": True})
        assert result["status"] == "success"
        assert result["total"] == 101
        assert result["suspicious_count"] == 101
        assert len(result["suspicious"]) == 100
        assert len(result["regions"]) == 100
        assert result["truncated"] is True


class TestInventoryOrder:
    """MEMSCAN_TOOLS 注册顺序与类型契约。"""

    def test_inventory_order_and_types(self) -> None:
        """7 个工具按文档顺序排列，且全部是 BaseTool 实例。"""
        expected_order = [
            "memory.regions",
            "memory.dump",
            "memory.dump_minidump",
            "memory.strings",
            "memory.iocs",
            "memory.carve_pe",
            "memory.analyze",
        ]
        assert [t.name for t in MEMSCAN_TOOLS] == expected_order
        assert all(isinstance(t, BaseTool) for t in MEMSCAN_TOOLS)
