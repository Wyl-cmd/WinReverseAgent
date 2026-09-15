"""测试模块：winreverse.engine.tools.memory_tools — MemoryWriteTool 的 bytes 载荷兜底弧。

覆盖点：write_type="bytes" 且 data 为非 str/list/bytes/bytearray（int）时落 else 的
bytes(data_raw) 零字节填充弧（memory_tools.py:169，guest 覆盖率唯一缺失行，09-15
coverage_guest.xml 复核）。导入链缺 yara/pymem 等 Windows 运行时依赖 → Linux 下
如实报 collection error（基线接受态），待 Windows 实机依赖就位后实跑回填。
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from winreverse.core import memory_api
from winreverse.engine.tools.memory_tools import MemoryWriteTool, _clear_sessions, _sessions

PID = 4242


@pytest.fixture
def attached_session() -> MagicMock:
    """向会话表注入一个已附加进程的 mock Pymem（用后清理）。"""
    pm = MagicMock()
    pm.process_handle = 1234
    _sessions[PID] = pm
    yield pm
    _clear_sessions()


def test_write_bytes_non_sequence_payload_uses_bytes_conversion(
    attached_session: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """data 传 int 应走 else 的 bytes(int) 分支：产出等长零字节并按其长度计 written。"""
    tool = MemoryWriteTool()
    captured: dict[str, object] = {}

    def _fake_write_bytes(pm: object, address: int, data: bytes) -> None:
        captured["pm"] = pm
        captured["address"] = address
        captured["data"] = data

    monkeypatch.setattr(memory_api, "write_bytes", _fake_write_bytes)
    out = tool.execute({"pid": PID, "address": 0x1000, "type": "bytes", "data": 5})

    assert out == {"status": "success", "written": 5}
    assert captured["data"] == b"\x00" * 5
    assert captured["pm"] is attached_session
    assert captured["address"] == 0x1000
