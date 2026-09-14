"""测试模块：winreverse.engine.tools.memory_tools（增量缺口补充）。

覆盖点：get_session 会话存取与 KeyError、memory.write 的 list/bytearray
输入分支与不支持类型错误、memory.read/write 自定义 encoding 与 max_len
透传、write 缺少 data 参数校验。

平台口径：本模块经 memory_api 引用 pymem（Windows 专有依赖），Linux 本机
collection error = 基线接受态，用例在 Windows 实机流水线实跑回填。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from winreverse.engine.tools.memory_tools import (
    MemoryReadTool,
    MemoryWriteTool,
    _clear_sessions,
    _sessions,
    get_session,
)


@pytest.fixture(autouse=True)
def clear_sessions() -> None:
    """每个测试前后清空会话表。"""
    _clear_sessions()
    yield
    _clear_sessions()


@pytest.fixture
def mock_pm() -> MagicMock:
    """mock 的 Pymem 实例。"""
    pm = MagicMock()
    pm.process_id = 1234
    return pm


class TestGetSession:
    """get_session 会话表存取测试。"""

    def test_returns_attached_session(self, mock_pm: MagicMock) -> None:
        """已附加的 pid 返回对应 Pymem 实例。"""
        _sessions[1234] = mock_pm
        assert get_session(1234) is mock_pm

    def test_missing_pid_raises_keyerror(self) -> None:
        """未附加的 pid 抛 KeyError 并提示先 attach。"""
        with pytest.raises(KeyError, match=r"memory\.attach"):
            get_session(9999)


class TestMemoryReadToolEncoding:
    """memory.read 自定义参数透传测试。"""

    def test_string_max_len_and_encoding_passthrough(self, mock_pm: MagicMock) -> None:
        """max_len 与 encoding 透传给 memory_api.read_string。"""
        _sessions[1234] = mock_pm
        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.read_string",
            return_value="wide",
        ) as mock_read:
            result = MemoryReadTool().execute(
                {
                    "pid": 1234,
                    "address": 0x2000,
                    "type": "string",
                    "max_len": 10,
                    "encoding": "utf-16le",
                }
            )
        assert result["status"] == "success"
        assert result["string"] == "wide"
        mock_read.assert_called_once_with(mock_pm, 0x2000, 10, "utf-16le")


class TestMemoryWriteToolExtras:
    """memory.write 输入形态与参数校验补充测试。"""

    def test_write_bytes_from_list(self, mock_pm: MagicMock) -> None:
        """data 为整数列表时按字节序列写入。"""
        _sessions[1234] = mock_pm
        with patch("winreverse.engine.tools.memory_tools.memory_api.write_bytes") as mock_write:
            result = MemoryWriteTool().execute(
                {"pid": 1234, "address": 0x1000, "type": "bytes", "data": [0x90, 0xCC]}
            )
        assert result["status"] == "success"
        assert result["written"] == 2
        mock_write.assert_called_once_with(mock_pm, 0x1000, b"\x90\xcc")

    def test_write_bytes_from_bytearray(self, mock_pm: MagicMock) -> None:
        """data 为 bytearray 时按字节序列写入。"""
        _sessions[1234] = mock_pm
        with patch("winreverse.engine.tools.memory_tools.memory_api.write_bytes") as mock_write:
            result = MemoryWriteTool().execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "type": "bytes",
                    "data": bytearray(b"\x01\x02\x03"),
                }
            )
        assert result["written"] == 3
        mock_write.assert_called_once_with(mock_pm, 0x1000, b"\x01\x02\x03")

    def test_write_missing_data_key(self, mock_pm: MagicMock) -> None:
        """type=bytes 但缺少 data 参数时返回 error。"""
        _sessions[1234] = mock_pm
        result = MemoryWriteTool().execute({"pid": 1234, "address": 0x1000, "type": "bytes"})
        assert result["status"] == "error"
        assert "data" in result["error_message"]

    def test_write_unsupported_type(self, mock_pm: MagicMock) -> None:
        """不支持的写入类型返回 error。"""
        _sessions[1234] = mock_pm
        result = MemoryWriteTool().execute(
            {"pid": 1234, "address": 0x1000, "type": "float", "value": 1}
        )
        assert result["status"] == "error"
        assert "不支持的写入类型" in result["error_message"]

    def test_write_string_custom_encoding(self, mock_pm: MagicMock) -> None:
        """自定义 encoding 时按该编码计算写入字节数并透传。"""
        _sessions[1234] = mock_pm
        with patch("winreverse.engine.tools.memory_tools.memory_api.write_string") as mock_write:
            result = MemoryWriteTool().execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "type": "string",
                    "string": "héllo",
                    "encoding": "utf-16le",
                }
            )
        assert result["status"] == "success"
        assert result["written"] == 10  # 5 字符 × 2 字节（utf-16le）
        mock_write.assert_called_once_with(mock_pm, 0x1000, "héllo", "utf-16le")
