"""测试模块：winreverse.engine.tools.memory_tools

测试内存操作工具。使用 mock 避免 pymem 的真实进程附加。
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from winreverse.engine.tools.memory_tools import (
    MEMORY_TOOLS,
    MemoryAttachTool,
    MemoryReadTool,
    MemoryWriteTool,
    _clear_sessions,
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


class TestMemoryAttachTool:
    """memory.attach 工具测试。"""

    def test_success(self, mock_pm: MagicMock) -> None:
        """成功附加进程。"""
        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.attach",
            return_value=mock_pm,
        ):
            tool = MemoryAttachTool()
            result = tool.execute({"process_name": "notepad.exe"})

        assert result["status"] == "success"
        assert result["pid"] == 1234
        assert result["process_name"] == "notepad.exe"

    def test_missing_process_name(self) -> None:
        """缺少 process_name 参数时返回 error。"""
        tool = MemoryAttachTool()
        result = tool.execute({})
        assert result["status"] == "error"
        assert "process_name" in result["error_message"]

    def test_process_not_found(self) -> None:
        """进程未找到时返回 error。"""
        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.attach",
            side_effect=RuntimeError("进程未找到: nonexistent.exe"),
        ):
            tool = MemoryAttachTool()
            result = tool.execute({"process_name": "nonexistent.exe"})

        assert result["status"] == "error"
        assert "进程未找到" in result["error_message"]

    def test_session_stored(self, mock_pm: MagicMock) -> None:
        """附加后会话应存储 pid -> Pymem 映射。"""
        from winreverse.engine.tools.memory_tools import _sessions

        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.attach",
            return_value=mock_pm,
        ):
            tool = MemoryAttachTool()
            tool.execute({"process_name": "notepad.exe"})

        assert 1234 in _sessions
        assert _sessions[1234] is mock_pm


class TestMemoryReadTool:
    """memory.read 工具测试。"""

    def test_read_bytes(self, mock_pm: MagicMock) -> None:
        """读取字节序列。"""
        from winreverse.engine.tools.memory_tools import _sessions

        _sessions[1234] = mock_pm
        mock_pm.read_bytes.return_value = b"\x48\x89\xe5"

        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.read_bytes",
            return_value=b"\x48\x89\xe5",
        ):
            tool = MemoryReadTool()
            result = tool.execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "length": 3,
                    "type": "bytes",
                }
            )

        assert result["status"] == "success"
        decoded = base64.b64decode(result["data"])
        assert decoded == b"\x48\x89\xe5"

    def test_read_int(self, mock_pm: MagicMock) -> None:
        """读取整数。"""
        from winreverse.engine.tools.memory_tools import _sessions

        _sessions[1234] = mock_pm

        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.read_int",
            return_value=42,
        ):
            tool = MemoryReadTool()
            result = tool.execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "type": "int",
                }
            )

        assert result["status"] == "success"
        assert result["value"] == 42

    def test_read_string(self, mock_pm: MagicMock) -> None:
        """读取字符串。"""
        from winreverse.engine.tools.memory_tools import _sessions

        _sessions[1234] = mock_pm

        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.read_string",
            return_value="hello world",
        ):
            tool = MemoryReadTool()
            result = tool.execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "type": "string",
                }
            )

        assert result["status"] == "success"
        assert result["string"] == "hello world"

    def test_default_type_is_bytes(self, mock_pm: MagicMock) -> None:
        """默认 type 为 bytes。"""
        from winreverse.engine.tools.memory_tools import _sessions

        _sessions[1234] = mock_pm

        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.read_bytes",
            return_value=b"\x00",
        ):
            tool = MemoryReadTool()
            result = tool.execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "length": 1,
                }
            )

        assert result["status"] == "success"
        assert "data" in result

    def test_session_not_found(self) -> None:
        """pid 未附加时返回 error。"""
        tool = MemoryReadTool()
        result = tool.execute({"pid": 9999, "address": 0x1000, "length": 4})
        assert result["status"] == "error"
        assert "进程未附加" in result["error_message"]

    def test_missing_pid(self) -> None:
        """缺少 pid 参数时返回 error。"""
        tool = MemoryReadTool()
        result = tool.execute({"address": 0x1000, "length": 4})
        assert result["status"] == "error"
        assert "pid" in result["error_message"]

    def test_unsupported_type(self, mock_pm: MagicMock) -> None:
        """不支持的读取类型返回 error。"""
        from winreverse.engine.tools.memory_tools import _sessions

        _sessions[1234] = mock_pm

        tool = MemoryReadTool()
        result = tool.execute(
            {
                "pid": 1234,
                "address": 0x1000,
                "type": "float",
            }
        )

        assert result["status"] == "error"
        assert "不支持的读取类型" in result["error_message"]


class TestMemoryWriteTool:
    """memory.write 工具测试。"""

    def test_write_bytes(self, mock_pm: MagicMock) -> None:
        """写入字节序列。"""
        from winreverse.engine.tools.memory_tools import _sessions

        _sessions[1234] = mock_pm
        data_b64 = base64.b64encode(b"\x90\x90").decode("ascii")

        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.write_bytes",
        ) as mock_write:
            tool = MemoryWriteTool()
            result = tool.execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "type": "bytes",
                    "data": data_b64,
                }
            )

        assert result["status"] == "success"
        assert result["written"] == 2
        mock_write.assert_called_once()

    def test_write_int(self, mock_pm: MagicMock) -> None:
        """写入整数。"""
        from winreverse.engine.tools.memory_tools import _sessions

        _sessions[1234] = mock_pm

        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.write_int",
        ) as mock_write:
            tool = MemoryWriteTool()
            result = tool.execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "type": "int",
                    "value": 42,
                }
            )

        assert result["status"] == "success"
        assert result["written"] == 4
        mock_write.assert_called_once()

    def test_write_string(self, mock_pm: MagicMock) -> None:
        """写入字符串。"""
        from winreverse.engine.tools.memory_tools import _sessions

        _sessions[1234] = mock_pm

        with patch(
            "winreverse.engine.tools.memory_tools.memory_api.write_string",
        ) as mock_write:
            tool = MemoryWriteTool()
            result = tool.execute(
                {
                    "pid": 1234,
                    "address": 0x1000,
                    "type": "string",
                    "string": "hello",
                }
            )

        assert result["status"] == "success"
        assert result["written"] == 5  # "hello" 的 UTF-8 字节数
        mock_write.assert_called_once()

    def test_session_not_found(self) -> None:
        """pid 未附加时返回 error。"""
        tool = MemoryWriteTool()
        result = tool.execute({"pid": 9999, "address": 0x1000, "type": "int", "value": 1})
        assert result["status"] == "error"
        assert "进程未附加" in result["error_message"]

    def test_missing_pid(self) -> None:
        """缺少 pid 参数时返回 error。"""
        tool = MemoryWriteTool()
        result = tool.execute({"address": 0x1000, "type": "int", "value": 1})
        assert result["status"] == "error"
        assert "pid" in result["error_message"]


class TestMemoryToolsList:
    """MEMORY_TOOLS 列表测试。"""

    def test_registered(self) -> None:
        """MEMORY_TOOLS 应包含 3 个工具。"""
        assert len(MEMORY_TOOLS) == 3
        names = [t.name for t in MEMORY_TOOLS]
        assert "memory.attach" in names
        assert "memory.read" in names
        assert "memory.write" in names
