"""测试模块：winreverse.core.memory_api

测试 pymem 薄包装层。
覆盖：
- attach 进程附加（成功 / 进程未找到 / 附加失败）
- read_int / read_bytes / read_string 读取
- write_int / write_bytes / write_string 写入
- scan_pattern 模式扫描
- list_modules 模块枚举
- 异常包装为 MemoryAccessError
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from winreverse.core import memory_api
from winreverse.core.memory_api import (
    MemoryAccessError,
    attach,
    list_modules,
    read_bytes,
    read_int,
    read_string,
    scan_pattern,
    write_bytes,
    write_int,
    write_string,
)


class TestAttach:
    """attach 进程附加测试"""

    def test_attach_success_by_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """按名附加应先经 psutil 解析 PID，再走 pymem 的 PID 附加路径。"""
        mock_pymem_cls = MagicMock()
        mock_instance = MagicMock()
        mock_pymem_cls.return_value = mock_instance
        monkeypatch.setattr(memory_api, "Pymem", mock_pymem_cls)
        monkeypatch.setattr(memory_api, "_resolve_pid_by_name", lambda name: 4242)
        result = attach("notepad.exe")
        assert result is mock_instance
        mock_pymem_cls.assert_called_once_with(4242)

    def test_attach_success_by_pid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """纯数字参数按 PID 直接附加，不触发按名解析。"""
        import psutil

        mock_pymem_cls = MagicMock()
        monkeypatch.setattr(memory_api, "Pymem", mock_pymem_cls)
        monkeypatch.setattr(psutil, "pid_exists", lambda pid: True)

        def _fail(name: str) -> int:
            raise AssertionError("PID 附加不应触发按名解析")

        monkeypatch.setattr(memory_api, "_resolve_pid_by_name", _fail)
        attach("4242")
        mock_pymem_cls.assert_called_once_with(4242)

    def test_attach_dead_pid_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """附加已退出 PID（残留句柄的僵尸 PID）应抛出 MemoryAccessError。"""
        import psutil

        monkeypatch.setattr(psutil, "pid_exists", lambda pid: False)
        with pytest.raises(MemoryAccessError, match="进程未找到"):
            attach("4242")

    def test_attach_process_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """按名解析无匹配进程应抛出 MemoryAccessError。"""
        from pymem.exception import ProcessNotFound

        def _not_found(name: str) -> int:
            raise ProcessNotFound(name)

        monkeypatch.setattr(memory_api, "_resolve_pid_by_name", _not_found)
        with pytest.raises(MemoryAccessError, match="进程未找到"):
            attach("nonexistent.exe")

    def test_attach_process_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """附加失败应抛出 MemoryAccessError。"""
        from pymem.exception import ProcessError

        mock_pymem_cls = MagicMock()
        mock_pymem_cls.side_effect = ProcessError("access denied")
        monkeypatch.setattr(memory_api, "Pymem", mock_pymem_cls)
        monkeypatch.setattr(memory_api, "_resolve_pid_by_name", lambda name: 4242)
        with pytest.raises(MemoryAccessError, match="附加进程失败"):
            attach("protected.exe")

    def test_resolve_pid_by_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_resolve_pid_by_name 大小写不敏感匹配首个同名进程。"""
        import psutil

        from winreverse.core import memory_api as api

        class FakeProc:
            def __init__(self, pid: int, name: str | None) -> None:
                self.pid = pid
                self.info = {"name": name}

        procs = [
            FakeProc(100, None),  # 访问被拒的进程，name 为 None
            FakeProc(200, "Notepad.EXE"),
            FakeProc(300, "notepad.exe"),
        ]
        monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
        assert api._resolve_pid_by_name("NOTEPAD.exe") == 200

    def test_resolve_pid_by_name_no_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """无匹配进程时抛 ProcessNotFound。"""
        import psutil
        from pymem.exception import ProcessNotFound

        from winreverse.core import memory_api as api

        monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter([]))
        with pytest.raises(ProcessNotFound):
            api._resolve_pid_by_name("ghost.exe")


class TestReadOperations:
    """读取操作测试"""

    def test_read_int_success(self) -> None:
        """read_int 应返回 Pymem.read_int 的结果。"""
        pm = MagicMock()
        pm.read_int.return_value = 42
        assert read_int(pm, 0x1000) == 42
        pm.read_int.assert_called_once_with(0x1000)

    def test_read_int_failure_wraps_to_memory_error(self) -> None:
        """read_int 失败应包装为 MemoryAccessError。"""
        pm = MagicMock()
        pm.read_int.side_effect = OSError("read failed")
        with pytest.raises(MemoryAccessError, match="read_int 失败"):
            read_int(pm, 0x1000)

    def test_read_bytes_success(self) -> None:
        """read_bytes 应返回 Pymem.read_bytes 的结果。"""
        pm = MagicMock()
        pm.read_bytes.return_value = b"\x01\x02\x03"
        result = read_bytes(pm, 0x2000, 3)
        assert result == b"\x01\x02\x03"
        pm.read_bytes.assert_called_once_with(0x2000, 3)

    def test_read_bytes_failure_wraps_to_memory_error(self) -> None:
        """read_bytes 失败应包装为 MemoryAccessError。"""
        pm = MagicMock()
        pm.read_bytes.side_effect = OSError("read failed")
        with pytest.raises(MemoryAccessError, match="read_bytes 失败"):
            read_bytes(pm, 0x2000, 10)

    def test_read_string_success(self) -> None:
        """read_string 应返回 Pymem.read_string 的结果。"""
        pm = MagicMock()
        pm.read_string.return_value = "hello"
        assert read_string(pm, 0x3000) == "hello"
        pm.read_string.assert_called_once_with(0x3000, byte=50, encoding="UTF-8")

    def test_read_string_with_custom_params(self) -> None:
        """read_string 应传递自定义参数。"""
        pm = MagicMock()
        pm.read_string.return_value = "world"
        result = read_string(pm, 0x3000, max_len=100, encoding="GBK")
        assert result == "world"
        pm.read_string.assert_called_once_with(0x3000, byte=100, encoding="GBK")

    def test_read_string_failure_wraps_to_memory_error(self) -> None:
        """read_string 失败应包装为 MemoryAccessError。"""
        pm = MagicMock()
        pm.read_string.side_effect = OSError("read failed")
        with pytest.raises(MemoryAccessError, match="read_string 失败"):
            read_string(pm, 0x3000)


class TestWriteOperations:
    """写入操作测试"""

    def test_write_int_success(self) -> None:
        """write_int 应调用 Pymem.write_int。"""
        pm = MagicMock()
        write_int(pm, 0x1000, 42)
        pm.write_int.assert_called_once_with(0x1000, 42)

    def test_write_int_failure_wraps_to_memory_error(self) -> None:
        """write_int 失败应包装为 MemoryAccessError。"""
        pm = MagicMock()
        pm.write_int.side_effect = OSError("write failed")
        with pytest.raises(MemoryAccessError, match="write_int 失败"):
            write_int(pm, 0x1000, 42)

    def test_write_bytes_success(self) -> None:
        """write_bytes 应调用 Pymem.write_bytes 并传递长度。"""
        pm = MagicMock()
        data = b"\x01\x02\x03"
        write_bytes(pm, 0x2000, data)
        pm.write_bytes.assert_called_once_with(0x2000, data, len(data))

    def test_write_bytes_failure_wraps_to_memory_error(self) -> None:
        """write_bytes 失败应包装为 MemoryAccessError。"""
        pm = MagicMock()
        pm.write_bytes.side_effect = OSError("write failed")
        with pytest.raises(MemoryAccessError, match="write_bytes 失败"):
            write_bytes(pm, 0x2000, b"\x01\x02")

    def test_write_string_success(self) -> None:
        """write_string 应调用 Pymem.write_string。"""
        pm = MagicMock()
        write_string(pm, 0x3000, "hello")
        pm.write_string.assert_called_once_with(0x3000, "hello", encoding="UTF-8")

    def test_write_string_failure_wraps_to_memory_error(self) -> None:
        """write_string 失败应包装为 MemoryAccessError。"""
        pm = MagicMock()
        pm.write_string.side_effect = OSError("write failed")
        with pytest.raises(MemoryAccessError, match="write_string 失败"):
            write_string(pm, 0x3000, "hello")


class TestScanPattern:
    """模式扫描测试"""

    def test_scan_pattern_single_match(self) -> None:
        """单结果模式应返回 int。"""
        pm = MagicMock()
        pm.pattern_scan_all.return_value = 0x400000
        result = scan_pattern(pm, "XX XX", return_multiple=False)
        assert result == 0x400000
        pm.pattern_scan_all.assert_called_once_with("XX XX", return_multiple=False)

    def test_scan_pattern_multiple_match(self) -> None:
        """多结果模式应返回 list[int]。"""
        pm = MagicMock()
        pm.pattern_scan_all.return_value = [0x1000, 0x2000, 0x3000]
        result = scan_pattern(pm, "XX XX", return_multiple=True)
        assert result == [0x1000, 0x2000, 0x3000]

    def test_scan_pattern_no_match_single_raises(self) -> None:
        """单结果模式无匹配应抛出 MemoryAccessError。"""
        pm = MagicMock()
        pm.pattern_scan_all.return_value = None
        with pytest.raises(MemoryAccessError, match="未找到匹配"):
            scan_pattern(pm, "XX XX")

    def test_scan_pattern_failure_wraps_to_memory_error(self) -> None:
        """扫描失败应包装为 MemoryAccessError。"""
        pm = MagicMock()
        pm.pattern_scan_all.side_effect = OSError("scan failed")
        with pytest.raises(MemoryAccessError, match="scan_pattern 失败"):
            scan_pattern(pm, "XX XX")


class TestListModules:
    """模块枚举测试"""

    def test_list_modules_success(self) -> None:
        """list_modules 应返回 Pymem.list_modules 的结果。"""
        pm = MagicMock()
        mock_modules = [MagicMock(name="kernel32.dll"), MagicMock(name="user32.dll")]
        pm.list_modules.return_value = mock_modules
        result = list_modules(pm)
        assert result == mock_modules

    def test_list_modules_failure_wraps_to_memory_error(self) -> None:
        """list_modules 失败应包装为 MemoryAccessError。"""
        pm = MagicMock()
        pm.list_modules.side_effect = OSError("enum failed")
        with pytest.raises(MemoryAccessError, match="list_modules 失败"):
            list_modules(pm)
