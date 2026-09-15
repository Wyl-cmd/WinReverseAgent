# 被测模块：winreverse.forensics.network（TsharkBridge.version）
# 覆盖点：network.py:157 —— tshark -v 空输出 / 空白首行时抛 NetworkToolError 的守卫分支
"""TsharkBridge.version 空输出守卫测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.forensics.network import NetworkToolError, TsharkBridge


def _make_bridge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str) -> TsharkBridge:
    """构造桥接实例：tshark 可执行文件用临时哑文件代替（仅需 is_file 通过解析）。"""
    fake_tshark = tmp_path / "tshark.exe"
    fake_tshark.write_text("dummy", encoding="utf-8")
    bridge = TsharkBridge(fake_tshark)
    # _run 是子进程 I/O 边界：桩掉它以注入"tshark -v"的 stdout，被测逻辑是 version 的守卫
    monkeypatch.setattr(bridge, "_run", lambda args, *, timeout=300: stdout)
    return bridge


class TestTsharkVersionEmptyOutput:
    """tshark -v 无有效首行时 version() 必须显式报错而非返回空串/下标越界。"""

    def test_empty_stdout_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # 空字符串：splitlines() 为空列表，走 not lines 分支
        bridge = _make_bridge(tmp_path, monkeypatch, "")
        with pytest.raises(NetworkToolError, match="无输出"):
            bridge.version()

    def test_blank_first_line_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # 首行全空白：not lines 为假，但 lines[0].strip() 为空，同样必须报错
        bridge = _make_bridge(tmp_path, monkeypatch, "   \nTshark 4.2.3\n")
        with pytest.raises(NetworkToolError, match="无输出"):
            bridge.version()

    def test_valid_first_line_returns_stripped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 对照组：有效首行原样返回（strip 后），确认守卫边界恰好落在"空/空白首行"
        bridge = _make_bridge(tmp_path, monkeypatch, "Tshark (Wireshark) 4.2.3\nsecond\n")
        assert bridge.version() == "Tshark (Wireshark) 4.2.3"
