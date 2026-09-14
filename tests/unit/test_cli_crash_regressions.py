"""被测模块: winreverse.cli（Windows 编码崩溃回归）。

覆盖点: _reconfigure_streams_utf8 对 charmap（cp1252）stdout/stderr 的重配置、
非 win32 平台 no-op、无 reconfigure 属性流容错。
list-skills 惰性初始化崩溃回归拆至 test_cli_list_skills_regression.py
（其 winreverse.app 导入链 Linux 报 collection error，基线接受态）。
"""

from __future__ import annotations

import io
import sys

import pytest

from winreverse.cli import _reconfigure_streams_utf8


class TestReconfigureStreamsUtf8:
    """--help 在 Windows（charmap 管道）UnicodeEncodeError 崩溃的回归锁。"""

    def _patch_charmap_streams(self, monkeypatch: pytest.MonkeyPatch):
        out_buf, err_buf = io.BytesIO(), io.BytesIO()
        out = io.TextIOWrapper(out_buf, encoding="cp1252")
        err = io.TextIOWrapper(err_buf, encoding="cp1252")
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        return out, out_buf, err, err_buf

    def test_charmap_stream_can_print_chinese_help(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """复现前提：cp1252 编码中文必崩；重配置后同一流可安全写出 UTF-8。"""
        crash_stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        with pytest.raises(UnicodeEncodeError):
            crash_stream.write("WinReverseAgent — 中文帮助")
        out, out_buf, err, err_buf = self._patch_charmap_streams(monkeypatch)
        _reconfigure_streams_utf8()
        text = "WinReverseAgent — Windows 原生逆向工程 AI Agent"
        out.write(text)
        err.write(text)
        out.flush()
        err.flush()
        assert out_buf.getvalue().decode("utf-8") == text
        assert err_buf.getvalue().decode("utf-8") == text

    def test_non_win32_is_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """非 win32 平台不做任何重配置。"""
        calls: list[dict] = []

        class _Recording:
            def reconfigure(self, **kwargs):
                calls.append(kwargs)

        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(sys, "stdout", _Recording())
        monkeypatch.setattr(sys, "stderr", _Recording())
        _reconfigure_streams_utf8()
        assert calls == []

    def test_streams_without_reconfigure_are_tolerated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """stdout/stderr 为 None 或缺 reconfigure 属性时不抛错。"""
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(sys, "stdout", None)
        monkeypatch.setattr(sys, "stderr", object())
        _reconfigure_streams_utf8()
