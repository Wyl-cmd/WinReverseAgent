"""被测模块: winreverse.cli 模块导入期的 _reconfigure_streams_utf8() 接线。

覆盖点: Windows --help charmap UnicodeEncodeError 修复的"导入期执行"一半——
reload 模块验证导入体真的就地调用了流重配置（helper 单元行为另见
test_cli_defects.py::TestReconfigureStreamsUtf8）；reload 产物仅作断言载体，
用例内回装旧模块对象，对同进程其余用例零残留。
"""

from __future__ import annotations

import importlib
import sys

import pytest

from winreverse import cli as cli_module


class _RecordingStream:
    """记录 reconfigure 调用参数的假流（无真实编码层）。"""

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def reconfigure(self, **kwargs: str) -> None:
        self.calls.append(kwargs)


def test_import_time_reconfigure_wiring(monkeypatch: pytest.MonkeyPatch) -> None:
    """win32 下 import winreverse.cli 必须就地重配置 stdout/stderr 为 UTF-8。

    --help 文本在回调前渲染，重配置若只定义不执行（或挪到命令回调内）
    则缺陷复现；此处锁"模块导入体触发调用"这一接线本身。
    """
    original_module = sys.modules["winreverse.cli"]
    out, err = _RecordingStream(), _RecordingStream()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    try:
        importlib.reload(cli_module)
    finally:
        # reload 生成的新模块对象仅作断言载体；回装旧对象避免给
        # 同进程后续用例换走一份命令重注册过的模块实现
        sys.modules["winreverse.cli"] = original_module
    assert out.calls == [{"encoding": "utf-8", "errors": "replace"}]
    assert err.calls == [{"encoding": "utf-8", "errors": "replace"}]


def test_wiring_restores_original_module_identity() -> None:
    """reload 用例结束后 sys.modules 中的 cli 必须仍是原始模块对象。"""
    assert sys.modules["winreverse.cli"] is cli_module
