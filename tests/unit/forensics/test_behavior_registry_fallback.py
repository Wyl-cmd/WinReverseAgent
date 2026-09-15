"""被测模块: winreverse.forensics.behavior._default_registry_keys ImportError 回落（真机 coverage 缺 269/270）。

覆盖点: winreg 不可用时默认注册表监控键返回空列表且不抛异常（269 except /
270 return）。以 sys.modules["winreg"]=None 模拟模块缺失（plain import 语句
命中 None 即抛 ImportError，两端行为一致），非伪造模块注入。
"""

from __future__ import annotations

import sys

import pytest

from winreverse.forensics.behavior import _default_registry_keys


def test_default_registry_keys_without_winreg(monkeypatch: pytest.MonkeyPatch) -> None:
    """winreg 导入失败时返回空列表（269-270）。"""
    monkeypatch.setitem(sys.modules, "winreg", None)
    assert _default_registry_keys() == []
