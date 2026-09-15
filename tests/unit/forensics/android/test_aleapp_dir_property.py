"""被测模块: winreverse.forensics.android.aleapp — AleappBridge 构造与 aleapp_dir 属性。

覆盖点: guest coverage 唯一缺口 aleapp.py:61（aleapp_dir property 原样返回注入目录），
兼锁默认构造 Path.cwd()/vendor/aleapp 约定位置与 is_available/entry_script 联动；
纯 Python 模块（仅 subprocess/sys/dataclasses/pathlib），Linux 本机可直接实跑。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.forensics.android.aleapp import AleappBridge


def test_explicit_dir_exposed_via_property(tmp_path: Path) -> None:
    """构造注入的 aleapp_dir 应经 property 原样返回，entry_script 依此拼接。"""
    bridge = AleappBridge(tmp_path / "aleapp-src")
    assert bridge.aleapp_dir == Path(tmp_path / "aleapp-src")
    assert bridge.entry_script == tmp_path / "aleapp-src" / "aleapp.py"
    assert bridge.is_available() is False


def test_default_dir_is_cwd_vendor_aleapp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """默认构造应取 Path.cwd()/vendor/aleapp（运行时下载通道约定位置）。"""
    monkeypatch.chdir(tmp_path)
    bridge = AleappBridge()
    assert bridge.aleapp_dir == tmp_path / "vendor" / "aleapp"


def test_is_available_true_when_entry_present(tmp_path: Path) -> None:
    """vendor 就位（存在 aleapp.py 入口）时 is_available 翻真。"""
    bridge = AleappBridge(tmp_path)
    (tmp_path / "aleapp.py").write_text("# aleapp entry", encoding="utf-8")
    assert bridge.is_available() is True
