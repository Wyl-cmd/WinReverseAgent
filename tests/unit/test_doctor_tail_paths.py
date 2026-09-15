"""被测模块: winreverse.doctor（_check_admin / _check_core_contracts / _check_platform）。

覆盖点（对照 coverage_guest.xml 真机缺口）: doctor:64,66 管理员权限检查的
AttributeError/OSError 回落、doctor:73 非管理员 warn、doctor:106-107 核心契约
ImportError 分支、doctor:120 非 win32 平台 warn。全部以 monkeypatch 注入确定性
输入驱动真实分支逻辑，Linux/Windows 双端行为一致，不加平台守卫。
"""

from __future__ import annotations

import ctypes
import sys

import pytest

from winreverse.doctor import (
    _check_admin,
    _check_core_contracts,
    _check_platform,
)


class _Shell32Missing:
    """ctypes.windll 替身：访问 shell32 即抛 AttributeError（异常回落分支输入）。"""

    @property
    def shell32(self) -> object:
        raise AttributeError("shell32 unavailable")


class _FakeShell32:
    def __init__(self, flag: int) -> None:
        self._flag = flag

    def IsUserAnAdmin(self) -> int:
        return self._flag


class _FakeWindll:
    def __init__(self, flag: int) -> None:
        self.shell32 = _FakeShell32(flag)


class TestCheckAdmin:
    """管理员权限检查：异常回落 / 非管理员 / 管理员三路返回。"""

    def test_shell32_unavailable_falls_back_to_warn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ctypes, "windll", _Shell32Missing(), raising=False)
        result = _check_admin()
        assert result.name == "管理员权限"
        assert result.status == "warn"
        assert "跳过" in result.message

    def test_non_admin_returns_warn_with_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ctypes, "windll", _FakeWindll(0), raising=False)
        result = _check_admin()
        assert result.status == "warn"
        assert result.message == "未以管理员身份运行"
        assert "管理员身份运行" in result.detail

    def test_admin_returns_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ctypes, "windll", _FakeWindll(1), raising=False)
        result = _check_admin()
        assert result.status == "ok"
        assert "已获取管理员权限" in result.message


class TestCheckCoreContracts:
    """核心契约模块导入失败时返回 error 并携带异常 detail。"""

    def test_import_error_reported_as_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # `from pkg import mod` 有 getattr 快路径：仅置 sys.modules[key]=None 在
        # 真模块已被先前测试导入时会绕过；先摘除父包属性强制走真实 import，
        # 再以 sys.modules[key]=None 使其确定性抛 ImportError（双端一致）。
        for pkg_name, attr in (("winreverse.engine", "bus"), ("winreverse.skill", "loader")):
            pkg = sys.modules.get(pkg_name)
            if pkg is not None:
                monkeypatch.delattr(pkg, attr, raising=False)
            monkeypatch.setitem(sys.modules, f"{pkg_name}.{attr}", None)
        result = _check_core_contracts()
        assert result.name == "核心契约模块"
        assert result.status == "error"
        assert "导入失败" in result.message
        assert result.detail  # 异常文本非空


class TestCheckPlatform:
    """平台检查：win32 → ok，其余平台 → warn 并带平台名。"""

    def test_windows_returns_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        result = _check_platform()
        assert result.status == "ok"
        assert result.message == "Windows"

    def test_non_windows_returns_warn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        result = _check_platform()
        assert result.status == "warn"
        assert "linux" in result.message
        assert "仅支持 Windows" in result.message
