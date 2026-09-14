"""测试模块：winreverse.core.yara_api 错误路径补充（generic yara.Error 兜底分支）。

覆盖：compile_source / compile_file 对非 SyntaxError 的 yara.Error → YaraCompileError；
scan_file / scan_bytes 对 yara.Error → YaraScanError（含真实不存在文件）；YaraMatch 冻结不可变。
`yara` 依赖缺失 → Linux 下如实报 collection error（基线接受态），待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest
import yara

from winreverse.core.yara_api import (
    YaraCompileError,
    YaraMatch,
    YaraScanError,
    compile_file,
    compile_source,
    scan_bytes,
    scan_file,
)

TEST_RULE = """
rule test_hello {
    strings:
        $a = "hello"
    condition:
        $a
}
"""


class _BoomRules:
    """match 必抛 yara.Error 的规则替身（被测逻辑是包装层的异常翻译，非 yara 本身）。"""

    def match(self, **_kwargs: Any) -> Any:
        raise yara.Error("callback aborted")


class TestCompileGenericErrorBranch:
    """compile_* 对非 SyntaxError 的 yara.Error 应译为 YaraCompileError（"编译失败"分支）。"""

    def test_compile_source_generic_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(**_kwargs: Any) -> Any:
            raise yara.Error("too many rules")

        monkeypatch.setattr("winreverse.core.yara_api.yara.compile", _boom)
        with pytest.raises(YaraCompileError, match=r"YARA 规则编译失败.*too many rules") as ei:
            compile_source("rule r { condition: true }")
        assert isinstance(ei.value.__cause__, yara.Error)

    def test_compile_file_generic_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(**_kwargs: Any) -> Any:
            raise yara.Error("corrupted file")

        monkeypatch.setattr("winreverse.core.yara_api.yara.compile", _boom)
        with pytest.raises(YaraCompileError, match=r"YARA 规则编译失败.*corrupted file"):
            compile_file(tmp_path / "rule.yar")


class TestScanErrorBranch:
    """scan_* 对 yara.Error 应译为 YaraScanError 并保留定位信息。"""

    def test_scan_file_missing_file_raises_scan_error(self, tmp_path: Path) -> None:
        """扫描不存在文件：真实 yara.Error（could not open file）→ YaraScanError 带路径。"""
        rules = compile_source(TEST_RULE)
        missing = tmp_path / "ghost.bin"
        with pytest.raises(YaraScanError, match=r"ghost.bin") as ei:
            scan_file(rules, missing)
        assert isinstance(ei.value.__cause__, yara.Error)

    def test_scan_bytes_generic_error(self) -> None:
        with pytest.raises(YaraScanError, match="callback aborted"):
            scan_bytes(_BoomRules(), b"payload")


class TestYaraMatchFrozen:
    """YaraMatch 为 frozen dataclass：字段赋值应被拒绝（取证结果不可篡改）。"""

    def test_frozen_rejects_mutation(self) -> None:
        match = YaraMatch(rule="test_hello", meta={"author": "t"})
        with pytest.raises(dataclasses.FrozenInstanceError):
            match.rule = "forged"  # type: ignore[misc]
