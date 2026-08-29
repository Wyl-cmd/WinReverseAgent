"""测试模块：winreverse.core.yara_api

测试 yara-python 薄包装层。
覆盖：
- compile_source / compile_file 规则编译
- scan_file / scan_bytes 扫描
- YaraMatch dataclass 字段
- YaraCompileError / YaraScanError 异常
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.core.yara_api import (
    YaraCompileError,
    YaraMatch,
    compile_file,
    compile_source,
    scan_bytes,
    scan_file,
)

# 测试用 YARA 规则：匹配 "hello" 字符串
TEST_RULE = """
rule test_hello {
    strings:
        $a = "hello"
    condition:
        $a
}
"""

# 测试用 YARA 规则：带 tag 和 meta
TEST_RULE_WITH_META = """
rule test_tagged : malware trojan {
    meta:
        author = "test"
        severity = "high"
    strings:
        $a = "evil"
    condition:
        $a
}
"""


class TestCompileSource:
    """compile_source 规则源码编译测试"""

    def test_compile_valid_rule(self) -> None:
        """有效规则应编译成功。"""
        rules = compile_source(TEST_RULE)
        assert rules is not None

    def test_compile_invalid_rule_raises(self) -> None:
        """语法错误的规则应抛出 YaraCompileError。"""
        invalid_rule = "rule invalid { condition: $a }"  # 缺少 strings 段
        with pytest.raises(YaraCompileError, match="YARA 规则"):
            compile_source(invalid_rule)

    def test_compile_rule_with_meta(self) -> None:
        """带 meta 的规则应编译成功。"""
        rules = compile_source(TEST_RULE_WITH_META)
        assert rules is not None


class TestCompileFile:
    """compile_file 规则文件编译测试"""

    def test_compile_valid_rule_file(self, tmp_path: Path) -> None:
        """有效规则文件应编译成功。"""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text(TEST_RULE, encoding="utf-8")
        rules = compile_file(rule_file)
        assert rules is not None

    def test_compile_invalid_rule_file_raises(self, tmp_path: Path) -> None:
        """语法错误的规则文件应抛出 YaraCompileError。"""
        rule_file = tmp_path / "invalid.yar"
        rule_file.write_text("invalid rule content", encoding="utf-8")
        with pytest.raises(YaraCompileError):
            compile_file(rule_file)


class TestScanBytes:
    """scan_bytes 字节序列扫描测试"""

    def test_scan_bytes_with_match(self) -> None:
        """包含目标字符串的字节序列应命中。"""
        rules = compile_source(TEST_RULE)
        matches = scan_bytes(rules, b"hello world")
        assert len(matches) == 1
        assert matches[0].rule == "test_hello"

    def test_scan_bytes_without_match(self) -> None:
        """不包含目标字符串的字节序列应无命中。"""
        rules = compile_source(TEST_RULE)
        matches = scan_bytes(rules, b"goodbye world")
        assert len(matches) == 0

    def test_scan_bytes_returns_yara_match_instances(self) -> None:
        """scan_bytes 应返回 YaraMatch 实例。"""
        rules = compile_source(TEST_RULE)
        matches = scan_bytes(rules, b"hello")
        assert len(matches) == 1
        assert isinstance(matches[0], YaraMatch)

    def test_scan_bytes_with_meta_and_tags(self) -> None:
        """带 tag 和 meta 的规则命中时应正确返回。"""
        rules = compile_source(TEST_RULE_WITH_META)
        matches = scan_bytes(rules, b"evil payload")
        assert len(matches) == 1
        match = matches[0]
        assert match.rule == "test_tagged"
        assert "malware" in match.tags
        assert "trojan" in match.tags
        assert match.meta.get("author") == "test"
        assert match.meta.get("severity") == "high"


class TestScanFile:
    """scan_file 文件扫描测试"""

    def test_scan_file_with_match(self, tmp_path: Path) -> None:
        """包含目标字符串的文件应命中。"""
        target_file = tmp_path / "sample.txt"
        target_file.write_bytes(b"hello world")
        rules = compile_source(TEST_RULE)
        matches = scan_file(rules, target_file)
        assert len(matches) == 1
        assert matches[0].rule == "test_hello"

    def test_scan_file_without_match(self, tmp_path: Path) -> None:
        """不包含目标字符串的文件应无命中。"""
        target_file = tmp_path / "sample.txt"
        target_file.write_bytes(b"goodbye world")
        rules = compile_source(TEST_RULE)
        matches = scan_file(rules, target_file)
        assert len(matches) == 0


class TestYaraMatchDataclass:
    """YaraMatch dataclass 测试"""

    def test_yara_match_default_fields(self) -> None:
        """YaraMatch 默认字段应为空。"""
        match = YaraMatch(rule="test")
        assert match.rule == "test"
        assert match.namespace == ""
        assert match.tags == []
        assert match.meta == {}
        assert match.strings == []

    def test_yara_match_with_all_fields(self) -> None:
        """YaraMatch 应能携带全部字段。"""
        match = YaraMatch(
            rule="test",
            namespace="default",
            tags=["malware"],
            meta={"author": "test"},
            strings=[(0, "$a", b"hello")],
        )
        assert match.rule == "test"
        assert match.namespace == "default"
        assert match.tags == ["malware"]
        assert match.meta == {"author": "test"}
        assert match.strings == [(0, "$a", b"hello")]
