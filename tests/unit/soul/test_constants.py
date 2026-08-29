"""测试模块：winreverse.soul.constants

验证常量定义的正确性。
"""

from __future__ import annotations

from winreverse.soul.constants import SECURITY_KEYWORDS


class TestSecurityKeywords:
    """SECURITY_KEYWORDS 常量测试。"""

    def test_is_tuple(self) -> None:
        """SECURITY_KEYWORDS 是 tuple 类型。"""
        assert isinstance(SECURITY_KEYWORDS, tuple)

    def test_contains_expected_keywords(self) -> None:
        """包含核心安全关键词。"""
        expected = {"vulnerability", "cve", "cvss", "exploit", "finding", "evidence"}
        assert expected.issubset(set(SECURITY_KEYWORDS))

    def test_all_elements_are_str(self) -> None:
        """所有元素均为字符串。"""
        assert all(isinstance(kw, str) for kw in SECURITY_KEYWORDS)

    def test_all_elements_non_empty(self) -> None:
        """所有元素均非空。"""
        assert all(len(kw) > 0 for kw in SECURITY_KEYWORDS)
