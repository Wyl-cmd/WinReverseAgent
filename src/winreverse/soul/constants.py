"""winreverse.soul.constants — Soul 引擎常量。

从 KXNS soul/constants.py 迁移，保持独立无依赖。
"""

from __future__ import annotations

# 安全相关关键词，用于上下文过滤与 agent 类型识别
SECURITY_KEYWORDS: tuple[str, ...] = (
    "vulnerability",
    "cve",
    "cvss",
    "exploit",
    "finding",
    "evidence",
)
