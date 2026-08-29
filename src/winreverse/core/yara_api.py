"""winreverse.core.yara_api — yara-python 薄包装层。

仅暴露业务语义 API，隔离 yara-python 版本变更对上层调用方的影响。

封装的 yara-python 能力：
- 规则编译（compile_source / compile_file）
- 文件扫描（scan_file）
- 字节序列扫描（scan_bytes）

返回 YaraMatch dataclass，避免上层直接依赖 yara.Match 类型。

参考：实施方案 §4.2
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara


@dataclass(frozen=True)
class YaraMatch:
    """YARA 匹配结果数据类。

    封装 yara.Match 的核心字段，避免上层直接依赖 yara-python 类型。

    Attributes:
        rule: 命中的规则名
        namespace: 规则所属命名空间
        tags: 规则标签列表
        meta: 规则元数据字典
        strings: 命中的字符串列表（每项格式依 yara-python 版本可能不同）
    """

    rule: str
    namespace: str = ""
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[Any] = field(default_factory=list)


class YaraCompileError(ValueError):
    """YARA 规则编译失败（语法错误）。"""


class YaraScanError(RuntimeError):
    """YARA 扫描失败（文件不存在 / 权限不足等）。"""


def compile_source(rule_text: str) -> Any:
    """编译 YARA 规则源码。

    Args:
        rule_text: YARA 规则源码字符串

    Returns:
        yara.Rules 编译后的规则对象

    Raises:
        YaraCompileError: 规则语法错误
    """
    try:
        return yara.compile(source=rule_text)
    except yara.SyntaxError as e:
        raise YaraCompileError(f"YARA 规则语法错误: {e}") from e
    except yara.Error as e:
        raise YaraCompileError(f"YARA 规则编译失败: {e}") from e


def compile_file(file_path: str | Path) -> Any:
    """编译 YARA 规则文件。

    Args:
        file_path: YARA 规则文件路径（.yar / .yara）

    Returns:
        yara.Rules 编译后的规则对象

    Raises:
        YaraCompileError: 规则语法错误
        OSError: 文件读取失败
    """
    try:
        return yara.compile(filepath=str(file_path))
    except yara.SyntaxError as e:
        raise YaraCompileError(f"YARA 规则语法错误: {e}") from e
    except yara.Error as e:
        raise YaraCompileError(f"YARA 规则编译失败: {e}") from e


def scan_file(rules: Any, file_path: str | Path) -> list[YaraMatch]:
    """用编译后的规则扫描文件。

    Args:
        rules: yara.compile() 返回的规则对象
        file_path: 待扫描文件路径

    Returns:
        YaraMatch 列表（空列表表示无命中）

    Raises:
        YaraScanError: 扫描失败
    """
    try:
        matches = rules.match(filepath=str(file_path))
    except yara.Error as e:
        raise YaraScanError(f"YARA 扫描失败: {file_path}: {e}") from e
    return [_to_match(m) for m in matches]


def scan_bytes(rules: Any, data: bytes) -> list[YaraMatch]:
    """用编译后的规则扫描字节序列。

    Args:
        rules: yara.compile() 返回的规则对象
        data: 待扫描字节序列

    Returns:
        YaraMatch 列表（空列表表示无命中）

    Raises:
        YaraScanError: 扫描失败
    """
    try:
        matches = rules.match(data=data)
    except yara.Error as e:
        raise YaraScanError(f"YARA 扫描失败: {e}") from e
    return [_to_match(m) for m in matches]


def _to_match(m: Any) -> YaraMatch:
    """将 yara.Match 转换为 YaraMatch dataclass。

    Args:
        m: yara.Match 实例

    Returns:
        YaraMatch 数据类实例
    """
    return YaraMatch(
        rule=str(m.rule),
        namespace=str(getattr(m, "namespace", "")),
        tags=list(m.tags) if m.tags else [],
        meta=dict(m.meta) if m.meta else {},
        strings=list(m.strings) if m.strings else [],
    )
