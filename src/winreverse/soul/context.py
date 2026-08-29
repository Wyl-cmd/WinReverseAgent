"""winreverse.soul.context — 多层上下文管理。

从 KXNS soul/context.py 裁剪迁移，主要改动：
- 移除 `from kxns.memory.loader import ContextLayer` 依赖
- 内部定义 ContextLayer 枚举（保持原语义）

功能：
- 加载 global / user / project / local 四层 KXNS.md 上下文文件
- 支持 @[include](path) 语法递归引用外部文件
- 按 agent_type 关键词过滤相关上下文
- 构建 system prompt（基础提示 + skill 摘要 + 多层上下文）

参考：实施方案 §8.2.3
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel


class ContextLayer(str, Enum):
    """上下文层级，数值越大优先级越高（local 覆盖 project 覆盖 user 覆盖 global）。"""

    GLOBAL = "global"
    USER = "user"
    PROJECT = "project"
    LOCAL = "local"


class ContextEntry(BaseModel):
    """单条上下文条目。"""

    content: str
    layer: ContextLayer
    source: Path
    priority: int = 0

    model_config = {"arbitrary_types_allowed": True}


# 各 agent 类型对应的关键词，用于从上下文中筛选相关片段
_AGENT_TYPE_KEYWORDS: dict[str, list[str]] = {
    "pentest": ["pentest", "exploit", "vulnerability", "nmap", "metasploit", "kali"],
    "audit": ["audit", "compliance", "review", "semgrep", "bandit", "code review"],
    "reverse": ["reverse", "disassemble", "decompile", "binary", "ghidra", "ida"],
    "iot": ["iot", "firmware", "embedded", "hardware", "bluetooth", "zigbee"],
    "whitebox": ["whitebox", "source", "sast", "static analysis"],
    "coding": ["coding", "develop", "implement", "refactor", "debug"],
}


class ContextManager:
    """多层上下文管理器。

    加载顺序（按依赖关系，先主后次）：
        global (~/.winreverse/KXNS.md)
          → user (~/.winreverse/user/KXNS.md)
            → project (<work_dir>/.winreverse/KXNS.md)
              → local (<work_dir>/.winreverse/local/KXNS.md)

    构建 system prompt 时，按 priority 倒序拼接，local 优先级最高。
    """

    def __init__(self, work_dir: Path) -> None:
        self._work_dir = work_dir
        self._entries: list[ContextEntry] = []
        self._skill_catalog_summary: str = ""
        # WinReverseAgent 使用 ~/.winreverse/ 作为用户级配置目录
        self._kxns_files: dict[ContextLayer, Path] = {
            ContextLayer.GLOBAL: Path.home() / ".winreverse" / "KXNS.md",
            ContextLayer.USER: Path.home() / ".winreverse" / "user" / "KXNS.md",
            ContextLayer.PROJECT: work_dir / ".winreverse" / "KXNS.md",
            ContextLayer.LOCAL: work_dir / ".winreverse" / "local" / "KXNS.md",
        }

    def load_all(self) -> None:
        """加载全部四层上下文文件。"""
        self._entries.clear()
        for layer in ContextLayer:
            path = self._kxns_files.get(layer)
            if path is not None:
                self._load_kxns_file(layer, path)

    def _load_kxns_file(self, layer: ContextLayer, path: Path) -> None:
        if not path.exists():
            return

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return

        resolved = self._resolve_includes(raw, path.parent, set())
        self._entries.append(
            ContextEntry(
                content=resolved,
                layer=layer,
                source=path,
                priority=_layer_priority(layer),
            )
        )

    def _resolve_includes(
        self,
        content: str,
        base_path: Path,
        seen: set[Path],
    ) -> str:
        """递归解析 @[include](relative/path) 语法。"""
        include_pattern = re.compile(r"@\[include\]\((.+?)\)")

        def _replace(match: re.Match[str]) -> str:
            rel_path = match.group(1)
            full_path = (base_path / rel_path).resolve()

            if full_path in seen:
                return f"[circular include: {rel_path}]"

            if not full_path.exists():
                return f"[include not found: {rel_path}]"

            seen.add(full_path)
            try:
                included = full_path.read_text(encoding="utf-8")
                return self._resolve_includes(included, full_path.parent, seen)
            except OSError:
                return f"[error reading include: {rel_path}]"

        return include_pattern.sub(_replace, content)

    def set_skill_catalog_summary(self, summary: str) -> None:
        """设置 skill 目录摘要，会附加到 system prompt 末尾。"""
        self._skill_catalog_summary = summary.strip()

    def build_system_prompt(self, base_prompt: str) -> str:
        """构建完整 system prompt：基础提示 + skill 摘要 + 多层上下文。"""
        parts = [base_prompt]
        if self._skill_catalog_summary:
            parts.append(self._skill_catalog_summary)

        if not self._entries:
            return "\n".join(parts)

        sorted_entries = sorted(self._entries, key=lambda e: e.priority, reverse=True)

        for entry in sorted_entries:
            if entry.content.strip():
                parts.append(
                    f"\n--- {entry.layer.value} context ({entry.source.name}) ---\n"
                    f"{entry.content.strip()}"
                )

        return "\n".join(parts)

    def get_context_for_agent(self, agent_type: str) -> str:
        """按 agent 类型关键词过滤上下文。"""
        keywords = _AGENT_TYPE_KEYWORDS.get(agent_type, [])
        if not keywords:
            return ""

        relevant: list[str] = []
        for entry in self._entries:
            content_lower = entry.content.lower()
            if any(kw in content_lower for kw in keywords):
                relevant.append(entry.content.strip())

        return "\n\n".join(relevant)


def _layer_priority(layer: ContextLayer) -> int:
    """层级优先级：local > project > user > global。"""
    priorities: dict[ContextLayer, int] = {
        ContextLayer.GLOBAL: 10,
        ContextLayer.USER: 20,
        ContextLayer.PROJECT: 30,
        ContextLayer.LOCAL: 40,
    }
    return priorities.get(layer, 0)
