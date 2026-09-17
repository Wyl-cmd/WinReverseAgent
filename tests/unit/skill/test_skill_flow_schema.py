"""测试模块：skills/*.yaml 的 execution_flow 参数名 ↔ 工具 schema（P0-2 回归门禁）。

背景（2026-09-16 实测）：
    ``skills/sample_strings_and_config_extraction.yaml`` 给 ``memory.strings`` /
    ``memory.iocs`` 传 ``file_path``，而两个工具要的参数名是 ``path`` →
    预置执行流两步全部 ``KeyError: 缺少必需参数: path``，字符串类技能"跑得动、没数据"。

本测试把这类"技能参数名 ≠ 工具要求"钉在测试期（而不是等运行时 KeyError）：

1. 每个 ``action`` 必须是已注册工具；
2. ``args`` 里的每个键必须存在于该工具的参数 schema；
3. 每个 ``{{占位符}}`` 必须能解析（技能声明参数 / 上游工具输出可接线键）；
4. 工具的所有**必填**参数必须由 ``args`` 提供。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from winreverse.engine.bus import ToolRegistry
from winreverse.engine.tools import list_tool_names, register_all_tools
from winreverse.skill.loader import YamlSkillLoader
from winreverse.soul.tool_schema import (
    WIREABLE_OUTPUT_KEYS,
    ToolParameterSpec,
    tool_parameters,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SKILLS_DIR = PROJECT_ROOT / "skills"

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def _skill_files() -> list[Path]:
    """skills/*.yaml 列表（目录缺失时返回空列表，交由测试断言）。"""
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(list(SKILLS_DIR.glob("*.yaml")) + list(SKILLS_DIR.glob("*.yml")))


def _tool_schemas() -> dict[str, list[ToolParameterSpec]]:
    """全部工具的 {工具名: 参数 schema}。"""
    registry = ToolRegistry()
    register_all_tools(registry)
    return {name: tool_parameters(registry.get(name)) for name in list_tool_names()}


def test_repo_skills_are_present() -> None:
    """skills/ 目录与 YAML 技能存在（防止校验被空目录静默跳过）。"""
    assert SKILLS_DIR.is_dir(), f"skills 目录不存在: {SKILLS_DIR}"
    assert len(_skill_files()) >= 12, f"技能数量异常: {len(_skill_files())}"


@pytest.mark.parametrize("skill_path", _skill_files(), ids=lambda p: p.name)
def test_skill_flow_args_match_tool_schema(skill_path: Path) -> None:
    """技能预置流的参数名/必填项/占位符必须与工具 schema 一致。"""
    schemas = _tool_schemas()
    skill = YamlSkillLoader().load(skill_path)
    declared = {param.name for param in skill.parameters}
    wireable = set(WIREABLE_OUTPUT_KEYS)

    problems: list[str] = []
    for index, step in enumerate(skill.execution_flow):
        action = str(step.get("action", ""))
        raw_args = step.get("args") or {}
        where = f"{skill_path.name} execution_flow[{index}] {action}"

        if action not in schemas:
            problems.append(f"{where}: 工具未注册")
            continue
        if not isinstance(raw_args, dict):
            problems.append(f"{where}: args 必须是 mapping，当前 {type(raw_args).__name__}")
            continue

        schema = {param.name: param for param in schemas[action]}
        for key, value in raw_args.items():
            if key not in schema:
                problems.append(
                    f"{where}: 参数名 {key!r} 不在工具 schema （可用: {sorted(schema)}）"
                )
            for placeholder in _PLACEHOLDER_RE.findall(str(value)):
                if placeholder not in declared and placeholder not in wireable:
                    problems.append(
                        f"{where}: 占位符 {{{{{placeholder}}}}} 无法解析"
                        f"（技能参数: {sorted(declared)}；可接线键: {sorted(wireable)}）"
                    )
        missing = [
            name for name, param in schema.items() if param.required and name not in raw_args
        ]
        if missing:
            problems.append(f"{where}: 缺必填参数 {missing}")

    assert not problems, "技能预置流与工具 schema 不一致：\n" + "\n".join(problems)


def test_wireable_keys_are_produced_by_flow_tools() -> None:
    """可接线键必须真的是"某个工具会输出的键"（防止白名单腐烂）。"""
    schemas = _tool_schemas()
    # 明确约定来源（工具名 → 它输出里用于接线的键）
    expected_sources = {
        "memory.attach": "pid",
        "memory.dump": "output_dir",
        "memory.dump_minidump": "output_path",
        "net.live_capture": "pcap",
    }
    for tool_name, key in expected_sources.items():
        assert tool_name in schemas, f"接线来源工具缺失: {tool_name}"
        assert key in WIREABLE_OUTPUT_KEYS, f"{key!r} 不在可接线键白名单"
