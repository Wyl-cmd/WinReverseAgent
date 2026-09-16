"""覆盖 winreverse.soul.agent_spec.load_agent_spec 的字段解析分支。

覆盖点：缺 name 报错、tools→allowed_tools 字段别名、
非列表 allowed_tools 回退空元组、{agent: ...} 包裹结构正向加载。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.soul.agent_spec import AgentSpecError, ToolStrategy, load_agent_spec


class TestLoadAgentSpecFieldParsing:
    def test_missing_name_raises(self, tmp_path: Path) -> None:
        """缺少 name 字段时报 AgentSpecError。"""
        spec = tmp_path / "noname.yaml"
        spec.write_text("description: no name here\n", encoding="utf-8")
        with pytest.raises(AgentSpecError, match="'name'"):
            load_agent_spec(spec)

    def test_tools_alias_maps_to_allowed_tools(self, tmp_path: Path) -> None:
        """旧字段名 tools 兼容映射为 allowed_tools。"""
        spec = tmp_path / "alias.yaml"
        spec.write_text(
            "name: alias-agent\ndescription: d\ntool_strategy: allowlist\n"
            "tools:\n  - read_mem\n  - scan_yara\n",
            encoding="utf-8",
        )
        type_def = load_agent_spec(spec)
        assert type_def.allowed_tools == ("read_mem", "scan_yara")
        assert type_def.tool_strategy is ToolStrategy.ALLOWLIST

    def test_allowed_tools_non_list_yields_empty_tuple(self, tmp_path: Path) -> None:
        """allowed_tools 为标量（非列表）时回退为空元组。"""
        spec = tmp_path / "scalar.yaml"
        spec.write_text(
            "name: scalar-agent\ndescription: d\nallowed_tools: read_mem\n",
            encoding="utf-8",
        )
        assert load_agent_spec(spec).allowed_tools == ()

    def test_agent_wrapped_mapping_is_loaded(self, tmp_path: Path) -> None:
        """顶层 {agent: {...}} 包裹结构的正向加载与字段映射。"""
        spec = tmp_path / "wrapped.yaml"
        spec.write_text(
            "agent:\n  name: wrapped-agent\n  description: d\n"
            "  when_to_use: use when x\n  model: gpt-4o\n"
            "  supports_background: false\n",
            encoding="utf-8",
        )
        type_def = load_agent_spec(spec)
        assert type_def.name == "wrapped-agent"
        assert type_def.when_to_use == "use when x"
        assert type_def.default_model == "gpt-4o"
        assert type_def.supports_background is False
