"""测试模块：winreverse.soul.agent_spec

覆盖 AgentTypeDefinition、load_agent_spec、render_system_prompt、LaborMarket。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from winreverse.soul.agent_spec import (
    AgentSpecError,
    AgentTypeDefinition,
    LaborMarket,
    ToolStrategy,
    load_agent_spec,
    render_system_prompt,
)

# =============================================================================
# ToolStrategy 枚举测试
# =============================================================================


class TestToolStrategy:
    """ToolStrategy 枚举测试。"""

    def test_allowlist_value(self) -> None:
        """ALLOWLIST 值为 'allowlist'。"""
        assert ToolStrategy.ALLOWLIST.value == "allowlist"

    def test_inherit_value(self) -> None:
        """INHERIT 值为 'inherit'。"""
        assert ToolStrategy.INHERIT.value == "inherit"

    def test_from_string(self) -> None:
        """从字符串构造枚举。"""
        assert ToolStrategy("allowlist") is ToolStrategy.ALLOWLIST
        assert ToolStrategy("inherit") is ToolStrategy.INHERIT


# =============================================================================
# AgentTypeDefinition 数据类测试
# =============================================================================


class TestAgentTypeDefinition:
    """AgentTypeDefinition 数据类测试。"""

    def test_create_minimal(self) -> None:
        """创建最小化实例（仅必填字段）。"""
        type_def = AgentTypeDefinition(name="test", description="测试类型")
        assert type_def.name == "test"
        assert type_def.description == "测试类型"
        assert type_def.system_prompt_template == ""
        assert type_def.tool_strategy == ToolStrategy.INHERIT
        assert type_def.allowed_tools == ()
        assert type_def.default_model is None
        assert type_def.supports_background is True

    def test_create_full(self) -> None:
        """创建完整实例。"""
        type_def = AgentTypeDefinition(
            name="reverse",
            description="逆向分析 agent",
            system_prompt_template="你是逆向专家",
            tool_strategy=ToolStrategy.ALLOWLIST,
            when_to_use="分析二进制文件时",
            allowed_tools=("pe.parse", "pe.imports"),
            default_model="gpt-4",
            supports_background=False,
        )
        assert type_def.system_prompt_template == "你是逆向专家"
        assert type_def.tool_strategy == ToolStrategy.ALLOWLIST
        assert type_def.allowed_tools == ("pe.parse", "pe.imports")
        assert type_def.default_model == "gpt-4"
        assert type_def.supports_background is False

    def test_is_frozen(self) -> None:
        """frozen=True，不可变。"""
        type_def = AgentTypeDefinition(name="test", description="")
        with pytest.raises(Exception):  # noqa: B017
            type_def.name = "modified"  # type: ignore[misc]


# =============================================================================
# load_agent_spec 测试
# =============================================================================


class TestLoadAgentSpec:
    """load_agent_spec 函数测试。"""

    def test_load_valid_spec(self, tmp_path: Path) -> None:
        """加载合法的 YAML 规格。"""
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text(
            """
agent:
  name: reverse
  description: 逆向分析
  system_prompt: 你是逆向专家
  tool_strategy: allowlist
  allowed_tools:
    - pe.parse
    - pe.imports
  model: gpt-4
  when_to_use: 分析二进制时
""",
            encoding="utf-8",
        )

        type_def = load_agent_spec(spec_file)
        assert type_def.name == "reverse"
        assert type_def.description == "逆向分析"
        assert type_def.system_prompt_template == "你是逆向专家"
        assert type_def.tool_strategy == ToolStrategy.ALLOWLIST
        assert type_def.allowed_tools == ("pe.parse", "pe.imports")
        assert type_def.default_model == "gpt-4"

    def test_load_minimal_spec(self, tmp_path: Path) -> None:
        """加载仅必填字段的规格。"""
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text("name: simple\ndescription: 简单 agent", encoding="utf-8")

        type_def = load_agent_spec(spec_file)
        assert type_def.name == "simple"
        assert type_def.description == "简单 agent"
        assert type_def.tool_strategy == ToolStrategy.INHERIT

    def test_load_with_system_prompt_path(self, tmp_path: Path) -> None:
        """通过 system_prompt_path 引用外部提示文件。"""
        prompt_file = tmp_path / "prompt.txt"
        prompt_file.write_text("外部提示内容", encoding="utf-8")
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text(
            """
name: with_path
description: 引用外部提示
system_prompt_path: prompt.txt
""",
            encoding="utf-8",
        )

        type_def = load_agent_spec(spec_file)
        assert type_def.system_prompt_template == "外部提示内容"

    def test_load_with_tools_alias(self, tmp_path: Path) -> None:
        """tools 字段是 allowed_tools 的别名。"""
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text(
            """
name: alias_test
description: 测试 tools 别名
tools:
  - tool1
  - tool2
""",
            encoding="utf-8",
        )

        type_def = load_agent_spec(spec_file)
        assert type_def.allowed_tools == ("tool1", "tool2")

    def test_load_invalid_strategy_falls_back(self, tmp_path: Path) -> None:
        """无效的 tool_strategy 回退为 INHERIT。"""
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text(
            "name: bad_strategy\ndescription: test\ntool_strategy: unknown",
            encoding="utf-8",
        )

        type_def = load_agent_spec(spec_file)
        assert type_def.tool_strategy == ToolStrategy.INHERIT

    def test_load_missing_file_raises(self, tmp_path: Path) -> None:
        """文件不存在时抛出 AgentSpecError。"""
        with pytest.raises(AgentSpecError, match="not found"):
            load_agent_spec(tmp_path / "nonexistent.yaml")

    def test_load_directory_not_file_raises(self, tmp_path: Path) -> None:
        """传入目录时抛出 AgentSpecError。"""
        with pytest.raises(AgentSpecError, match="not a file"):
            load_agent_spec(tmp_path)

    def test_load_missing_name_raises(self, tmp_path: Path) -> None:
        """缺少 name 字段时抛出 AgentSpecError。"""
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text("description: no name", encoding="utf-8")

        with pytest.raises(AgentSpecError, match="name"):
            load_agent_spec(spec_file)

    def test_load_invalid_yaml_raises(self, tmp_path: Path) -> None:
        """YAML 语法错误时抛出 AgentSpecError。"""
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text("name: [unclosed", encoding="utf-8")

        with pytest.raises(AgentSpecError, match="Invalid YAML"):
            load_agent_spec(spec_file)

    def test_load_non_mapping_yaml_raises(self, tmp_path: Path) -> None:
        """YAML 内容非映射类型时抛出 AgentSpecError。"""
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text("- list\n- not\n- mapping", encoding="utf-8")

        with pytest.raises(AgentSpecError, match="YAML mapping"):
            load_agent_spec(spec_file)


# =============================================================================
# render_system_prompt 测试
# =============================================================================


class TestRenderSystemPrompt:
    """render_system_prompt 函数测试。"""

    def test_render_without_args(self) -> None:
        """无参数时直接返回模板。"""
        template = "你是助手"
        result = render_system_prompt(template)
        assert result == "你是助手"

    def test_render_with_empty_args(self) -> None:
        """空参数字典时直接返回模板。"""
        template = "你是助手"
        result = render_system_prompt(template, {})
        assert result == "你是助手"

    def test_render_with_args_jinja2(self) -> None:
        """有参数时使用 jinja2 渲染（若已安装）。"""
        try:
            import jinja2  # noqa: F401
        except ImportError:
            pytest.skip("jinja2 not installed")

        template = "你好，{{ name }}！"
        result = render_system_prompt(template, {"name": "用户"})
        assert "用户" in result

    def test_render_fallback_replace(self) -> None:
        """jinja2 不可用时退化为字符串替换。

        fallback 替换格式为 {{key}}（无空格），与 jinja2 的 {{ key }} 不同。
        """
        # 模拟 jinja2 不可用：直接测试替换逻辑
        template = "你好，{{name}}！"
        # 通过 monkeypatch jinja2 导入失败
        import sys

        original_jinja2 = sys.modules.get("jinja2")
        sys.modules["jinja2"] = None  # type: ignore[assignment]
        try:
            result = render_system_prompt(template, {"name": "用户"})
            assert "用户" in result
        finally:
            if original_jinja2 is not None:
                sys.modules["jinja2"] = original_jinja2
            else:
                sys.modules.pop("jinja2", None)


# =============================================================================
# LaborMarket 测试
# =============================================================================


class TestLaborMarket:
    """LaborMarket 注册中心测试。"""

    def test_register_and_get(self) -> None:
        """注册后可按名查询。"""
        market = LaborMarket()
        type_def = AgentTypeDefinition(name="test", description="测试")
        market.register(type_def)

        assert market.get("test") is type_def

    def test_get_unknown_returns_none(self) -> None:
        """查询未注册类型返回 None。"""
        market = LaborMarket()
        assert market.get("unknown") is None

    def test_require_unknown_raises(self) -> None:
        """require 未注册类型抛出 AgentSpecError。"""
        market = LaborMarket()
        with pytest.raises(AgentSpecError, match="Unknown agent type"):
            market.require("unknown")

    def test_require_known_returns_type(self) -> None:
        """require 已注册类型返回定义。"""
        market = LaborMarket()
        type_def = AgentTypeDefinition(name="test", description="")
        market.register(type_def)

        assert market.require("test") is type_def

    def test_list_types_empty(self) -> None:
        """空市场列表为空。"""
        market = LaborMarket()
        assert market.list_types() == []

    def test_list_types_returns_all(self) -> None:
        """list_types 返回所有已注册类型。"""
        market = LaborMarket()
        market.register(AgentTypeDefinition(name="a", description=""))
        market.register(AgentTypeDefinition(name="b", description=""))

        types = market.list_types()
        assert len(types) == 2
        names = {t.name for t in types}
        assert names == {"a", "b"}

    def test_register_overrides_same_name(self) -> None:
        """重复注册同名类型会覆盖。"""
        market = LaborMarket()
        market.register(AgentTypeDefinition(name="test", description="v1"))
        market.register(AgentTypeDefinition(name="test", description="v2"))

        assert market.get("test").description == "v2"

    def test_load_spec_from_file(self, tmp_path: Path) -> None:
        """load_spec 从 YAML 文件加载并注册。"""
        spec_file = tmp_path / "agent.yaml"
        spec_file.write_text("name: loaded\ndescription: 从文件加载", encoding="utf-8")

        market = LaborMarket()
        type_def = market.load_spec(spec_file)

        assert type_def.name == "loaded"
        assert market.get("loaded") is type_def

    def test_load_directory(self, tmp_path: Path) -> None:
        """load_directory 批量加载目录。"""
        (tmp_path / "a.yaml").write_text("name: a\ndescription: agent A", encoding="utf-8")
        (tmp_path / "b.yaml").write_text("name: b\ndescription: agent B", encoding="utf-8")
        (tmp_path / "c.yml").write_text("name: c\ndescription: agent C", encoding="utf-8")

        market = LaborMarket()
        loaded = market.load_directory(tmp_path)

        assert len(loaded) == 3
        assert market.get("a") is not None
        assert market.get("b") is not None
        assert market.get("c") is not None

    def test_load_directory_nonexistent_returns_empty(self, tmp_path: Path) -> None:
        """加载不存在的目录返回空列表。"""
        market = LaborMarket()
        loaded = market.load_directory(tmp_path / "nonexistent")
        assert loaded == []

    def test_load_directory_skips_invalid_files(self, tmp_path: Path) -> None:
        """加载目录时跳过无效文件。"""
        (tmp_path / "valid.yaml").write_text("name: valid\ndescription: ok", encoding="utf-8")
        (tmp_path / "invalid.yaml").write_text("description: no name", encoding="utf-8")

        market = LaborMarket()
        loaded = market.load_directory(tmp_path)

        assert len(loaded) == 1
        assert market.get("valid") is not None
        assert market.get("invalid") is None
