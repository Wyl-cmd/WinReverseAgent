"""测试模块：soul/tool_schema.py 的内部判据与边界（P0-1 覆盖率回补）。

`tests/unit/soul/test_toolset_parameters.py` 走的是"装配全部真实工具"的端到端路径，
覆盖不到本模块的类型推断/归一化/容错分支；本文件用最小人造工具类直接打点：

- 默认值/字面量类型推断（bool/int/float/str/list/dict/负数常量/非字面量）
- 读取方式 → 必填性判定（require / subscript / get）
- docstring 参数描述提取（`# 注释` 与 `<占位>` 两种写法）
- 源码不可得时的容错（返回空列表，不抛）
- 显式声明的归一化（ToolParameterSpec / dict / tuple / 非法项）
- 非法声明整体回落到源码推断（`tool_parameters` 的 fallthrough 分支）
"""

from __future__ import annotations

import ast
from typing import Any, ClassVar

from winreverse.engine.bus import ToolParameterSpec
from winreverse.soul import tool_schema
from winreverse.soul.tool_schema import (
    WIREABLE_OUTPUT_KEYS,
    _is_required,
    _json_type_of_default,
    _literal_type_of,
    _match_param_read,
    _normalise,
    flow_placeholder_sources,
    infer_parameters_from_source,
    tool_parameters,
)


class _UnusualDefault:
    """非 bool/int/float/str/list/dict 的默认值（命中类型推断的兜底 return "string"）。"""


def _parse_expr(source: str) -> ast.expr:
    return ast.parse(source, mode="eval").body


class TestJsonTypeOfDefault:
    """默认值 → JSON Schema 类型串。"""

    def test_scalar_and_container_defaults(self) -> None:
        assert _json_type_of_default(True) == "boolean"
        assert _json_type_of_default(7) == "integer"
        assert _json_type_of_default(1.5) == "number"
        assert _json_type_of_default("x") == "string"
        assert _json_type_of_default([1, 2]) == "array"
        assert _json_type_of_default((1, 2)) == "array"
        assert _json_type_of_default({"a": 1}) == "object"

    def test_unknown_default_falls_back_to_string(self) -> None:
        """bool 必须先于 int 判定；未知类型兜底 string。"""
        assert _json_type_of_default(False) == "boolean"
        assert _json_type_of_default(_UnusualDefault()) == "string"


class TestLiteralTypeOf:
    """AST 字面量节点 → JSON Schema 类型串。"""

    def test_none_node_and_none_constant(self) -> None:
        assert _literal_type_of(None) is None
        assert _literal_type_of(_parse_expr("None")) is None

    def test_constant_list_dict(self) -> None:
        assert _literal_type_of(_parse_expr("'s'")) == "string"
        assert _literal_type_of(_parse_expr("[1]")) == "array"
        assert _literal_type_of(_parse_expr("{'k': 1}")) == "object"

    def test_negative_numbers(self) -> None:
        """负数常量：-1 → integer（UnaryOp 分支）。"""
        assert _literal_type_of(_parse_expr("-1")) == "integer"
        assert _literal_type_of(_parse_expr("-1.5")) == "number"

    def test_non_literal_returns_none(self) -> None:
        assert _literal_type_of(_parse_expr("some_name")) is None


class TestMatchParamRead:
    """参数读取点识别（节点级）。"""

    def test_get_without_default(self) -> None:
        matched = _match_param_read(_parse_expr("input_data.get('k')"))
        assert matched == ("k", "get", None)

    def test_get_with_default_node(self) -> None:
        matched = _match_param_read(_parse_expr("input_data.get('k', 3)"))
        assert matched is not None
        assert matched[0] == "k" and matched[1] == "get" and matched[2] is not None

    def test_unrelated_expression_returns_none(self) -> None:
        assert _match_param_read(_parse_expr("other.get('k')")) is None
        assert _match_param_read(_parse_expr("input_data.get(dynamic)")) is None


class TestIsRequired:
    """必填性判定：require 优先，其次 get（选填），最后 subscript。"""

    def test_subscript_only_is_required(self) -> None:
        assert _is_required({"subscript"}) is True

    def test_get_wins_over_subscript(self) -> None:
        assert _is_required({"subscript", "get"}) is False

    def test_require_wins_over_get(self) -> None:
        assert _is_required({"require", "get"}) is True


class TestDocstringDescriptions:
    """docstring 参数描述提取。"""

    def test_placeholder_value_becomes_description(self) -> None:
        """无 `#` 注释时，`<说明>` 形式的占位值直接作为描述。"""

        class _Tool:
            """工具说明。

            输入:
                "file_path": <PE 文件路径>
            """

        specs = infer_parameters_from_source(_Tool)
        assert specs == []

        descriptions = tool_schema._docstring_descriptions(_Tool)
        assert descriptions["file_path"] == "PE 文件路径"

    def test_comment_wins_and_duplicates_are_skipped(self) -> None:
        class _Tool:
            """工具说明。

            输入:
                "path": <路径占位>  # 首选注释说明
                "path": 另一个占位
            """

        descriptions = tool_schema._docstring_descriptions(_Tool)
        assert descriptions == {"path": "首选注释说明"}


class TestInferFaultTolerance:
    """源码不可得 → 返回空列表（不抛）。"""

    def test_missing_run_returns_empty(self) -> None:
        class _NoRun:
            pass

        assert infer_parameters_from_source(_NoRun) == []

    def test_builtin_run_source_unavailable(self) -> None:
        """内置函数无源码 → getsource 抛 TypeError → 容错返回空列表。"""

        class _BuiltinRun:
            _run = staticmethod(len)

        assert infer_parameters_from_source(_BuiltinRun) == []

    def test_explicit_reading_forms_and_cast_types(self) -> None:
        class _Tool:
            """工具说明。

            输入:
                "target": <目标路径>
            """

            def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
                name = self._require(input_data, "name")
                count = int(input_data.get("count", 3))
                enabled = input_data["enabled"]
                return {"name": name, "count": count, "enabled": enabled}

        specs = {spec.name: spec for spec in infer_parameters_from_source(_Tool)}

        assert specs["name"].required is True
        assert specs["name"].type == "string"
        assert specs["count"].required is False
        assert specs["count"].type == "integer", "int(...) 外层强制转换应推断为 integer"
        assert specs["count"].default == 3
        assert specs["enabled"].required is True
        assert specs["enabled"].type == "string", "无默认值/无强制转换 → 回落 string"


class TestNormalise:
    """显式声明归一化：ToolParameterSpec / dict / tuple / 非法项。"""

    def test_spec_passthrough(self) -> None:
        spec = ToolParameterSpec(name="a")
        assert _normalise(spec) is spec

    def test_dict_form(self) -> None:
        spec = _normalise({"name": "a", "type": "integer", "description": "d", "required": False})
        assert spec is not None
        assert (spec.name, spec.type, spec.description, spec.required) == (
            "a",
            "integer",
            "d",
            False,
        )
        assert isinstance(spec.default, type(None))

    def test_dict_form_minimal(self) -> None:
        spec = _normalise({"name": "a"})
        assert spec is not None
        assert (spec.type, spec.description, spec.required) == ("string", "", True)

    def test_dict_without_name_is_invalid(self) -> None:
        assert _normalise({"type": "string"}) is None

    def test_tuple_forms(self) -> None:
        spec = _normalise(("a", "integer", "说明", False))
        assert spec is not None
        assert (spec.name, spec.type, spec.description, spec.required) == (
            "a",
            "integer",
            "说明",
            False,
        )

        short = _normalise(["a"])
        assert short is not None
        assert (short.name, short.type, short.description, short.required) == (
            "a",
            "string",
            "",
            True,
        )

    def test_unrecognised_item_is_invalid(self) -> None:
        assert _normalise(42) is None
        assert _normalise([]) is None


class TestToolParametersFallthrough:
    """声明项全部非法 → 回落到源码推断（tool_parameters 的 fallthrough 分支）。"""

    def test_invalid_declaration_falls_back_to_inference(self) -> None:
        class _Tool:
            """工具说明。"""

            parameters: ClassVar[list[Any]] = [42, {"type": "string"}]

            def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {"p": self._require(input_data, "path")}

        specs = tool_parameters(_Tool)

        assert [spec.name for spec in specs] == ["path"]
        assert specs[0].required is True

    def test_valid_declaration_wins_over_source(self) -> None:
        class _Tool:
            """工具说明。"""

            parameters: ClassVar[list[Any]] = [{"name": "declared_only"}]

            def _run(self, input_data: dict[str, Any]) -> dict[str, Any]:
                return {"p": self._require(input_data, "from_source")}

        assert [spec.name for spec in tool_parameters(_Tool)] == ["declared_only"]


class TestFlowPlaceholderSources:
    """执行流占位符来源 = 技能参数 ∪ 可接线输出键。"""

    def test_sources_union(self) -> None:
        assert flow_placeholder_sources(["file_path"]) == {"file_path", *WIREABLE_OUTPUT_KEYS}

    def test_no_skill_params(self) -> None:
        assert flow_placeholder_sources([]) == set(WIREABLE_OUTPUT_KEYS)
