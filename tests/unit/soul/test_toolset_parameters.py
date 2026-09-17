"""测试模块：SoulToolsetAdapter 的工具参数 schema（P0-1 回归门禁）。

背景（2026-09-16 实测）：
    ``to_kosong_tools()`` 修复前对 47/47 个工具返回空 ``parameters`` →
    LLM 每轮 tool_call 的 ``arguments`` 恒为 ``{}`` → 带参工具必然
    ``KeyError: 缺少必需参数: ...``；技能表现为"跑得动、没数据"。

本测试锁定 P0-1 的契约：
1. 每个工具的 ``parameters`` 非空（真正的零参工具须在白名单里，且经源码校验确无入参）；
2. 每个参数都带 name / type / required，且 type 是合法 JSON Schema 类型串；
3. 必填项与 ``_run`` 源码里的读取点一致（``_require``/``input_data[...]`` 必填、``.get`` 选填）；
4. 显式声明的 ``ToolParameterSpec`` 优先；
5. 既有调用行为不变（``execute`` 路径与错误兜底照旧）。
"""

from __future__ import annotations

import base64
from typing import ClassVar

import pytest

from kosong.types import ToolParameter
from winreverse.engine.bus import ToolParameterSpec, ToolRegistry
from winreverse.engine.tools import ALL_TOOLS, register_all_tools
from winreverse.soul.tool_schema import infer_parameters_from_source, tool_parameters
from winreverse.soul.toolset import SoulToolsetAdapter

# 合法的 JSON Schema 类型串（kosong ToolParameter.type 会直接进 OpenAI function schema）
_VALID_TYPES = {"string", "integer", "number", "boolean", "array", "object"}

# 真正的零参工具（_run 完全不读 input_data）——白名单由下面的源码校验测试兜底
_ZERO_INPUT_TOOLS = {"behavior.sandbox_check"}


@pytest.fixture
def adapter() -> SoulToolsetAdapter:
    """装配全部真实工具的适配器。"""
    registry = ToolRegistry()
    register_all_tools(registry)
    return SoulToolsetAdapter(registry)


def test_all_tools_expose_non_empty_parameters(adapter: SoulToolsetAdapter) -> None:
    """48/48 工具都能带出参数 schema（零参工具除外，见白名单校验测试）。"""
    tools = adapter.to_kosong_tools()
    assert len(tools) == len(ALL_TOOLS)
    assert len(tools) >= 47, "工具数量不得低于修复前基线（47 个 + 新增 file.hash）"

    empty = [tool.name for tool in tools if not tool.parameters]
    unexpected = [name for name in empty if name not in _ZERO_INPUT_TOOLS]
    assert not unexpected, f"这些工具的 parameters 仍为空（LLM 无法传参）: {unexpected}"


def test_every_parameter_has_name_type_required(adapter: SoulToolsetAdapter) -> None:
    """每个参数都含 name/type/required，且 type 合法。"""
    for tool in adapter.to_kosong_tools():
        for param in tool.parameters:
            assert isinstance(param, ToolParameter)
            assert isinstance(param.name, str) and param.name.strip()
            assert param.type in _VALID_TYPES, f"{tool.name}.{param.name} 类型非法: {param.type!r}"
            assert isinstance(param.required, bool)


def test_required_flags_match_source_reads(adapter: SoulToolsetAdapter) -> None:
    """必填判定与 _run 源码读取点一致（显式声明的工具以声明为准）。"""
    for tool in adapter.to_kosong_tools():
        if tool.name in _ZERO_INPUT_TOOLS:
            continue
        instance = adapter.get_tool(tool.name)
        assert instance is not None
        if getattr(instance, "parameters", None):
            # 显式声明（ToolParameterSpec）：作者在工具里定义了判别式语义，
            # 覆盖源码推断（如 memory.read 的 length 只在 type=bytes 时必填）
            continue
        from_source = {spec.name: spec.required for spec in tool_parameters(instance)}
        exported = {param.name: param.required for param in tool.parameters}
        assert exported == from_source, f"{tool.name} 参数集合与源码不一致"


def test_required_parameters_are_present_in_schema(adapter: SoulToolsetAdapter) -> None:
    """每个必填参数都能在源码里找到读取点（不得凭空捏造必填项）。"""
    by_name = {tool.name: tool for tool in adapter.to_kosong_tools()}
    for name, tool in by_name.items():
        if name in _ZERO_INPUT_TOOLS:
            continue
        source_names = {
            spec.name for spec in infer_parameters_from_source(type(adapter.get_tool(name)))
        }
        for param in tool.parameters:
            assert param.name in source_names, f"{name}.{param.name} 不在源码读取点里"


def test_zero_input_tools_really_have_no_inputs() -> None:
    """白名单里的"零参工具"必须经源码校验：确实不读 input_data。"""
    by_name = {tool.name: tool for tool in ALL_TOOLS}
    for name in _ZERO_INPUT_TOOLS:
        assert name in by_name, f"白名单工具不存在: {name}"
        assert infer_parameters_from_source(type(by_name[name])) == [], (
            f"{name} 源码里存在参数读取点，不应留在零参白名单"
        )


def test_known_tools_expose_expected_parameters(adapter: SoulToolsetAdapter) -> None:
    """关键工具的参数名/必填性与实测调用保持一致。"""
    expected = {
        "pe.meta": {"file_path": True},
        "pe.sections": {"file_path": True},
        "memory.strings": {"path": True, "min_length": False, "limit": False},
        "memory.iocs": {"path": True},
        "memory.attach": {"process_name": True},
        "memory.dump": {"pid": True, "output_dir": False, "max_total_mb": False},
        "file.hash": {"path": True, "algorithm": False},
        "shell.run": {"command": True, "shell": False, "timeout": False},
        "die.scan_file": {"file_path": True, "deep": False},
        "fs.read_file": {"path": True, "offset": False, "length": False},
    }
    by_name = {tool.name: tool for tool in adapter.to_kosong_tools()}
    for name, params in expected.items():
        schema = {param.name: param.required for param in by_name[name].parameters}
        for param_name, required in params.items():
            assert param_name in schema, f"{name} 缺参数 {param_name}"
            assert schema[param_name] is required, (
                f"{name}.{param_name} required 期望 {required}，实际 {schema[param_name]}"
            )


def test_parameter_types_are_inferred(adapter: SoulToolsetAdapter) -> None:
    """类型推断生效：pid/address 等为 integer，布尔开关为 boolean。"""
    by_name = {
        tool.name: {p.name: p.type for p in tool.parameters} for tool in adapter.to_kosong_tools()
    }
    assert by_name["memory.dump"]["pid"] == "integer"
    assert by_name["memory.dump"]["max_total_mb"] == "integer"
    assert by_name["memory.strings"]["min_length"] == "integer"
    assert by_name["memory.regions"]["include_all"] == "boolean"
    assert by_name["die.scan_file"]["deep"] == "boolean"
    assert by_name["pe.meta"]["file_path"] == "string"


def test_declared_parameters_take_precedence() -> None:
    """工具显式声明 parameters 时优先使用（不再走源码推断）。"""

    class _DeclaredTool:
        name = "test.declared"
        description = "显式声明参数的工具"
        parameters: ClassVar[list[ToolParameterSpec]] = [
            ToolParameterSpec(
                name="path",
                type="string",
                description="文件路径",
                required=True,
            ),
            ToolParameterSpec(name="deep", type="boolean", description="深度", required=False),
        ]

        def execute(self, input_data: dict[str, object]) -> dict[str, object]:
            return {"status": "success"}

        def _run(self, input_data: dict[str, object]) -> dict[str, object]:
            return {"status": "success"}

    registry = ToolRegistry()
    registry.register(_DeclaredTool())
    adapter = SoulToolsetAdapter(registry)

    tool = adapter.to_kosong_tools()[0]
    assert [(p.name, p.type, p.required) for p in tool.parameters] == [
        ("path", "string", True),
        ("deep", "boolean", False),
    ]
    assert tool.parameters[0].description == "文件路径"


def test_parameter_descriptions_come_from_docstring(adapter: SoulToolsetAdapter) -> None:
    """参数描述从工具 docstring 提取（含 ``# 说明`` 注释与 ``<占位说明>`` 两种写法）。"""
    by_name = {
        tool.name: {p.name: p.description for p in tool.parameters}
        for tool in adapter.to_kosong_tools()
    }
    tools = adapter.to_kosong_tools()

    assert by_name["memory.dump"]["pid"] == "memory.attach 返回的进程 ID"
    assert by_name["memory.regions"]["include_all"].startswith("可选")
    # 有描述的参数数量下限（防止 docstring 提取逻辑回归）
    described = sum(1 for tool in tools for param in tool.parameters if param.description)
    assert described >= 35, f"带描述的参数过少: {described}"


async def test_execute_path_unchanged(adapter: SoulToolsetAdapter) -> None:
    """schema 变更不影响调用行为：正确参数照旧成功、缺参照旧报 KeyError。"""
    ok = await adapter.execute(
        "disasm",
        {"code": base64.b64encode(b"\x90").decode("ascii"), "arch": "x64"},
    )
    assert ok.is_error is False
    assert '"status": "success"' in ok.output

    missing = await adapter.execute("pe.meta", {})
    assert missing.is_error is True
    assert "file_path" in missing.output
