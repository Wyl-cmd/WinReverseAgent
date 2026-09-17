"""winreverse.soul.tool_schema — ToolInterface 入参 schema 读取与推断（P0-1 修复）。

背景（2026-09-16 实测）：
    修复前 ``SoulToolsetAdapter._infer_parameters()`` 恒返回空列表，导致 47/47 个工具
    向 LLM 暴露的 ``parameters`` 全为空；LLM 每轮 tool_call 的 ``arguments`` 恒为 ``{}``，
    任何带参工具必然 ``KeyError: 缺少必需参数: ...``。技能因此"跑得动、没数据"。

本模块提供两条路径（显式优先）：

1. **显式声明**：工具类（或实例）声明 ``parameters: list[ToolParameterSpec]``；
2. **源码推断**：解析工具 ``_run`` 的 AST，收集参数读取点：
   - ``self._require(input_data, "x")``  → 必填
   - ``input_data["x"]``                → 必填
   - ``input_data.get("x", <default>)`` → 选填（带默认值）
   类型按"外层强制转换函数"（int/float/bool/str/list/dict）或默认值字面量推断；
   描述取自类 docstring 的 ``"参数名": 值  # 说明`` 注释（即工具自带的"输入:"块）。

设计约束：推断只读工具源码，不改变任何运行时调用行为（``execute`` 契约不变）。
"""

from __future__ import annotations

import ast
import inspect
import re
import textwrap
from typing import Any

from winreverse.engine.bus import ToolInterface, ToolParameterSpec

# 强制转换函数 → JSON Schema 类型串
_CAST_TYPES: dict[str, str] = {
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "str": "string",
    "list": "array",
    "dict": "object",
}

# 默认值类型 → JSON Schema 类型串（bool 必须排在 int 之前判定）
_JSON_TYPES: dict[str, str] = {
    "bool": "boolean",
    "int": "integer",
    "float": "number",
    "str": "string",
    "list": "array",
    "dict": "object",
}

# 参数读取点的键名集合（AST/静态校验共用）
_REQUIRE_ATTR = "_require"

# docstring 中 "参数名": 值  # 说明 的行（工具"输入:"块的写法）
_DOC_PARAM_RE = re.compile(
    r'^\s*"?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"?\s*:\s*(?P<value>[^#]*?)\s*(?:#\s*(?P<comment>.+))?$'
)


def _json_type_of_default(value: Any) -> str:
    """默认值 → JSON Schema 类型串。"""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _literal_type_of(node: ast.expr | None) -> str | None:
    """AST 字面量节点 → JSON Schema 类型串（非字面量返回 None）。"""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return None if node.value is None else _json_type_of_default(node.value)
    if isinstance(node, ast.List):
        return "array"
    if isinstance(node, ast.Dict):
        return "object"
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, (int, float))
        and not isinstance(node.operand.value, bool)
    ):
        # 负数常量（-1）按数值处理
        return "number" if isinstance(node.operand.value, float) else "integer"
    return None


def _match_param_read(node: ast.expr) -> tuple[str, str, ast.expr | None] | None:
    """识别参数读取表达式。

    支持三种写法（kind 用于判定必填性）：
        self._require(input_data, "name")        → ("name", "require", None)
        input_data["name"]                       → ("name", "subscript", None)
        input_data.get("name")                   → ("name", "get", None)
        input_data.get("name", <default>)        → ("name", "get", <default 节点>)

    Args:
        node: 待识别的 AST 表达式节点

    Returns:
        (参数名, 读取方式, 默认值节点)；不匹配时返回 None
    """
    # self._require(input_data, "name")
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == _REQUIRE_ATTR
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        return node.args[1].value, "require", None

    # input_data["name"]
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "input_data"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        return node.slice.value, "subscript", None

    # input_data.get("name"[, default])
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "input_data"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        default_node = node.args[1] if len(node.args) > 1 else None
        return node.args[0].value, "get", default_node

    return None


def _is_required(kinds: set[str]) -> bool:
    """按读取方式判定必填性。

    规则（保守优先"必填"，但尊重守卫式读法）：
    - 出现 ``self._require(...)``       → 必填（工具自己声明了必填）
    - 只有 ``input_data["x"]`` 下标读取 → 必填
    - 出现过 ``input_data.get("x")``    → 选填（``str(input_data["x"]) if input_data.get("x") else None``
      这类"守卫 + 下标"写法不是必填，net.edit_pcap.keep_first_n / shell.run.cwd 即此形态）
    """
    if "require" in kinds:
        return True
    if "get" in kinds:
        return False
    return "subscript" in kinds


def _docstring_descriptions(cls: type) -> dict[str, str]:
    """从类 docstring 的 ``"参数名": 值  # 说明`` 行提取参数描述。

    描述来源优先级：
    1. ``#`` 之后的注释（工具"输入:"块的标准写法）
    2. 值本身是占位说明（``"<PE 文件路径>"`` → ``PE 文件路径``）
    """
    descriptions: dict[str, str] = {}
    doc = inspect.getdoc(cls) or ""
    for line in doc.splitlines():
        match = _DOC_PARAM_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        if name in descriptions:
            continue
        comment = (match.group("comment") or "").strip()
        value = (match.group("value") or "").strip().rstrip(",").strip()
        if comment:
            descriptions[name] = comment
        elif len(value) > 2 and value.startswith("<") and value.endswith(">"):
            descriptions[name] = value[1:-1].strip()
    return descriptions


def infer_parameters_from_source(cls: type) -> list[ToolParameterSpec]:
    """从工具类 ``_run`` 源码推断参数 schema。

    Args:
        cls: 工具类（需实现 ``_run(self, input_data)``）

    Returns:
        参数声明列表（按源码中出现顺序去重）；无法解析源码时返回空列表
    """
    run = getattr(cls, "_run", None)
    if run is None:
        return []
    try:
        source = textwrap.dedent(inspect.getsource(run))
        tree = ast.parse(source)
    except (OSError, TypeError, SyntaxError, IndentationError):
        return []

    order: list[str] = []
    kinds: dict[str, set[str]] = {}
    defaults: dict[str, ast.expr | None] = {}
    cast_types: dict[str, str] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.expr):
            continue
        matched = _match_param_read(node)
        if matched is not None:
            name, kind, default_node = matched
            if name not in kinds:
                order.append(name)
                kinds[name] = set()
                defaults[name] = default_node
            kinds[name].add(kind)
            if kind == "get" and default_node is not None:
                defaults.setdefault(name, default_node)
            continue

        # 外层强制转换（int(...) / bool(...) / str(...)）→ 类型提示
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _CAST_TYPES
            and len(node.args) == 1
        ):
            inner = _match_param_read(node.args[0])
            if inner is not None:
                cast_types.setdefault(inner[0], _CAST_TYPES[node.func.id])

    descriptions = _docstring_descriptions(cls)
    specs: list[ToolParameterSpec] = []
    for name in order:
        default_node = defaults.get(name)
        ptype = cast_types.get(name) or _literal_type_of(default_node) or "string"
        default_value = None
        if default_node is not None and isinstance(default_node, ast.Constant):
            default_value = default_node.value
        specs.append(
            ToolParameterSpec(
                name=name,
                type=ptype,
                description=descriptions.get(name, ""),
                required=_is_required(kinds[name]),
                default=default_value,
            )
        )
    return specs


def _normalise(spec: Any) -> ToolParameterSpec | None:
    """把显式声明归一化为 ToolParameterSpec（支持 dict / 元组 / 实例）。"""
    if isinstance(spec, ToolParameterSpec):
        return spec
    if isinstance(spec, dict) and spec.get("name"):
        return ToolParameterSpec(
            name=str(spec["name"]),
            type=str(spec.get("type") or "string"),
            description=str(spec.get("description") or ""),
            required=bool(spec.get("required", True)),
            default=spec.get("default"),
        )
    if isinstance(spec, (tuple, list)) and spec:
        return ToolParameterSpec(
            name=str(spec[0]),
            type=str(spec[1]) if len(spec) > 1 else "string",
            description=str(spec[2]) if len(spec) > 2 else "",
            required=bool(spec[3]) if len(spec) > 3 else True,
        )
    return None


def tool_parameters(tool: ToolInterface) -> list[ToolParameterSpec]:
    """读取工具的入参 schema（显式声明优先，否则源码推断）。

    Args:
        tool: 工具实例/类

    Returns:
        参数声明列表；两者都拿不到时返回空列表
    """
    declared = getattr(tool, "parameters", None)
    if declared:
        specs = [spec for spec in (_normalise(item) for item in declared) if spec is not None]
        if specs:
            return specs
    target = tool if isinstance(tool, type) else type(tool)
    return infer_parameters_from_source(target)


# 预置执行流可以从上游工具输出"接线"给下游的键（soul/tool_schema 与 skill 校验共用）。
# 说明：memory.attach → pid；memory.dump → output_dir/dump_dir；net.live_capture → pcap
WIREABLE_OUTPUT_KEYS: tuple[str, ...] = (
    "pid",
    "output_dir",
    "dump_dir",
    "output_path",
    "manifest_path",
    "pcap",
    "serial",
)


def flow_placeholder_sources(skill_parameters: list[str]) -> set[str]:
    """执行流中 ``{{占位符}}`` 的合法来源：技能参数 + 可接线输出键。"""
    return set(skill_parameters) | set(WIREABLE_OUTPUT_KEYS)


__all__ = [
    "WIREABLE_OUTPUT_KEYS",
    "flow_placeholder_sources",
    "infer_parameters_from_source",
    "tool_parameters",
]
