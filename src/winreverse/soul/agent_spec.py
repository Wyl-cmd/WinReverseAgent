"""winreverse.soul.agent_spec — Agent 类型定义与加载。

从 KXNS soul/agent_spec.py 迁移，原文件本身不依赖 kxns.* 模块，可近乎原样迁移。
仅修改 LaborMarket.__init__ 中的初始化逻辑注释。

功能：
- ToolStrategy 枚举（allowlist / inherit）
- AgentTypeDefinition 数据类：定义 agent 类型的系统提示、工具策略、模型等
- load_agent_spec: 从 YAML 文件加载 AgentTypeDefinition
- render_system_prompt: 用 jinja2 或简单字符串替换渲染系统提示模板
- LaborMarket: agent 类型注册中心，支持 load_directory 批量加载

参考：实施方案 §8.2.4
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class ToolStrategy(str, Enum):
    """工具选择策略。"""

    ALLOWLIST = "allowlist"
    INHERIT = "inherit"


@dataclass(frozen=True, slots=True, kw_only=True)
class AgentTypeDefinition:
    """Agent 类型定义。

    Attributes:
        name: 类型名称（唯一标识）
        description: 用途说明
        system_prompt_template: 系统提示模板（可含 jinja2 占位符）
        tool_strategy: 工具选择策略（allowlist 仅允许 allowed_tools，inherit 继承父级）
        when_to_use: 何时使用此 agent 类型（供调度器参考）
        allowed_tools: 当 tool_strategy=ALLOWLIST 时允许的工具名列表
        default_model: 默认 LLM 模型名
        supports_background: 是否支持后台运行
    """

    name: str
    description: str
    system_prompt_template: str = ""
    tool_strategy: ToolStrategy = ToolStrategy.INHERIT
    when_to_use: str = ""
    allowed_tools: tuple[str, ...] = ()
    default_model: str | None = None
    supports_background: bool = True


class AgentSpecError(Exception):
    """Agent 规格加载异常。"""


def load_agent_spec(path: Path) -> AgentTypeDefinition:
    """从 YAML 文件加载 AgentTypeDefinition。

    Args:
        path: YAML 文件路径

    Returns:
        AgentTypeDefinition 实例

    Raises:
        AgentSpecError: 文件不存在、YAML 语法错误或缺少必填字段
    """
    if not path.exists():
        raise AgentSpecError(f"Agent spec file not found: {path}")
    if not path.is_file():
        raise AgentSpecError(f"Agent spec path is not a file: {path}")

    try:
        with open(path, encoding="utf-8") as f:
            data: dict[str, Any] = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise AgentSpecError(f"Invalid YAML in agent spec file: {e}") from e

    if not isinstance(data, dict):
        raise AgentSpecError("Agent spec file must contain a YAML mapping")

    # 兼容两种 YAML 结构：顶层为 agent 定义，或 {agent: {...}} 包裹
    agent_data = data.get("agent", data)
    if not isinstance(agent_data, dict):
        raise AgentSpecError("'agent' 字段应为映射（或顶层直接为 agent 定义）")

    name = agent_data.get("name")
    if not name:
        raise AgentSpecError("Agent spec must have a 'name' field")

    description = agent_data.get("description", "")

    # 系统提示支持两种方式：外部文件引用 或 内联字符串
    system_prompt_template = ""
    system_prompt_path = agent_data.get("system_prompt_path")
    system_prompt_inline = agent_data.get("system_prompt")
    if system_prompt_path is not None:
        prompt_file = path.parent / system_prompt_path
        if prompt_file.exists():
            try:
                system_prompt_template = prompt_file.read_text(encoding="utf-8")
            except (OSError, ValueError) as e:
                # 统一收敛为 AgentSpecError，保证 load_directory 能按文件粒度跳过坏文件
                raise AgentSpecError(f"无法读取系统提示文件 {prompt_file}: {e}") from e
        else:
            logger.warning("System prompt file not found: %s", prompt_file)
    elif system_prompt_inline is not None:
        system_prompt_template = system_prompt_inline

    strategy_str = agent_data.get("tool_strategy", "inherit")
    try:
        tool_strategy = ToolStrategy(strategy_str)
    except ValueError:
        tool_strategy = ToolStrategy.INHERIT

    # 兼容 allowed_tools 和 tools 两个字段名
    allowed_tools_raw = agent_data.get("allowed_tools") or agent_data.get("tools") or []
    allowed_tools = tuple(allowed_tools_raw) if isinstance(allowed_tools_raw, list) else ()

    when_to_use = agent_data.get("when_to_use", "")
    default_model = agent_data.get("model")
    supports_background = agent_data.get("supports_background", True)

    return AgentTypeDefinition(
        name=name,
        description=description,
        system_prompt_template=system_prompt_template,
        tool_strategy=tool_strategy,
        when_to_use=when_to_use,
        allowed_tools=allowed_tools,
        default_model=default_model,
        supports_background=supports_background,
    )


def render_system_prompt(template: str, args: dict[str, str] | None = None) -> str:
    """渲染系统提示模板。

    优先使用 jinja2，未安装时退化为简单字符串替换（{{key}} → value）。

    Args:
        template: 模板字符串
        args: 模板参数

    Returns:
        渲染后的字符串
    """
    if not args:
        return template
    try:
        from jinja2 import Template

        jinja_template = Template(template)
        rendered: str = jinja_template.render(**args)
        return rendered
    except ImportError:
        result = template
        for key, value in args.items():
            result = result.replace(f"{{{{{key}}}}}", value)
        return result


class LaborMarket:
    """Agent 类型注册中心。

    管理所有已加载的 AgentTypeDefinition，支持按名称查询、批量加载目录。
    """

    def __init__(self) -> None:
        self._types: dict[str, AgentTypeDefinition] = {}

    def register(self, type_def: AgentTypeDefinition) -> None:
        """注册一个 agent 类型。重复注册会覆盖同名类型。"""
        self._types[type_def.name] = type_def

    def get(self, name: str) -> AgentTypeDefinition | None:
        """按名称查询 agent 类型，未找到返回 None。"""
        return self._types.get(name)

    def require(self, name: str) -> AgentTypeDefinition:
        """按名称查询 agent 类型，未找到抛出 AgentSpecError。"""
        type_def = self._types.get(name)
        if type_def is None:
            raise AgentSpecError(f"Unknown agent type: {name}")
        return type_def

    def list_types(self) -> list[AgentTypeDefinition]:
        """列出所有已注册的 agent 类型。"""
        return list(self._types.values())

    def load_spec(self, path: Path) -> AgentTypeDefinition:
        """加载单个 YAML 文件并注册。"""
        type_def = load_agent_spec(path)
        self._types[type_def.name] = type_def
        return type_def

    def load_directory(self, dir_path: Path) -> list[AgentTypeDefinition]:
        """批量加载目录下所有 .yaml/.yml 文件。"""
        loaded: list[AgentTypeDefinition] = []
        if not dir_path.is_dir():
            return loaded
        for yaml_file in sorted(dir_path.glob("*.yaml")):
            try:
                type_def = self.load_spec(yaml_file)
                loaded.append(type_def)
            except AgentSpecError:
                logger.warning("Failed to load agent spec from %s", yaml_file)
        for yaml_file in sorted(dir_path.glob("*.yml")):
            try:
                type_def = self.load_spec(yaml_file)
                loaded.append(type_def)
            except AgentSpecError:
                logger.warning("Failed to load agent spec from %s", yaml_file)
        return loaded
