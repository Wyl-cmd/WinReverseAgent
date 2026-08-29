"""winreverse.skill.loader — Skill 加载器。

定义 SkillLoader Protocol 与 Skill 数据类，并提供 YAML 格式的实现 YamlSkillLoader。

参考：实施方案 §6
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

import yaml


@dataclass(frozen=True)
class SkillParameter:
    """Skill 参数定义。

    Attributes:
        name: 参数名
        type: 参数类型（string/int/bool/float 等）
        default: 默认值
        description: 参数说明
        required: 是否必填
    """

    name: str
    type: str = "string"
    default: Any = None
    description: str = ""
    required: bool = False


@dataclass
class Skill:
    """Skill 数据模型。

    一个 Skill 包含：
    - 元信息（name/description/target）
    - 参数定义（parameters）
    - Prompt 模板（prompt_template）
    - 可选的执行流（execution_flow）

    Attributes:
        name: 技能名称（唯一标识）
        description: 技能用途说明
        target: 适用目标（如 '通用游戏' / 'PE 文件' / '木马样本'）
        parameters: 参数列表
        prompt_template: Prompt 模板，用 {{var}} 占位
        execution_flow: 可选的预置执行流（增加确定性）
        source_path: Skill 文件来源路径（用于错误定位）
    """

    name: str
    description: str
    target: str = "通用"
    parameters: list[SkillParameter] = field(default_factory=list)
    prompt_template: str = ""
    execution_flow: list[dict[str, Any]] = field(default_factory=list)
    source_path: Path | None = None

    def render_prompt(self, variables: dict[str, Any]) -> str:
        """渲染 Prompt 模板，用 variables 替换 {{var}} 占位符。

        Args:
            variables: 变量字典

        Returns:
            渲染后的 Prompt 字符串

        Raises:
            KeyError: 模板中的变量未在 variables 中提供
        """
        result = self.prompt_template
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", str(value))
        return result

    def validate_parameters(self, args: dict[str, Any]) -> list[str]:
        """校验传入参数是否满足 Skill 定义。

        Args:
            args: 用户传入的参数字典

        Returns:
            错误消息列表（空列表表示校验通过）
        """
        errors: list[str] = []
        for param in self.parameters:
            if param.required and param.name not in args:
                errors.append(f"缺少必填参数: {param.name}")
        return errors


class SkillLoader(Protocol):
    """Skill 加载器契约。

    YAML/Markdown/JSON 格式各做一个实现，互不影响。
    新增格式时只需实现此接口，不改调用方代码。
    """

    def load(self, path: Path) -> Skill:
        """从文件加载 Skill。

        Args:
            path: Skill 文件路径

        Returns:
            Skill 实例

        Raises:
            FileNotFoundError: 文件不存在
            ValueError: 文件格式错误
        """
        ...

    def supports(self, path: Path) -> bool:
        """判断加载器是否支持该文件格式。

        Args:
            path: 文件路径

        Returns:
            True 表示此加载器可处理该文件
        """
        ...


class SkillNotFoundError(FileNotFoundError):
    """请求的 Skill 不存在时抛出。"""


class SkillLoadError(ValueError):
    """Skill 文件加载失败（YAML 语法错误或字段缺失）。"""


class YamlSkillLoader:
    """YAML 格式 Skill 加载器。

    解析 `*.yaml` / `*.yml` 文件，按 Skill 数据模型构造实例。

    YAML 结构示例：
        name: "技能名称"            # 必填
        description: "技能说明"      # 必填
        target: "通用"              # 可选，默认 "通用"
        parameters:                 # 可选
          - name: "process_name"
            type: "string"
            default: "game.exe"
            description: "目标进程名"
            required: true
        prompt_template: |          # 可选
          任务：...
        execution_flow:             # 可选
          - action: "memory.attach"
            args: "{{process_name}}"
    """

    def load(self, path: Path) -> Skill:
        """从 YAML 文件加载 Skill。

        Args:
            path: Skill 文件路径（.yaml / .yml）

        Returns:
            Skill 实例

        Raises:
            FileNotFoundError: 文件不存在
            SkillLoadError: YAML 语法错误或必填字段缺失
        """
        # 文件不存在时让 open() 自然抛 FileNotFoundError
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise SkillLoadError(f"YAML 语法错误: {path}: {e}") from e

        if not isinstance(data, dict):
            raise SkillLoadError(
                f"Skill 文件顶层结构必须是字典: {path}（实际类型: {type(data).__name__}）"
            )

        # 必填字段校验
        name = data.get("name")
        description = data.get("description")
        if not name:
            raise SkillLoadError(f"Skill 文件缺少必填字段 'name': {path}")
        if not description:
            raise SkillLoadError(f"Skill 文件缺少必填字段 'description': {path}")

        # 可选字段
        target = str(data.get("target", "通用"))
        prompt_template = str(data.get("prompt_template", ""))

        # 参数列表解析
        parameters = self._parse_parameters(data.get("parameters"), path)

        # 执行流解析
        execution_flow = self._parse_execution_flow(data.get("execution_flow"), path)

        return Skill(
            name=str(name),
            description=str(description),
            target=target,
            parameters=parameters,
            prompt_template=prompt_template,
            execution_flow=execution_flow,
            source_path=path,
        )

    def supports(self, path: Path) -> bool:
        """判断是否支持该文件（按后缀名）。"""
        return path.suffix.lower() in (".yaml", ".yml")

    @staticmethod
    def _parse_parameters(raw: Any, path: Path) -> list[SkillParameter]:
        """解析 parameters 字段。

        Args:
            raw: YAML 解析后的原始数据（应为 list[dict]）
            path: 文件路径（用于错误定位）

        Returns:
            SkillParameter 列表

        Raises:
            SkillLoadError: parameters 格式错误
        """
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise SkillLoadError(
                f"'parameters' 必须是列表: {path}（实际类型: {type(raw).__name__}）"
            )

        result: list[SkillParameter] = []
        for idx, item in enumerate(raw):
            if not isinstance(item, dict):
                raise SkillLoadError(
                    f"'parameters[{idx}]' 必须是字典: {path}（实际类型: {type(item).__name__}）"
                )
            param_name = item.get("name")
            if not param_name:
                raise SkillLoadError(f"'parameters[{idx}]' 缺少 'name' 字段: {path}")

            result.append(
                SkillParameter(
                    name=str(param_name),
                    type=str(item.get("type", "string")),
                    default=item.get("default"),
                    description=str(item.get("description", "")),
                    required=bool(item.get("required", False)),
                )
            )
        return result

    @staticmethod
    def _parse_execution_flow(raw: Any, path: Path) -> list[dict[str, Any]]:
        """解析 execution_flow 字段。

        Args:
            raw: YAML 解析后的原始数据（应为 list[dict]）
            path: 文件路径（用于错误定位）

        Returns:
            执行流步骤列表

        Raises:
            SkillLoadError: execution_flow 格式错误
        """
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise SkillLoadError(
                f"'execution_flow' 必须是列表: {path}（实际类型: {type(raw).__name__}）"
            )

        result: list[dict[str, Any]] = []
        for idx, item in enumerate(raw):
            if not isinstance(item, dict):
                raise SkillLoadError(
                    f"'execution_flow[{idx}]' 必须是字典: {path}（实际类型: {type(item).__name__}）"
                )
            if "action" not in item:
                raise SkillLoadError(f"'execution_flow[{idx}]' 缺少 'action' 字段: {path}")
            result.append(cast(dict[str, Any], item))
        return result


class SkillRegistry:
    """Skill 注册中心。

    扫描 skills/ 目录，用 SkillLoader 加载所有 Skill，按名称索引。
    """

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        """注册 Skill。重复注册同名 Skill 抛出 ValueError。"""
        if skill.name in self._skills:
            raise ValueError(f"Skill 已注册: {skill.name}")
        self._skills[skill.name] = skill

    def get(self, name: str) -> Skill:
        """获取 Skill 实例。未注册时抛出 SkillNotFoundError。

        支持文件名别名：按 YAML name 未命中时，回退按来源文件名
        （不含扩展名，如 'pe_analyzer'）匹配，与 CLI 使用习惯一致。
        """
        if name in self._skills:
            return self._skills[name]
        for skill in self._skills.values():
            if skill.source_path is not None and skill.source_path.stem == name:
                return skill
        raise SkillNotFoundError(name)

    def list_skills(self) -> list[dict[str, str]]:
        """列出所有已注册 Skill 的 name 与 description。"""
        return [{"name": s.name, "description": s.description} for s in self._skills.values()]

    def clear(self) -> None:
        """清空所有注册的 Skill（主要用于测试）。"""
        self._skills.clear()

    def __len__(self) -> int:
        return len(self._skills)

    def __contains__(self, name: object) -> bool:
        return name in self._skills
