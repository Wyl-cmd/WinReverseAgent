"""winreverse.skill.executor — Skill 执行器（Skill → Soul 数据流连通）。

将 YamlSkillLoader 加载的 Skill 转换为 Soul 引擎可执行的调用序列：
1. 从 SkillRegistry 获取 Skill 实例
2. 校验参数（必填项检查）
3. 渲染 prompt_template（用 parameters 替换 {{var}} 占位符）
4. 若 Skill 含 execution_flow：
   - 渲染每步 args 中的 {{var}} 占位符
   - 通过 SoulToolsetAdapter 执行工具调用
   - 收集结果作为预置上下文，附加到 prompt
5. 调用 WinReverseSoul.run(prompt) 执行 agent loop
6. 返回最终 assistant 回复

设计原则（抄写优先）：
- 不重写 Skill.render_prompt 与 SoulToolsetAdapter.execute，直接复用
- 不改动 SkillLoader / Soul 引擎代码，仅做组装
- execution_flow 是可选的确定性预执行步骤，LLM 仍可自主决策后续工具调用

参考：实施方案 §6.3 Skill 引擎数据流
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from winreverse.skill.loader import Skill, SkillNotFoundError, SkillRegistry
from winreverse.soul.soul import WinReverseSoul

logger = logging.getLogger(__name__)


class SkillExecutionError(Exception):
    """Skill 执行失败（参数校验、工具调用异常等）。"""


@dataclass(slots=True)
class FlowStepResult:
    """execution_flow 单步执行结果。

    Attributes:
        action: 工具名
        arguments: 实际传入参数（已渲染）
        output: 工具输出（字符串形式）
        is_error: 是否为错误结果
    """

    action: str
    arguments: dict[str, Any]
    output: str
    is_error: bool = False


@dataclass
class SkillRunResult:
    """Skill 执行完整结果。

    Attributes:
        skill_name: Skill 名称
        final_answer: Soul 引擎最终回复
        flow_results: 预置执行流结果（无 execution_flow 时为空列表）
        rendered_prompt: 渲染后的 prompt（含预置上下文）
    """

    skill_name: str
    final_answer: str
    flow_results: list[FlowStepResult] = field(default_factory=list)
    rendered_prompt: str = ""


class SkillExecutor:
    """Skill 执行器：连通 Skill 加载器与 Soul 引擎。

    用法：
        registry = ToolRegistry()
        register_all_tools(registry)
        soul = WinReverseSoul(llm=my_llm, registry=registry)

        skill_registry = SkillRegistry()
        loader = YamlSkillLoader()
        skill_registry.register(loader.load(Path("skills/pe_analyzer.yaml")))

        executor = SkillExecutor(skill_registry=skill_registry, soul=soul)
        result = await executor.run("PE 文件分析", {"file_path": "test.exe"})
        print(result.final_answer)
    """

    def __init__(
        self,
        skill_registry: SkillRegistry,
        soul: WinReverseSoul,
    ) -> None:
        """初始化 Skill 执行器。

        Args:
            skill_registry: Skill 注册中心（已加载所有 Skill YAML）
            soul: WinReverseSoul 引擎实例（已配置 LLM 与工具集）
        """
        self._skill_registry = skill_registry
        self._soul = soul

    @property
    def soul(self) -> WinReverseSoul:
        """关联的 Soul 引擎实例。"""
        return self._soul

    @property
    def skill_registry(self) -> SkillRegistry:
        """关联的 Skill 注册中心。"""
        return self._skill_registry

    async def run(
        self,
        skill_name: str,
        parameters: dict[str, Any] | None = None,
        *,
        agent_type: str = "default",
        model: str | None = None,
        max_turns: int | None = None,
    ) -> SkillRunResult:
        """执行指定 Skill。

        Args:
            skill_name: Skill 名称（需已注册到 SkillRegistry）
            parameters: 用户传入参数（用于渲染 prompt_template 和 execution_flow）
            agent_type: 传递给 Soul 引擎的 agent 类型
            model: 覆盖默认 LLM 模型名
            max_turns: 覆盖默认最大轮次

        Returns:
            SkillRunResult 包含最终回复、预置流结果、渲染后的 prompt

        Raises:
            SkillNotFoundError: Skill 未注册
            SkillExecutionError: 参数校验失败或预置流执行异常
        """
        params = parameters or {}

        # 1. 获取 Skill 实例
        try:
            skill = self._skill_registry.get(skill_name)
        except SkillNotFoundError:
            logger.warning("Skill 未注册: %s", skill_name)
            raise

        logger.info("开始执行 Skill: %s (target=%s)", skill.name, skill.target)

        # 2. 校验参数
        errors = skill.validate_parameters(params)
        if errors:
            raise SkillExecutionError(f"Skill '{skill_name}' 参数校验失败: {'; '.join(errors)}")

        # 3. 填充默认值（用于渲染 prompt 和 flow）
        render_vars = self._build_render_vars(skill, params)

        # 4. 渲染 prompt_template
        base_prompt = skill.render_prompt(render_vars)

        # 5. 执行预置 execution_flow（可选）
        flow_results: list[FlowStepResult] = []
        if skill.execution_flow:
            flow_results = await self._execute_flow(skill, render_vars)
            logger.info(
                "Skill '%s' 预置流执行完成: %d 步，%d 错误",
                skill.name,
                len(flow_results),
                sum(1 for r in flow_results if r.is_error),
            )

        # 6. 组装最终 prompt（base + 预置流结果上下文）
        final_prompt = self._build_prompt_with_flow(base_prompt, flow_results)

        # 7. 调用 Soul 引擎执行 agent loop
        try:
            answer = await self._soul.run(
                prompt=final_prompt,
                agent_type=agent_type,
                model=model,
                max_turns=max_turns,
            )
        except Exception as exc:
            logger.exception("Skill '%s' Soul 引擎执行失败", skill.name)
            raise SkillExecutionError(f"Soul 引擎执行失败: {exc}") from exc

        return SkillRunResult(
            skill_name=skill.name,
            final_answer=answer,
            flow_results=flow_results,
            rendered_prompt=final_prompt,
        )

    @staticmethod
    def _build_render_vars(
        skill: Skill,
        user_params: dict[str, Any],
    ) -> dict[str, Any]:
        """合并 Skill 参数定义的默认值与用户传入参数。

        Args:
            skill: Skill 实例
            user_params: 用户传入参数

        Returns:
            合并后的变量字典（用户值优先于默认值）
        """
        variables: dict[str, Any] = {}
        for param in skill.parameters:
            if param.name in user_params:
                variables[param.name] = user_params[param.name]
            elif param.default is not None:
                variables[param.name] = param.default
            else:
                # 必填项已由 validate_parameters 检查；非必填且无默认值留空字符串
                variables[param.name] = ""
        # 同时保留用户传入的额外参数（不在 Skill 定义中的）
        for key, value in user_params.items():
            if key not in variables:
                variables[key] = value
        return variables

    async def _execute_flow(
        self,
        skill: Skill,
        variables: dict[str, Any],
    ) -> list[FlowStepResult]:
        """执行 Skill 的预置 execution_flow。

        Args:
            skill: Skill 实例
            variables: 渲染变量

        Returns:
            每步执行结果列表
        """
        results: list[FlowStepResult] = []
        toolset = self._soul.toolset

        for idx, step in enumerate(skill.execution_flow):
            action = step.get("action", "")
            raw_args = step.get("args", {})

            if not action:
                logger.warning(
                    "Skill '%s' execution_flow[%d] 缺少 action 字段，跳过",
                    skill.name,
                    idx,
                )
                continue

            # 渲染 args 中的 {{var}} 占位符
            rendered_args = self._render_args(raw_args, variables)

            logger.debug(
                "Skill '%s' 预置流[%d] 调用 %s args=%s",
                skill.name,
                idx,
                action,
                rendered_args,
            )

            try:
                tool_result = await toolset.execute(action, rendered_args)
                results.append(
                    FlowStepResult(
                        action=action,
                        arguments=rendered_args,
                        output=tool_result.output,
                        is_error=tool_result.is_error,
                    )
                )
            except Exception as exc:
                # 单步失败不中断整体流程，记录错误继续后续步骤
                logger.exception(
                    "Skill '%s' 预置流[%d] %s 执行异常",
                    skill.name,
                    idx,
                    action,
                )
                results.append(
                    FlowStepResult(
                        action=action,
                        arguments=rendered_args,
                        output=f"执行异常: {type(exc).__name__}: {exc}",
                        is_error=True,
                    )
                )

        return results

    @staticmethod
    def _render_args(
        raw_args: dict[str, Any],
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        """渲染工具调用参数中的 {{var}} 占位符，并做类型推断。

        支持的类型转换（针对字符串值）：
        - "true"/"false"（不区分大小写）→ bool
        - 纯数字字符串 → int
        - 浮点数字符串 → float
        - 其他 → 字符串

        非字符串值（int/bool/list 等）原样返回。

        Args:
            raw_args: 原始参数字典
            variables: 渲染变量

        Returns:
            渲染并类型转换后的参数字典
        """
        rendered: dict[str, Any] = {}
        for key, value in raw_args.items():
            if isinstance(value, str):
                # 替换 {{var}} 占位符
                replaced = value
                for var_name, var_value in variables.items():
                    replaced = replaced.replace(f"{{{{{var_name}}}}}", str(var_value))
                rendered[key] = SkillExecutor._infer_type(replaced)
            else:
                rendered[key] = value
        return rendered

    @staticmethod
    def _infer_type(value: str) -> Any:
        """字符串类型推断。

        Args:
            value: 字符串值

        Returns:
            推断后的值（bool/int/float/str）
        """
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        # 尝试 int
        try:
            return int(value)
        except ValueError:
            pass
        # 尝试 float
        try:
            return float(value)
        except ValueError:
            pass
        return value

    @staticmethod
    def _build_prompt_with_flow(
        base_prompt: str,
        flow_results: list[FlowStepResult],
    ) -> str:
        """将预置流结果作为上下文附加到 prompt。

        若 flow_results 为空或全部成功且无输出，则原样返回 base_prompt。

        Args:
            base_prompt: 渲染后的 prompt_template
            flow_results: 预置流执行结果

        Returns:
            组装后的完整 prompt
        """
        if not flow_results:
            return base_prompt

        parts = [base_prompt, "", "--- 预置执行流结果（execution_flow output）---"]
        for idx, result in enumerate(flow_results):
            status_mark = "[ERROR]" if result.is_error else "[OK]"
            parts.append(
                f"\n步骤 {idx + 1}: {status_mark} {result.action}"
                f"\n  参数: {result.arguments}"
                f"\n  输出:\n{result.output}"
            )
        parts.append("--- 预置执行流结果结束 ---")
        parts.append("\n请基于上述预置执行流结果和任务描述，继续完成分析并输出最终报告。")
        return "\n".join(parts)
