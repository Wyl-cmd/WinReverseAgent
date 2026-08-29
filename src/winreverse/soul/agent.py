"""winreverse.soul.agent — 单轮 Agent 实现。

从 KXNS soul/agent.py 裁剪迁移，主要改动：
- 移除 `from kxns.soul.subagents.*` 依赖（WinReverseAgent 当前阶段不实现子 agent）
- 移除 `from kxns.soul.tool_args import parse_tool_call_arguments`（内联简化版解析）
- 移除 `from kxns.soul.tool_resolution import resolve_kosong_tools`（直接使用 SoulToolsetAdapter）
- Runtime 改用 SoulToolsetAdapter（WinReverseAgent 适配器）替代 KxnsToolset
- 移除 AgentRuntime 类（功能合并到 Runtime，减少概念冗余）

核心循环：
    run(prompt) → step() → call_llm() → execute_tool() → _should_continue() → 下一轮

参考：实施方案 §8.2.7
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from kosong.types import GenerateResult, Message, MessageRole, ToolCall, ToolResult
from winreverse.soul.compaction import Compactor
from winreverse.soul.toolset import SoulToolsetAdapter

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CompactionEvent:
    """一次自动压缩的事件记录（token 数均为估算值）。

    Attributes:
        before_tokens: 压缩前的 token 估算
        after_tokens: 压缩后的 token 估算
        micro_saved: MicroCompact 节省的 token（旧工具结果清理）
        snip_freed: SnipCompact 释放的 token（旧消息裁剪）
        strategy: 配置的压缩策略名
        used_llm: 是否动用了 LLM 总结式压缩
    """

    before_tokens: int
    after_tokens: int
    micro_saved: int
    snip_freed: int
    strategy: str
    used_llm: bool


class AgentState(str, Enum):
    """Agent 运行状态。"""

    IDLE = "idle"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    FINISHED = "finished"
    FAILED = "failed"


class AgentConfig(BaseModel):
    """Agent 配置。

    Attributes:
        name: Agent 名称（用于日志与追踪）
        system_prompt: 系统提示词
        tools: 允许调用的工具名列表（空表示继承全部）
        model: LLM 模型名（None 表示用默认）
        agent_type: Agent 类型标识（用于上下文过滤）
        max_turns: 最大轮次（防止无限循环）
        max_context_size: 上下文窗口 token 上限（自动压缩触发基准）
        compaction_strategy: 压缩策略（simple / selective / layered）
        auto_compact: 是否启用自动上下文压缩
        compaction_trigger_ratio: 触发比例（token 达窗口上限的该比例时压缩）
    """

    name: str
    system_prompt: str
    tools: list[str] = Field(default_factory=list)
    model: str | None = None
    agent_type: str = "default"
    max_turns: int = 50
    max_context_size: int = 100000
    compaction_strategy: str = "layered"
    auto_compact: bool = True
    compaction_trigger_ratio: float = 0.8

    model_config = {"arbitrary_types_allowed": True}


class StepResult(BaseModel):
    """单步执行结果。

    Attributes:
        response: LLM 返回的消息
        tool_calls: 本步触发的工具调用列表
        tool_results: 工具执行结果列表（与 tool_calls 一一对应）
        stop_reason: 停止原因（stop/end_turn/tool_use）
    """

    response: Message
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    stop_reason: str = "stop"

    model_config = {"arbitrary_types_allowed": True}


def parse_tool_call_arguments(arguments_raw: Any) -> tuple[dict[str, Any], str | None]:
    """解析工具调用参数（简化版，替代 kxns.soul.tool_args.parse_tool_call_arguments）。

    Args:
        arguments_raw: 原始参数（可能是 JSON 字符串、dict 或 None）

    Returns:
        (parsed_dict, error_message)：解析成功 error_message 为 None
    """
    if arguments_raw is None:
        return {}, None
    if isinstance(arguments_raw, dict):
        return arguments_raw, None
    if isinstance(arguments_raw, str):
        if not arguments_raw.strip():
            return {}, None
        try:
            parsed = json.loads(arguments_raw)
            if isinstance(parsed, dict):
                return parsed, None
            return {}, f"Tool arguments must be a JSON object, got {type(parsed).__name__}"
        except json.JSONDecodeError as e:
            return {}, f"Invalid JSON in tool arguments: {e}"
    return {}, f"Unsupported tool arguments type: {type(arguments_raw).__name__}"


@dataclass(slots=True, kw_only=True)
class Runtime:
    """Agent 运行时上下文。

    封装 LLM 调用、工具执行、会话目录等运行时依赖。
    Agent 通过 Runtime 与外部资源交互，便于测试注入 mock。

    Attributes:
        llm: LLM 生成器（需提供 async generate(messages, model, tools) 方法）
        toolset: Soul 工具集适配器（None 表示无工具可用）
        session_dir: 会话目录（用于持久化日志/中间结果）
        work_dir: 工作目录（用于相对路径解析）
        app_config: 应用配置（可选，供扩展使用）
        compactor: 上下文压缩器（None 表示禁用自动压缩）
    """

    llm: Any = None
    toolset: SoulToolsetAdapter | None = None
    session_dir: Path = field(default_factory=lambda: Path.cwd())
    work_dir: Path = field(default_factory=lambda: Path.cwd())
    app_config: Any = None
    compactor: Compactor | None = None

    async def call_llm(
        self,
        agent_id: str,
        messages: list[Message],
        model: str | None = None,
        tools: list[str] | None = None,
        agent_config: AgentConfig | None = None,
    ) -> GenerateResult:
        """调用 LLM 生成下一轮回复。

        Args:
            agent_id: Agent 实例 ID（用于日志）
            messages: 对话历史
            model: 模型名（None 用 Runtime 默认）
            tools: 允许的工具名列表（当前未使用，预留）
            agent_config: Agent 配置（当前未使用，预留）

        Returns:
            GenerateResult 包含 LLM 返回的消息和停止原因

        Raises:
            RuntimeError: LLM 未初始化
        """
        _ = agent_id, tools, agent_config  # 预留扩展点
        if self.llm is None:
            raise RuntimeError("LLM manager not initialized")

        # 从 toolset 导出 kosong Tool 列表
        kosong_tools = None
        if self.toolset is not None:
            kosong_tools = self.toolset.to_kosong_tools()

        # 调用 LLM 生成器（兼容 kosong.generate 和 LLM manager 两种接口）
        generate_fn = getattr(self.llm, "generate", None)
        if generate_fn is None:
            raise RuntimeError("LLM manager missing generate() method")

        if kosong_tools:
            return await generate_fn(messages=messages, model=model, tools=kosong_tools)
        return await generate_fn(messages=messages, model=model)

    async def execute_tool(
        self,
        agent_id: str,
        tool_name: str,
        arguments: Any,
    ) -> str:
        """执行工具调用。

        Args:
            agent_id: Agent 实例 ID
            tool_name: 工具名
            arguments: 输入参数（dict 或 JSON 字符串）

        Returns:
            工具输出（字符串形式）

        Raises:
            RuntimeError: 未配置 toolset
        """
        _ = agent_id
        if self.toolset is None:
            raise RuntimeError(f"Tool '{tool_name}' not found: no toolset configured in Runtime")

        args = arguments if isinstance(arguments, dict) else {}
        result = await self.toolset.execute(tool_name, args)
        return result.output


class Agent:
    """单轮 Agent（agent loop 实现）。

    核心循环：
        1. 将用户 prompt 加入消息历史
        2. 循环调用 step() 直到 _should_continue 返回 False
        3. 每个 step：call_llm → 解析 tool_calls → execute_tool → 收集结果
        4. 返回最后一条 assistant 消息内容

    Attributes:
        id: Agent 实例唯一 ID
        config: Agent 配置
        state: 当前运行状态
        messages: 对话历史
        current_turn: 当前轮次
    """

    def __init__(self, config: AgentConfig, runtime: Runtime) -> None:
        self.id: str = uuid.uuid4().hex
        self.config: AgentConfig = config
        self.state: AgentState = AgentState.IDLE
        self.messages: list[Message] = []
        self.current_turn: int = 0
        self._runtime: Runtime = runtime
        self.last_compaction: CompactionEvent | None = None
        """最近一次自动压缩的事件记录（供 TUI/UI 展示与测试断言）"""
        self.total_usage: dict[str, int] = {"input": 0, "output": 0, "steps": 0}
        """会话级 token 用量累计（每次 LLM 调用累加）"""
        self.compaction_count: int = 0
        """自动压缩触发次数"""
        self.on_assistant_text: Any = None
        """每轮 assistant 文本回调（TUI 实时显示 AI 发言）；签名 fn(text: str)"""

    async def _maybe_compact(self) -> None:
        """按需执行上下文压缩（在每次 LLM 调用前调用）。

        分层执行（便宜的先上，贵的兜底）：
        1. MicroCompact：旧工具结果就地清理（无 LLM）
        2. SnipCompact：按比例裁剪旧消息（无 LLM）
        3. 仍超限 → 有 LLM 走总结式压缩，无 LLM 走确定性 LAYERED 压缩

        压缩成功/失败都会反馈到 AutoCompact 熔断器；
        任何异常都不会中断 agent 主循环。
        """
        compactor = self._runtime.compactor
        if compactor is None or not self.config.auto_compact:
            return

        model = self.config.model or "cl100k_base"
        token_count = compactor.estimate_tokens(self.messages, model)
        if not compactor.auto_compact.should_compact(
            token_count,
            self.config.max_context_size,
            reserved_context_size=compactor.auto_compact.buffer_tokens,
        ):
            return

        try:
            self.messages, micro_saved = compactor.micro_compact.compact(self.messages, model=model)
            self.messages, snip_freed = compactor.snip_compact.compact(self.messages, model=model)
            remaining = compactor.estimate_tokens(self.messages, model)

            used_llm = False
            if remaining >= self.config.max_context_size * self.config.compaction_trigger_ratio:
                # 微压缩/裁剪不足以回落到阈值以下，做整体压缩
                if compactor.has_llm:
                    result = await compactor.compact_with_llm(self.messages, model)
                    if len(result.messages) < len(self.messages):
                        self.messages = list(result.messages)
                        used_llm = True
                if compactor.estimate_tokens(self.messages, model) >= (
                    self.config.max_context_size * self.config.compaction_trigger_ratio
                ):
                    # LLM 压缩不可用或效果不足，退回确定性压缩
                    self.messages, _result = compactor.compact(self.messages, model)

            after_tokens = compactor.estimate_tokens(self.messages, model)
            self.compaction_count += 1
            self.last_compaction = CompactionEvent(
                before_tokens=token_count,
                after_tokens=after_tokens,
                micro_saved=micro_saved,
                snip_freed=snip_freed,
                strategy=self.config.compaction_strategy,
                used_llm=used_llm,
            )
            compactor.auto_compact.record_success()
            logger.info(
                "[COMPACT] ~%d -> ~%d tokens (micro -%d, snip -%d, llm=%s)",
                token_count,
                after_tokens,
                micro_saved,
                snip_freed,
                used_llm,
            )
        except Exception as e:
            compactor.auto_compact.record_failure()
            logger.warning("Auto compaction failed (will retry later): %s", e)

    async def run(self, prompt: str) -> str:
        """运行 agent loop。

        Args:
            prompt: 用户输入

        Returns:
            最后一条 assistant 消息的文本内容
        """
        self.state = AgentState.RUNNING
        self.messages.append(Message(role=MessageRole.USER, content=prompt))

        for turn in range(self.config.max_turns):
            self.current_turn = turn
            step_result = await self.step()

            self.messages.append(step_result.response)

            # 实时推送本轮 assistant 发言（TUI 显示 AI 在说什么）
            if self.on_assistant_text is not None:
                text = "".join(
                    str(getattr(part, "text", "")) for part in step_result.response.content
                )
                if text.strip():
                    try:
                        self.on_assistant_text(text)
                    except Exception:
                        logger.exception("on_assistant_text 回调失败")

            # 将工具结果作为 tool 消息追加到历史
            if step_result.tool_results:
                for tr in step_result.tool_results:
                    self.messages.append(
                        Message(
                            role=MessageRole.TOOL,
                            content=tr.content,
                            tool_call_id=tr.tool_call_id,
                        )
                    )

            if not self._should_continue(step_result):
                break

        if self.state == AgentState.RUNNING:
            self.state = AgentState.FINISHED

        # 提取最后一条 assistant 消息的文本内容
        final_content = ""
        for msg in reversed(self.messages):
            if msg.role == MessageRole.ASSISTANT and msg.content:
                if isinstance(msg.content, str):
                    final_content = msg.content
                elif isinstance(msg.content, list):
                    parts: list[str] = []
                    for part in msg.content:
                        if hasattr(part, "text"):
                            parts.append(part.text)
                    final_content = "\n".join(parts)
                break

        return final_content

    async def step(self) -> StepResult:
        """执行单步：上下文压缩（按需）→ 调用 LLM → 处理工具调用。"""
        tool_calls: list[ToolCall] = []
        tool_results: list[ToolResult] = []

        await self._maybe_compact()

        result = await self._runtime.call_llm(
            agent_id=self.id,
            messages=self.messages,
            model=self.config.model,
            agent_config=self.config,
        )

        response = result.message
        stop_reason = result.stop_reason

        usage = result.usage
        if usage is not None:
            self.total_usage["input"] += int(getattr(usage, "input", 0) or 0)
            self.total_usage["output"] += int(getattr(usage, "output", 0) or 0)
        self.total_usage["steps"] += 1

        if response.tool_calls:
            tool_calls = response.tool_calls
            for tc in tool_calls:
                tr = await self._process_tool_call(tc)
                tool_results.append(tr)

        return StepResult(
            response=response,
            tool_calls=tool_calls,
            tool_results=tool_results,
            stop_reason=stop_reason,
        )

    async def _process_tool_call(self, tool_call: ToolCall) -> ToolResult:
        """处理单个工具调用：解析参数 → 执行 → 包装结果。"""
        try:
            tool_name = tool_call.function.name if tool_call.function else ""
            arguments_raw = tool_call.function.arguments if tool_call.function else None
            arguments, parse_err = parse_tool_call_arguments(arguments_raw)
            if parse_err:
                return ToolResult(
                    tool_call_id=tool_call.id,
                    content=parse_err,
                    is_error=True,
                )
            output = await self._runtime.execute_tool(
                agent_id=self.id,
                tool_name=tool_name,
                arguments=arguments,
            )
            return ToolResult(
                tool_call_id=tool_call.id,
                content=output,
                is_error=False,
            )
        except Exception as exc:
            logger.exception("Tool call failed: %s", tool_call)
            return ToolResult(
                tool_call_id=tool_call.id,
                content=str(exc),
                is_error=True,
            )

    def context_snapshot(self) -> dict[str, Any]:
        """当前上下文状态快照（TUI 状态栏轮询用）。

        Returns:
            messages: 当前消息条数
            used_tokens: 估算 token（compactor 缺失时为 0）
            max_context_size: 窗口上限
            remaining_tokens: 剩余额度
            usage_ratio: 占用比例（0-1）
            trigger_ratio: 压缩触发比例
            compaction_count: 自动压缩次数
            total_usage: {input, output, steps}
        """
        compactor = self._runtime.compactor
        model = self.config.model or "cl100k_base"
        used = compactor.estimate_tokens(self.messages, model) if compactor else 0
        max_size = self.config.max_context_size
        return {
            "messages": len(self.messages),
            "used_tokens": used,
            "max_context_size": max_size,
            "remaining_tokens": max(0, max_size - used),
            "usage_ratio": (used / max_size) if max_size else 0.0,
            "trigger_ratio": self.config.compaction_trigger_ratio,
            "compaction_count": self.compaction_count,
            "total_usage": dict(self.total_usage),
        }

    def _should_continue(self, result: StepResult) -> bool:
        """判断是否继续下一轮。"""
        if self.state != AgentState.RUNNING:
            return False
        if result.stop_reason in ("stop", "end_turn"):
            return False
        if result.stop_reason == "tool_use" and result.tool_calls:
            return True
        if self.current_turn >= self.config.max_turns - 1:
            return False
        return bool(result.tool_calls)


# 兼容类型别名（供外部代码引用）
AgentRuntime = Runtime

# 类型别名，便于类型注解（KXNS 中 role 字段使用 Literal）
AgentRole = Literal["root", "subagent"]
