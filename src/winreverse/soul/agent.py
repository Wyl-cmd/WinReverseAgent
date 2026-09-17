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
import re
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

# P0-3① 续写提示词：max_tokens 截断后从中断处继续（不重复已输出内容）
_CONTINUE_PROMPT = (
    "上一条回复因输出长度上限被截断（stop_reason=max_tokens）。"
    "请从中断处继续输出剩余内容，不要重复已输出的部分；"
    "若内容已完整，请直接给出结论。"
)

# P0-3② 空答复兜底提示词：不带工具，强制用已有信息给结论
_SUMMARY_PROMPT = (
    "你上一条回复没有产生任何可读文本。现在**不要调用任何工具**，"
    "直接用本次会话中已经拿到的信息（含预置执行流输出/工具返回结果）给出最终结论："
    "先给结论，再列关键证据（数据、数值、路径），最后写仍不确定的项。"
    "若确实没有可用数据，就明确写出「未取得数据」及原因。"
)

# P0-4 短答闸门提示词：不足 min_answer_chars 且无结构的"引子式答复"补一次续写
_SHORT_ANSWER_PROMPT = (
    "你上一条回复过短且没有实质内容（只有开场句/元话术，没有结论与证据）。"
    "现在**不要调用任何工具**，直接用本次会话中已经拿到的信息"
    "（含预置执行流输出/工具返回结果）补充实质内容："
    "先给结论，再列关键证据（数据、数值、路径），最后写仍不确定的项。"
    "不要重复已经输出的开场句；若确实没有可用数据，就明确写出「未取得数据」及原因。"
)

# 短答闸门的结构判据：列表项（`- ` / `* ` / `1. ` / `1) `）
_LIST_ITEM_RE = re.compile(r"(?:[-*+•]|\d{1,2}[.)])\s+\S")

# 短答闸门的结构判据：结论/证据类标记词（短文本里出现即视为有实质内容）
_SUBSTANCE_MARKERS = (
    "结论",
    "证据",
    "摘要",
    "风险",
    "建议",
    "不确定",
    "未取得数据",
    "sha256",
    "md5",
    "imphash",
)


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


class EmptyFinalAnswerError(RuntimeError):
    """最终答复为空且兜底总结调用也拿不到文本（不许静默返回空）。

    2026-09-16（P0-3② 修复）：修复前 ``run()`` 在"末条 assistant 消息是空
    TextPart"时会静默返回 ``""``，调用方（CLI / Skill 执行器）只看到空白
    最终答复，误判为"技能没产出"。现在改为抛可读错误，让失败显式暴露。
    """


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
        max_tokens_continuations: stop_reason=max_tokens 时的自动续写次数上限
        short_answer_gate: 是否启用短答闸门（非截断但无实质内容的答复补一次续写）。
            默认 False（库级静默）：启用后每次短答会多消耗一次 LLM 调用，
            由应用层显式打开（WinReverseApplication → WinReverseSoul → AgentConfig）。
        min_answer_chars: 短答闸门的最短实质长度（低于此长度且无结构 → 触发续写）
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
    max_tokens_continuations: int = 2
    short_answer_gate: bool = False
    min_answer_chars: int = 300

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
        *,
        allow_tools: bool = True,
    ) -> GenerateResult:
        """调用 LLM 生成下一轮回复。

        Args:
            agent_id: Agent 实例 ID（用于日志）
            messages: 对话历史
            model: 模型名（None 用 Runtime 默认）
            tools: 允许的工具名列表（当前未使用，预留）
            agent_config: Agent 配置（当前未使用，预留）
            allow_tools: 是否把工具集暴露给本次调用（False = 纯文本总结调用，
                P0-3② 空答复兜底使用）

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
        if allow_tools and self.toolset is not None:
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
        self.last_stop_reason: str = ""
        """最近一轮 LLM 调用的 stop_reason（P0-3 诊断用：区分 max_tokens 截断/正常结束）"""
        self.answer_fallback_used: bool = False
        """是否动用了空答复兜底总结调用（P0-3②）"""
        self.short_answer_retry_used: bool = False
        """是否动用了短答闸门续写调用（P0-4）"""
        self._answer_override: str | None = None
        """max_tokens 续写后的拼接文本（非空时优先作为最终答复，P0-3①）"""

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

        返回流程（2026-09-16 P0-3 修复 / 2026-09-17 P0-4 短答闸门）：
        1. 正常循环：step() → 追加 assistant/工具消息 → 判定是否继续
        2. ``stop_reason == "max_tokens"``：先带剩余预算**自动续写并拼接**，不再直接结束
        3. 收尾提取"最后一条含非空文本的 assistant 消息"；若文本过短且无结构
           （「引子式答复」）则补**一次**短答续写
        4. 仍为空则做**一次**不带工具的总结兜底调用；再为空则抛
           ``EmptyFinalAnswerError``（不许静默返回空）

        Args:
            prompt: 用户输入

        Returns:
            最终答复文本（保证非空白；除非一次 LLM 都没调用过，如 max_turns=0）

        Raises:
            EmptyFinalAnswerError: 跑过 LLM 但拿到空答复且兜底后仍为空
        """
        self.state = AgentState.RUNNING
        self.messages.append(Message(role=MessageRole.USER, content=prompt))
        self.answer_fallback_used = False
        self.short_answer_retry_used = False
        self._answer_override = None

        for turn in range(self.config.max_turns):
            self.current_turn = turn
            self._answer_override = None
            step_result = await self.step()
            self.last_stop_reason = step_result.stop_reason

            self.messages.append(step_result.response)

            # 实时推送本轮 assistant 发言（TUI 显示 AI 在说什么）
            if self.on_assistant_text is not None:
                text = self._text_of(step_result.response)
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

            # P0-3①：输出预算耗尽（GLM 等推理模型的推理 token 与正文共享 max_tokens）
            # → 带剩余预算续写并拼接，而不是把被截断的内容当最终答复直接结束。
            if step_result.stop_reason == "max_tokens" and not step_result.tool_calls:
                self._answer_override = await self._continue_after_max_tokens(step_result)

            if not self._should_continue(step_result):
                break

        if self.state == AgentState.RUNNING:
            self.state = AgentState.FINISHED

        # 提取最终答复：跳过空文本部件/纯推理消息，取最后一条含非空 TextPart 的 assistant
        final_content = self._extract_final_answer()

        # P0-4：短答闸门 —— 非截断但无实质内容的"引子式答复"补一次续写
        # （现象：5/23 ≈ 21.7% 技能 E2E 交付 146–255 字符开场句并以 rc=0 交付）
        if (
            self.config.short_answer_gate
            and final_content.strip()
            and not self._is_substantive_answer(final_content)
            and self.total_usage["steps"] > 0
        ):
            final_content = await self._continue_short_answer(final_content)

        # P0-3②：空答复兜底一次（不带工具、明确要求"用已有信息给出结论"）
        if not final_content.strip() and self.total_usage["steps"] > 0:
            final_content = await self._empty_answer_fallback()

        if not final_content.strip() and self.total_usage["steps"] > 0:
            # 不许静默返回空：明确报错（CLI/Skill 执行器会转为 rc≠0 的可见失败）
            raise EmptyFinalAnswerError(
                f"最终答复为空：已做 {self.total_usage['steps']} 次 LLM 调用，"
                f"最后 stop_reason={self.last_stop_reason or 'unknown'}，"
                f"续写与总结兜底均未取得文本（请检查模型输出预算 / 推理 token 占用）"
            )

        return final_content

    @staticmethod
    def _text_of(message: Message | None) -> str:
        """抽取消息文本（兼容 str 内容与多部件 list；跳过无 .text 的部件）。"""
        if message is None or not message.content:
            return ""
        content = message.content
        if isinstance(content, str):
            return content
        parts: list[str] = []
        for part in content:
            text = getattr(part, "text", None)
            if isinstance(text, str) and text:
                parts.append(text)
        return "\n".join(parts)

    def _extract_final_answer(self) -> str:
        """提取最终答复：优先 max_tokens 续写拼接文本，否则最后一条含非空文本的 assistant。

        P0-3 修复点：修复前"取最后一条 assistant 消息"会把空 TextPart 当作最终答复（返回 ""），
        即使前一轮/前几轮已经有实质内容。现在按"最后一条**含非空文本**"回退查找。
        """
        if self._answer_override and self._answer_override.strip():
            return self._answer_override
        for msg in reversed(self.messages):
            if msg.role != MessageRole.ASSISTANT:
                continue
            text = self._text_of(msg)
            if text.strip():
                return text
        return ""

    async def _continue_after_max_tokens(self, truncated: StepResult) -> str:
        """stop_reason=max_tokens 时续写：带剩余预算再次调用并把片段拼接回来。

        Args:
            truncated: 被截断的那一轮 step 结果

        Returns:
            拼接后的完整文本（原始片段 + 各次续写片段；都不为空才算成功）
        """
        merged = self._text_of(truncated.response)
        attempts = max(0, int(self.config.max_tokens_continuations))
        for index in range(attempts):
            self.messages.append(Message(role=MessageRole.USER, content=_CONTINUE_PROMPT))
            result = await self._runtime.call_llm(
                agent_id=self.id,
                messages=self.messages,
                model=self.config.model,
                agent_config=self.config,
            )
            self.messages.append(result.message)
            self.total_usage["steps"] += 1
            usage = result.usage
            if usage is not None:
                self.total_usage["input"] += int(
                    getattr(usage, "input", None) or getattr(usage, "input_tokens", 0) or 0
                )
                self.total_usage["output"] += int(
                    getattr(usage, "output", None) or getattr(usage, "output_tokens", 0) or 0
                )
            chunk = self._text_of(result.message)
            if not chunk.strip():
                break
            merged = f"{merged}{chunk}" if merged else chunk
            logger.info(
                "[MAX_TOKENS] 续写第 %d 次成功拼接 %d 字符（stop_reason=%s）",
                index + 1,
                len(chunk),
                result.stop_reason,
            )
            if result.stop_reason != "max_tokens":
                break
        return merged

    async def _empty_answer_fallback(self) -> str:
        """空答复兜底：一次不带工具的"用已有信息给出结论"总结调用（P0-3②）。"""
        self.answer_fallback_used = True
        self.messages.append(Message(role=MessageRole.USER, content=_SUMMARY_PROMPT))
        try:
            result = await self._runtime.call_llm(
                agent_id=self.id,
                messages=self.messages,
                model=self.config.model,
                agent_config=self.config,
                allow_tools=False,
            )
        except Exception:
            logger.exception("空答复兜底总结调用失败")
            return ""
        self.messages.append(result.message)
        self.total_usage["steps"] += 1
        self.last_stop_reason = result.stop_reason
        return self._text_of(result.message)

    def _is_substantive_answer(self, text: str) -> bool:
        """短答闸门判据：答复是否"有实质内容"（P0-4）。

        判据 = 长度达标 **或** 结构命中：
        1. ``len(strip) >= config.min_answer_chars`` → 视为实质；
        2. 含代码块（```）/ 列表项 / 结论·证据类标记词 → 视为实质。

        两者皆不满足 = 「引子式答复」（只有开场句/元话术），需要补一次续写。

        Args:
            text: 待判定答复文本

        Returns:
            True 表示有实质内容（放行），False 表示属短答（触发一次续写）
        """
        stripped = text.strip()
        if not stripped:
            return False
        if len(stripped) >= max(0, int(self.config.min_answer_chars)):
            return True
        if "```" in stripped:
            return True
        if any(_LIST_ITEM_RE.search(line) for line in stripped.splitlines()):
            return True
        return any(marker in stripped for marker in _SUBSTANCE_MARKERS)

    async def _continue_short_answer(self, short_text: str) -> str:
        """短答闸门续写：对「非截断但无实质内容」的答复补一次总结调用（P0-4）。

        只重试一次（不循环），且不带工具；续写仍为空则返回 ``""``，
        由 ``run()`` 既有的空答复兜底路径接管（再空则抛 EmptyFinalAnswerError）。

        Args:
            short_text: 上一轮的短答复文本（作为兜底保留项）

        Returns:
            续写文本；续写取不到文本时返回 ""（交给空答复兜底）
        """
        self.short_answer_retry_used = True
        self.messages.append(Message(role=MessageRole.USER, content=_SHORT_ANSWER_PROMPT))
        try:
            result = await self._runtime.call_llm(
                agent_id=self.id,
                messages=self.messages,
                model=self.config.model,
                agent_config=self.config,
                allow_tools=False,
            )
        except Exception:
            logger.exception("短答闸门续写调用失败，保留原答复（%d 字符）", len(short_text.strip()))
            return short_text
        self.messages.append(result.message)
        self.total_usage["steps"] += 1
        self.last_stop_reason = result.stop_reason
        continuation = self._text_of(result.message)
        if not continuation.strip():
            logger.warning(
                "短答闸门：续写未取得文本（原答复 %d 字符），转入空答复兜底",
                len(short_text.strip()),
            )
            return ""
        if self._is_substantive_answer(continuation):
            logger.info("短答闸门：续写取得实质答复 %d 字符", len(continuation.strip()))
            return continuation
        logger.warning(
            "短答闸门：续写仍为短答复（%d 字符 < 阈值 %d），保留较长的一条（不循环重试）",
            len(continuation.strip()),
            self.config.min_answer_chars,
        )
        return continuation if len(continuation.strip()) > len(short_text.strip()) else short_text

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
            # kosong Usage 的字段是 input_tokens/output_tokens；兼容带 .input/.output 的 TokenUsage
            self.total_usage["input"] += int(
                getattr(usage, "input", None) or getattr(usage, "input_tokens", 0) or 0
            )
            self.total_usage["output"] += int(
                getattr(usage, "output", None) or getattr(usage, "output_tokens", 0) or 0
            )
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
