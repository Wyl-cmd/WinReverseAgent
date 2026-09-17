"""winreverse.soul.soul — 轻量级 Soul 引擎主入口。

从 KXNS KxnsSoul 裁剪简化，保留核心 agent loop + 上下文压缩能力。
不包含 KXNS 的以下子系统（作为 P2 后续按需引入）：
- coordinator（多 worker 协调）
- denwarenji（检查点回溯）
- approval（工具调用审批）
- permissions（权限引擎）
- hooks（钩子引擎）
- injection（动态注入）
- recovery（错误恢复）
- wire（事件总线）

核心职责：
1. 组装 Runtime（LLM + Toolset + ContextManager + Compactor）
2. 创建 Agent 并执行 agent loop
3. 暴露 run(prompt) 一站式入口

参考：实施方案 §8.2.8
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from kosong.types import Message
from winreverse.engine.bus import ToolRegistry
from winreverse.soul.agent import Agent, AgentConfig, AgentState, Runtime
from winreverse.soul.agent_spec import AgentTypeDefinition, LaborMarket, ToolStrategy
from winreverse.soul.compaction import CompactionStrategy, Compactor, RuntimeLLMProvider
from winreverse.soul.context import ContextManager
from winreverse.soul.toolset import SoulToolsetAdapter, ToolEventCallback

logger = logging.getLogger(__name__)


class WinReverseSoul:
    """轻量级 Soul 引擎。

    组装 LLM、工具集、上下文管理器、压缩器，提供 run(prompt) 入口执行 agent loop。

    用法：
        registry = ToolRegistry()
        register_all_tools(registry)
        soul = WinReverseSoul(
            llm=my_llm_manager,
            registry=registry,
            work_dir=Path.cwd(),
        )
        result = await soul.run("分析 test.exe 的导入表")
    """

    def __init__(
        self,
        llm: Any,
        registry: ToolRegistry,
        *,
        work_dir: Path | None = None,
        session_dir: Path | None = None,
        labor_market: LaborMarket | None = None,
        default_model: str | None = None,
        default_max_turns: int = 50,
        on_tool_event: ToolEventCallback | None = None,
        max_context_size: int = 100000,
        compaction_strategy: str = "layered",
        auto_compact: bool = True,
        compaction_trigger_ratio: float = 0.8,
        on_text_event: Any = None,
        short_answer_gate: bool = False,
        min_answer_chars: int = 300,
    ) -> None:
        """初始化 Soul 引擎。

        Args:
            llm: LLM 管理器（需提供 async generate(messages, model, tools) 方法）
            registry: WinReverseAgent 工具注册中心
            work_dir: 工作目录（用于上下文加载与相对路径解析）
            session_dir: 会话目录（用于持久化日志/中间结果，默认用 work_dir/.winreverse/sessions/）
            labor_market: Agent 类型注册中心（None 表示使用默认空市场）
            default_model: 默认 LLM 模型名
            default_max_turns: 默认最大轮次
            on_tool_event: 工具调用事件回调（用于 TUI 实时更新），默认 None
            max_context_size: 上下文窗口 token 上限（自动压缩触发基准）
            compaction_strategy: 压缩策略（simple / selective / layered）
            auto_compact: 是否启用自动上下文压缩
            compaction_trigger_ratio: 触发比例（token 达窗口上限的该比例时压缩）
            short_answer_gate: 是否启用短答闸门（P0-4：非截断但无实质内容的答复补一次
                续写）。默认 False（库级静默，避免额外的 LLM 调用）；应用层（技能/REPL）
                在 WinReverseApplication 中显式打开
            min_answer_chars: 短答闸门的最短实质长度（低于此长度且无结构 → 触发续写）
        """
        self._llm = llm
        self._registry = registry
        self._work_dir = work_dir or Path.cwd()
        self._session_dir = session_dir or (self._work_dir / ".winreverse" / "sessions")
        self._labor_market = labor_market or LaborMarket()
        self._default_model = default_model
        self._default_max_turns = default_max_turns
        self._on_tool_event = on_tool_event
        self._max_context_size = max_context_size
        self._compaction_strategy = compaction_strategy
        self._auto_compact = auto_compact
        self._compaction_trigger_ratio = compaction_trigger_ratio
        self._on_text_event = on_text_event
        self.short_answer_gate = short_answer_gate
        """短答闸门开关（P0-4）——透传给每次 run 构建的 AgentConfig"""
        self.min_answer_chars = min_answer_chars
        """短答闸门最短实质长度（P0-4）"""

        # 上下文管理器
        self._context_manager = ContextManager(self._work_dir)

        # Soul 工具集适配器（桥接 ToolRegistry → kosong Tool）
        self._toolset = SoulToolsetAdapter(registry, on_tool_event=on_tool_event)

        # 上下文压缩器（包装 llm 为压缩 Provider，供总结式压缩使用）
        self._compactor = self._build_compactor()

        # Runtime（共享给所有 Agent 实例）
        self._runtime = Runtime(
            llm=llm,
            toolset=self._toolset,
            session_dir=self._session_dir,
            work_dir=self._work_dir,
            compactor=self._compactor,
        )

        self._started = False

    def _build_compactor(self) -> Compactor:
        """按配置构建压缩器（llm 可用时附带总结式压缩能力）。"""
        try:
            strategy = CompactionStrategy(self._compaction_strategy)
        except ValueError:
            logger.warning("未知压缩策略 %s，回退 layered", self._compaction_strategy)
            strategy = CompactionStrategy.LAYERED
        llm_provider = RuntimeLLMProvider(self._llm) if self._llm is not None else None
        return Compactor(
            strategy=strategy,
            max_tokens=self._max_context_size,
            llm_provider=llm_provider,
        )

    @property
    def last_agent(self) -> Agent | None:
        """最近一次 run 创建的 Agent 实例（上下文快照数据源；未运行时 None）。"""
        return getattr(self, "_last_agent", None)

    @property
    def context_manager(self) -> ContextManager:
        """上下文管理器实例。"""
        return self._context_manager

    @property
    def toolset(self) -> SoulToolsetAdapter:
        """工具集适配器实例。"""
        return self._toolset

    @property
    def labor_market(self) -> LaborMarket:
        """Agent 类型注册中心。"""
        return self._labor_market

    @property
    def runtime(self) -> Runtime:
        """Runtime 实例（供外部创建自定义 Agent 时使用）。"""
        return self._runtime

    def start(self) -> None:
        """启动 Soul 引擎（加载上下文文件）。

        首次调用时加载 work_dir 下的 KXNS.md 上下文文件。
        重复调用幂等（不会重复加载）。
        """
        if self._started:
            return
        self._context_manager.load_all()
        self._started = True
        logger.info("Soul 引擎已启动，加载 %d 条上下文", len(self._context_manager._entries))

    def set_skill_catalog_summary(self, summary: str) -> None:
        """设置 skill 目录摘要（附加到 system prompt）。"""
        self._context_manager.set_skill_catalog_summary(summary)

    def build_system_prompt(self, base_prompt: str, agent_type: str = "default") -> str:
        """构建系统提示词。

        Args:
            base_prompt: 基础提示词
            agent_type: Agent 类型（用于上下文过滤）

        Returns:
            完整系统提示词（基础提示 + skill 摘要 + 多层上下文）
        """
        # 优先使用 agent_type 对应的 system_prompt_template
        type_def = self._labor_market.get(agent_type)
        if type_def is not None and type_def.system_prompt_template:
            base_prompt = type_def.system_prompt_template

        prompt = self._context_manager.build_system_prompt(base_prompt)

        # 追加 agent_type 相关上下文
        type_context = self._context_manager.get_context_for_agent(agent_type)
        if type_context:
            prompt = f"{prompt}\n\n--- agent_type={agent_type} context ---\n{type_context}"

        return prompt

    async def run(
        self,
        prompt: str,
        *,
        agent_type: str = "default",
        system_prompt: str | None = None,
        model: str | None = None,
        max_turns: int | None = None,
        tools: list[str] | None = None,
    ) -> str:
        """执行 agent loop（一站式入口）。

        Args:
            prompt: 用户输入
            agent_type: Agent 类型（用于选择 system_prompt_template 和上下文过滤）
            system_prompt: 自定义系统提示词（覆盖 agent_type 的 template）
            model: LLM 模型名（None 用 default_model）
            max_turns: 最大轮次（None 用 default_max_turns）
            tools: 允许的工具名白名单（None 表示全部允许）

        Returns:
            Agent 最终回复文本
        """
        if not self._started:
            self.start()

        # 解析 agent_type 对应的配置
        type_def = self._labor_market.get(agent_type)
        if type_def is not None:
            effective_prompt = (
                system_prompt if system_prompt is not None else type_def.system_prompt_template
            )
            effective_model = model or type_def.default_model or self._default_model
            effective_max_turns = max_turns or self._default_max_turns
            effective_tools = tools or list(type_def.allowed_tools)
        else:
            effective_prompt = system_prompt or ""
            effective_model = model or self._default_model
            effective_max_turns = max_turns or self._default_max_turns
            effective_tools = tools or []

        # 构建完整系统提示词
        full_system_prompt = self.build_system_prompt(
            effective_prompt or "你是 WinReverseAgent，一个 Windows 原生逆向工程 AI 助手。",
            agent_type=agent_type,
        )

        # 如果指定了工具白名单，重新创建 toolset 适配器
        # ALLOWLIST 语义为 fail-closed：即使白名单为空也必须过滤（0 个工具可暴露），
        # 不得退回无过滤的共享 Runtime
        runtime = self._runtime
        if effective_tools or (
            type_def is not None and type_def.tool_strategy == ToolStrategy.ALLOWLIST
        ):
            filtered_toolset = SoulToolsetAdapter(
                self._registry,
                allowed_tools=effective_tools,
                on_tool_event=self._on_tool_event,
            )
            runtime = Runtime(
                llm=self._llm,
                toolset=filtered_toolset,
                session_dir=self._session_dir,
                work_dir=self._work_dir,
                compactor=self._compactor,
            )

        # 创建 Agent 配置
        config = AgentConfig(
            name=f"soul-{agent_type}",
            system_prompt=full_system_prompt,
            tools=effective_tools,
            model=effective_model,
            agent_type=agent_type,
            max_turns=effective_max_turns,
            max_context_size=self._max_context_size,
            compaction_strategy=self._compaction_strategy,
            auto_compact=self._auto_compact,
            compaction_trigger_ratio=self._compaction_trigger_ratio,
            short_answer_gate=self.short_answer_gate,
            min_answer_chars=self.min_answer_chars,
        )

        # 创建并运行 Agent（保留引用供 TUI 轮询上下文状态）
        agent = Agent(config, runtime)
        agent.on_assistant_text = self._on_text_event
        self._last_agent = agent
        try:
            result = await agent.run(prompt)
            return result
        except Exception as exc:
            agent.state = AgentState.FAILED
            logger.exception("Agent 运行失败: %s", agent.id)
            raise RuntimeError(f"Agent 运行失败: {exc}") from exc

    def register_agent_type(self, type_def: AgentTypeDefinition) -> None:
        """注册 agent 类型。"""
        self._labor_market.register(type_def)

    def load_agent_specs(self, spec_dir: Path) -> list[AgentTypeDefinition]:
        """批量加载 agent 类型定义。"""
        return self._labor_market.load_directory(spec_dir)

    def get_history(self, agent: Agent) -> list[Message]:
        """获取 agent 的对话历史（供外部展示或持久化）。"""
        return list(agent.messages)
