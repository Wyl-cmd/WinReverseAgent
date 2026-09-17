"""winreverse.app — Agent 主入口（业务编排层）。

编排 Soul 引擎、SkillExecutor、ToolRegistry、LLM 适配器，提供：
- run_skill(): 异步执行指定 Skill
- run_repl(): 启动交互式 REPL（M6-2 实现）
- run(): 兼容 M1 骨架的同步入口（打印版本）

配置优先级：
1. 显式传入的 AppConfig（app_config 参数）
2. 显式传入的 AgentConfig（config 参数，兼容旧接口，内部转换）
3. 默认 AppConfig

设计原则：
- 保持 create_agent / run_from_config 接口兼容（不破坏 M1 测试）
- 新增 run_skill / run_repl 方法对接 Soul 引擎
- LLM 适配器可注入（测试时用 mock 替代真实 API 调用）
"""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from winreverse import __version__
from winreverse.config import AppConfig as NewAppConfig
from winreverse.config import LLMConfig, load_or_default
from winreverse.engine.bus import ToolRegistry
from winreverse.engine.tools import register_all_tools
from winreverse.skill.executor import SkillExecutor, SkillRunResult
from winreverse.skill.loader import SkillRegistry, YamlSkillLoader
from winreverse.soul.soul import WinReverseSoul

logger = logging.getLogger(__name__)


# =============================================================================
# 兼容 M1 骨架的 AgentConfig（保留 dataclass 接口）
# =============================================================================


@dataclass
class AgentConfig:
    """Agent 运行配置（M1 兼容接口）。

    保留此 dataclass 以兼容 M1 阶段的测试与调用方。
    新代码应优先使用 winreverse.config.AppConfig。

    Attributes:
        model: LLM 模型名
        api_key: LLM API Key
        work_dir: 工作目录
        yolo: 是否跳过确认（危险操作）
        max_turns: 单次会话最大轮次
    """

    model: str = ""
    api_key: str = ""
    work_dir: str = "."
    yolo: bool = False
    max_turns: int = 50

    def to_app_config(self) -> NewAppConfig:
        """转换为新的 AppConfig 实例。"""
        llm = LLMConfig(model=self.model, api_key=self.api_key)
        from winreverse.config import AgentConfig as NewAgentConfig

        agent = NewAgentConfig(
            work_dir=self.work_dir,
            yolo=self.yolo,
            max_turns=self.max_turns,
        )
        return NewAppConfig(llm=llm, agent=agent)


# =============================================================================
# Agent 主类
# =============================================================================


@dataclass
class Agent:
    """Agent 主类（业务编排层）。

    编排 Soul 引擎、SkillExecutor、ToolRegistry，提供 Skill 执行与 REPL 入口。

    Args:
        config: M1 兼容的 AgentConfig（与 app_config 二选一）
        app_config: 新的 AppConfig（优先于 config）
        llm: 可选的 LLM 对象（测试时注入 mock，None 时从 config 创建 LLMAdapter）
        work_dir: 工作目录（覆盖 config 中的值）
    """

    config: AgentConfig = field(default_factory=AgentConfig)
    app_config: NewAppConfig | None = None
    llm: Any | None = None
    work_dir: str | None = None
    _initialized: bool = field(default=False, init=False)
    _soul: Any = field(default=None, init=False)
    _executor: Any = field(default=None, init=False)
    _registry: Any = field(default=None, init=False)
    _skill_registry: Any = field(default=None, init=False)

    def __post_init__(self) -> None:
        """延迟初始化 Soul 引擎相关组件。"""
        # 避免在构造时就创建 LLM 客户端（可能失败）
        # 实际初始化在首次调用 run_skill / run_repl 时发生
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """首次调用时初始化 Soul 引擎相关组件。"""
        if self._initialized:
            return

        # 解析生效的 AppConfig
        if self.app_config is not None:
            effective_config = self.app_config
        else:
            effective_config = self.config.to_app_config()

        # 覆盖 work_dir
        if self.work_dir is not None:
            from winreverse.config import AgentConfig as NewAgentConfig

            effective_config = NewAppConfig(
                llm=effective_config.llm,
                agent=NewAgentConfig(
                    work_dir=self.work_dir,
                    skills_dir=effective_config.agent.skills_dir,
                    max_turns=effective_config.agent.max_turns,
                    yolo=effective_config.agent.yolo,
                    default_agent_type=effective_config.agent.default_agent_type,
                ),
                tools=effective_config.tools,
            )

        self._effective_config = effective_config

        # 创建 LLM 适配器（若未注入）
        if self.llm is None:
            from winreverse.llm_runtime import LLMAdapter

            self._llm_instance = LLMAdapter(effective_config.llm)
        else:
            self._llm_instance = self.llm

        # 创建工具注册中心并注册所有静态分析工具
        self._registry = ToolRegistry()
        try:
            register_all_tools(self._registry)
        except Exception as e:
            logger.warning("工具注册失败（可能已注册）: %s", e)

        # 创建 Skill 注册中心，加载 skills/ 目录
        self._skill_registry = SkillRegistry()
        work_path = Path(effective_config.agent.work_dir)
        skills_path = work_path / effective_config.agent.skills_dir
        if not skills_path.is_dir() and getattr(sys, "frozen", False):
            # PyInstaller 打包运行：cwd 下无 skills/ 时回退 exe 目录（随包分发）
            skills_path = Path(sys.executable).parent / effective_config.agent.skills_dir
        if skills_path.is_dir():
            loader = YamlSkillLoader()
            for yaml_file in sorted(skills_path.glob("*.yaml")):
                try:
                    skill = loader.load(yaml_file)
                    self._skill_registry.register(skill)
                except Exception as e:
                    logger.warning("加载 Skill %s 失败: %s", yaml_file, e)
            for yaml_file in sorted(skills_path.glob("*.yml")):
                try:
                    skill = loader.load(yaml_file)
                    self._skill_registry.register(skill)
                except Exception as e:
                    logger.warning("加载 Skill %s 失败: %s", yaml_file, e)
        else:
            logger.debug("Skill 目录不存在: %s", skills_path)

        # 创建 Soul 引擎（压缩配置从 [agent] 段透传）
        self._soul = WinReverseSoul(
            llm=self._llm_instance,
            registry=self._registry,
            work_dir=work_path,
            max_context_size=effective_config.agent.max_context_size,
            compaction_strategy=effective_config.agent.compaction_strategy,
            auto_compact=effective_config.agent.auto_compact,
            compaction_trigger_ratio=effective_config.agent.compaction_trigger_ratio,
            # P0-4 短答闸门：应用层（技能/REPL 交付路径）显式打开。
            # 现象：累计 5/23 ≈ 21.7% 的技能交付是 146–255 字符「引子式答复」
            # （只有开场句/元话术，无结论与证据）且 rc=0；Agent 库级默认关闭，
            # 因为启用后每次短答会多消耗一次 LLM 调用。
            short_answer_gate=True,
        )

        # 创建 SkillExecutor
        self._executor = SkillExecutor(
            skill_registry=self._skill_registry,
            soul=self._soul,
        )

        self._initialized = True
        logger.debug(
            "Agent 初始化完成: %d 个工具, %d 个 Skill",
            len(self._registry),
            len(self._skill_registry),
        )

    def run(self) -> int:
        """启动 Agent（M1 兼容入口）。

        M1 阶段仅打印版本号。M6-2 的 REPL 功能通过 run_repl() 方法提供。

        Returns:
            退出码（0 正常退出）
        """
        print(f"WinReverseAgent v{__version__}")
        print("输入 'winreverse run' 启动 REPL，或 'winreverse skill <name>' 执行 Skill。")
        return 0

    def run_repl(self) -> int:
        """启动交互式 REPL 主循环。

        Returns:
            退出码
        """
        self._ensure_initialized()
        print(f"WinReverseAgent v{__version__} REPL")
        print("输入消息与 Agent 对话，输入 'exit' 或 'quit' 退出。")
        print()

        while True:
            try:
                user_input = input(">>> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n再见。")
                break

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                print("再见。")
                break

            try:
                answer = asyncio.run(self._soul.run(user_input))
                print()
                print(answer)
                print()
            except Exception as e:
                print(f"\n[错误] Agent 执行失败: {e}\n")

        return 0

    async def run_skill(
        self,
        skill_name: str,
        parameters: dict[str, Any] | None = None,
    ) -> SkillRunResult:
        """异步执行指定 Skill。

        Args:
            skill_name: Skill 名称
            parameters: 传入参数

        Returns:
            SkillRunResult 包含最终回复与预置流结果

        Raises:
            SkillNotFoundError: Skill 未注册
            SkillExecutionError: 执行失败
        """
        self._ensure_initialized()
        return cast(SkillRunResult, await self._executor.run(skill_name, parameters or {}))

    def run_skill_sync(
        self,
        skill_name: str,
        parameters: dict[str, Any] | None = None,
    ) -> SkillRunResult:
        """同步执行指定 Skill（封装异步调用）。

        Args:
            skill_name: Skill 名称
            parameters: 传入参数

        Returns:
            SkillRunResult
        """
        return asyncio.run(self.run_skill(skill_name, parameters))

    def shutdown(self) -> None:
        """清理资源。"""
        if self._initialized and hasattr(self, "_llm_instance"):
            llm = getattr(self, "_llm_instance", None)
            if llm is not None and hasattr(llm, "close"):
                try:
                    asyncio.run(llm.close())
                except Exception as e:
                    logger.debug("LLM 关闭异常: %s", e)
        self._initialized = False


# =============================================================================
# 工厂函数
# =============================================================================


def create_agent(config: AgentConfig | None = None) -> Agent:
    """工厂函数：创建 Agent 实例。

    Args:
        config: 配置对象，None 时用默认配置

    Returns:
        Agent 实例
    """
    if config is None:
        config = AgentConfig()
    return Agent(config=config)


def create_agent_from_config(app_config: NewAppConfig) -> Agent:
    """从 AppConfig 创建 Agent 实例。

    Args:
        app_config: 应用配置

    Returns:
        Agent 实例
    """
    return Agent(app_config=app_config)


def create_agent_from_config_file(config_path: Path | None = None) -> Agent:
    """从 config.toml 文件创建 Agent 实例。

    Args:
        config_path: 配置文件路径，None 时用默认路径

    Returns:
        Agent 实例
    """
    app_config = load_or_default(config_path)
    return create_agent_from_config(app_config)


def run_from_config(config_dict: dict[str, Any]) -> int:
    """从配置字典启动 Agent（M1 兼容接口）。

    Args:
        config_dict: 配置字典

    Returns:
        退出码
    """
    config = AgentConfig(
        model=config_dict.get("model", ""),
        api_key=config_dict.get("api_key", ""),
        work_dir=config_dict.get("work_dir", "."),
        yolo=config_dict.get("yolo", False),
        max_turns=config_dict.get("max_turns", 50),
    )
    agent = create_agent(config)
    return agent.run()
