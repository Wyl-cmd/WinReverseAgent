"""winreverse.config.settings — 配置系统实现（config.toml + Pydantic 验证）。

功能：
- 定义 LLM / Agent / Tools 三段配置 schema（Pydantic BaseModel）
- load_config: 从 config.toml 加载并验证
- save_config: 序列化为 config.toml（保留注释与格式）
- ensure_config_exists: 首次启动时创建默认配置文件
- 环境变量覆盖：API Key 等敏感字段支持从环境变量读取

配置文件结构（config.toml）：
    [llm]
    provider = "openai"           # 固定 OpenAI 协议（国内模型均兼容）
    model = ""                    # 填模型 ID，如 kimi-k2 / deepseek-chat / gpt-4o
    api_key = ""                  # 留空则从环境变量 OPENAI_API_KEY 读取
    base_url = ""                 # OpenAI 协议兼容端点（如 https://api.moonshot.cn/v1）
    max_tokens = 8192
    temperature = 0.7

    [agent]
    work_dir = "."
    skills_dir = "skills"
    max_turns = 50
    yolo = false
    default_agent_type = "default"

    [tools]
    tools_dir = "tools"
    verify_on_startup = true

设计原则：
- 不引入 pydantic-settings（避免额外依赖），用 tomlkit + pydantic 手动桥接
- 配置文件可选，缺失时使用默认值并自动创建
- 敏感字段（api_key）支持环境变量覆盖，避免硬编码到文件

参考：实施方案 §6.1 配置系统
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import tomlkit
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

# =============================================================================
# 默认值常量
# =============================================================================

_DEFAULT_CONFIG_FILENAME = "config.toml"
_DEFAULT_LLM_PROVIDER = "openai"
_DEFAULT_LLM_MODEL = ""
_DEFAULT_MAX_TOKENS = 8192
_DEFAULT_TEMPERATURE = 0.7
_DEFAULT_MAX_TURNS = 50
_DEFAULT_WORK_DIR = "."
_DEFAULT_SKILLS_DIR = "skills"
_DEFAULT_TOOLS_DIR = "tools"
_DEFAULT_AGENT_TYPE = "default"
_DEFAULT_VERIFY_ON_STARTUP = True

# Provider → 环境变量名映射（用于 api_key 留空时自动读取）
_PROVIDER_API_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "google": "GOOGLE_API_KEY",
    "ollama": "OLLAMA_API_KEY",  # ollama 通常无需 key，但保留映射
}


class ConfigError(Exception):
    """配置加载/保存/验证异常。"""


# =============================================================================
# 配置模型（Pydantic BaseModel）
# =============================================================================


class LLMConfig(BaseModel):
    """LLM 配置。

    Attributes:
        provider: 提供商名称（anthropic/openai/deepseek/google/ollama）
        model: 模型 ID（如 kimi-k2 / deepseek-chat / gpt-4o）
        api_key: API Key（留空则从环境变量读取）
        base_url: 自定义 API 基础 URL（留空则用 provider 默认值）
        max_tokens: 单次响应最大 token 数
        temperature: 采样温度（0.0-2.0）
    """

    provider: str = Field(default=_DEFAULT_LLM_PROVIDER, description="LLM 提供商")
    model: str = Field(default=_DEFAULT_LLM_MODEL, description="模型 ID")
    api_key: str = Field(default="", description="API Key（留空则从环境变量读取）")
    base_url: str = Field(default="", description="OpenAI 协议兼容端点（留空用官方端点）")
    max_tokens: int = Field(default=_DEFAULT_MAX_TOKENS, ge=1, description="最大 token 数")
    temperature: float = Field(default=_DEFAULT_TEMPERATURE, ge=0.0, le=2.0, description="采样温度")

    def resolve_api_key(self) -> str:
        """解析实际的 API Key。

        优先级：配置文件中的 api_key > 环境变量 > 空字符串。

        Returns:
            API Key 字符串（可能为空）
        """
        if self.api_key.strip():
            return self.api_key.strip()
        env_var = _PROVIDER_API_KEY_ENV.get(self.provider, "")
        if env_var:
            return os.environ.get(env_var, "")
        return ""


class AgentConfig(BaseModel):
    """Agent 运行配置。

    Attributes:
        work_dir: 工作目录（相对路径相对于配置文件所在目录）
        skills_dir: Skill YAML 文件目录
        max_turns: 单次会话最大轮次
        yolo: 是否跳过危险操作确认
        default_agent_type: 默认 agent 类型
        max_context_size: 上下文窗口 token 上限（自动压缩触发基准）
        compaction_strategy: 上下文压缩策略（simple / selective / layered）
        auto_compact: 是否启用自动上下文压缩
        compaction_trigger_ratio: 压缩触发比例（token 达窗口上限的该比例时触发）
    """

    work_dir: str = Field(default=_DEFAULT_WORK_DIR, description="工作目录")
    skills_dir: str = Field(default=_DEFAULT_SKILLS_DIR, description="Skill 目录")
    max_turns: int = Field(default=_DEFAULT_MAX_TURNS, ge=1, le=500, description="单次会话最大轮次")
    yolo: bool = Field(default=False, description="跳过危险操作确认")
    default_agent_type: str = Field(default=_DEFAULT_AGENT_TYPE, description="默认 agent 类型")
    max_context_size: int = Field(
        default=100000, ge=4096, le=2000000, description="上下文窗口 token 上限"
    )
    compaction_strategy: str = Field(
        default="layered", description="上下文压缩策略（simple/selective/layered）"
    )
    auto_compact: bool = Field(default=True, description="启用自动上下文压缩")
    compaction_trigger_ratio: float = Field(default=0.8, ge=0.1, le=1.0, description="压缩触发比例")


class ToolsConfig(BaseModel):
    """外部工具配置。

    Attributes:
        tools_dir: 外部工具二进制目录（tshark/yara/die 等）
        verify_on_startup: 启动时是否校验工具完整性
    """

    tools_dir: str = Field(default=_DEFAULT_TOOLS_DIR, description="外部工具目录")
    verify_on_startup: bool = Field(
        default=_DEFAULT_VERIFY_ON_STARTUP, description="启动时校验工具完整性"
    )


class AppConfig(BaseModel):
    """应用主配置（聚合 LLM/Agent/Tools 三段）。

    Attributes:
        llm: LLM 配置
        agent: Agent 运行配置
        tools: 外部工具配置
    """

    llm: LLMConfig = Field(default_factory=LLMConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)


# =============================================================================
# 配置文件路径解析
# =============================================================================


def get_default_config_path() -> Path:
    """获取默认配置文件路径。

    查找顺序：
    1. 便携包（PyInstaller frozen）：exe 所在目录（随包读写、重打包保留）
    2. 当前工作目录下的 config.toml
    3. 用户主目录下的 ~/.winreverse/config.toml

    Returns:
        优先使用的配置文件路径（不一定存在）
    """
    import sys as _sys

    if getattr(_sys, "frozen", False):
        return Path(_sys.executable).parent / _DEFAULT_CONFIG_FILENAME
    cwd_config = Path.cwd() / _DEFAULT_CONFIG_FILENAME
    if cwd_config.exists():
        return cwd_config
    home_config = Path.home() / ".winreverse" / _DEFAULT_CONFIG_FILENAME
    return home_config


def ensure_config_exists(path: Path | None = None) -> tuple[Path, AppConfig]:
    """确保配置文件存在，不存在则创建默认配置。

    Args:
        path: 指定配置文件路径，None 则用 get_default_config_path()

    Returns:
        (配置文件路径, 加载的 AppConfig)
    """
    config_path = path or get_default_config_path()
    if config_path.exists():
        return config_path, load_config(config_path)
    # 创建默认配置
    config = AppConfig()
    save_config(config, config_path)
    logger.info("已创建默认配置文件: %s", config_path)
    return config_path, config


# =============================================================================
# 配置加载与保存
# =============================================================================


def load_config(path: Path | None = None) -> AppConfig:
    """从 config.toml 加载配置。

    Args:
        path: 配置文件路径，None 则用 get_default_config_path()

    Returns:
        AppConfig 实例

    Raises:
        ConfigError: 文件不存在、TOML 语法错误或字段验证失败
    """
    config_path = path or get_default_config_path()
    if not config_path.exists():
        logger.debug("配置文件不存在，使用默认值: %s", config_path)
        return AppConfig()

    try:
        with open(config_path, encoding="utf-8") as f:
            raw_text = f.read()
        data: dict[str, Any] = tomlkit.parse(raw_text)
        # tomlkit 返回的容器类型转换为原生 dict/list 以兼容 pydantic
        data = _tomlkit_to_native(data)
    except OSError as e:
        raise ConfigError(f"无法读取配置文件 {config_path}: {e}") from e
    except Exception as e:
        raise ConfigError(f"配置文件 TOML 语法错误 {config_path}: {e}") from e

    try:
        return AppConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigError(f"配置文件字段验证失败 {config_path}: {e}") from e


def save_config(config: AppConfig, path: Path | None = None) -> None:
    """保存配置到 config.toml。

    Args:
        config: AppConfig 实例
        path: 目标路径，None 则用 get_default_config_path()

    Raises:
        ConfigError: 写入失败
    """
    config_path = path or get_default_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # 构建 TOML 文档（带注释）
    doc = tomlkit.document()
    doc.add(tomlkit.comment("WinReverseAgent 配置文件"))
    doc.add(tomlkit.comment("首次启动时自动生成，可手动编辑后重启生效"))
    doc.add(tomlkit.nl())

    # [llm] 段
    llm_table = tomlkit.table()
    llm_table.add(tomlkit.comment("LLM 提供商与模型配置"))
    llm_table.add("provider", config.llm.provider)
    llm_table.add("model", config.llm.model)
    llm_table.add(tomlkit.comment("api_key 留空则从环境变量读取（如 ANTHROPIC_API_KEY）"))
    llm_table.add("api_key", config.llm.api_key)
    llm_table.add(tomlkit.comment("base_url = OpenAI 协议兼容端点（国内模型均支持）"))
    llm_table.add("base_url", config.llm.base_url)
    llm_table.add("max_tokens", config.llm.max_tokens)
    llm_table.add("temperature", config.llm.temperature)
    doc.add("llm", llm_table)
    doc.add(tomlkit.nl())

    # [agent] 段
    agent_table = tomlkit.table()
    agent_table.add(tomlkit.comment("Agent 运行配置"))
    agent_table.add("work_dir", config.agent.work_dir)
    agent_table.add("skills_dir", config.agent.skills_dir)
    agent_table.add("max_turns", config.agent.max_turns)
    agent_table.add(tomlkit.comment("yolo=true 跳过危险操作确认（不推荐生产环境使用）"))
    agent_table.add("yolo", config.agent.yolo)
    agent_table.add("default_agent_type", config.agent.default_agent_type)
    agent_table.add(tomlkit.comment("上下文窗口 token 上限（自动压缩触发基准）"))
    agent_table.add("max_context_size", config.agent.max_context_size)
    agent_table.add(tomlkit.comment("上下文压缩策略：simple / selective / layered"))
    agent_table.add("compaction_strategy", config.agent.compaction_strategy)
    agent_table.add(tomlkit.comment("是否启用自动上下文压缩"))
    agent_table.add("auto_compact", config.agent.auto_compact)
    agent_table.add(tomlkit.comment("压缩触发比例（token 达窗口上限的该比例时触发）"))
    agent_table.add("compaction_trigger_ratio", config.agent.compaction_trigger_ratio)
    doc.add("agent", agent_table)
    doc.add(tomlkit.nl())

    # [tools] 段
    tools_table = tomlkit.table()
    tools_table.add(tomlkit.comment("外部工具配置（tshark/yara/die 等）"))
    tools_table.add("tools_dir", config.tools.tools_dir)
    tools_table.add("verify_on_startup", config.tools.verify_on_startup)
    doc.add("tools", tools_table)

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(tomlkit.dumps(doc))
    except OSError as e:
        raise ConfigError(f"无法写入配置文件 {config_path}: {e}") from e


def _tomlkit_to_native(obj: Any) -> Any:
    """将 tomlkit 容器递归转换为原生 Python 类型。

    tomlkit 返回的 Table/Array/String 等容器类型在某些场景下
    与 pydantic 验证不兼容，转换为原生 dict/list/str。

    Args:
        obj: tomlkit 解析结果

    Returns:
        原生 Python 对象
    """
    if isinstance(obj, dict):
        return {k: _tomlkit_to_native(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_tomlkit_to_native(item) for item in obj]
    # tomlkit 的 String/Integer/Float/Boolean 都是 str/int/float/bool 子类
    # 直接返回即可（pydantic 能识别）
    return obj


# =============================================================================
# 便捷工厂函数
# =============================================================================


def create_default_config() -> AppConfig:
    """创建默认配置实例。"""
    return AppConfig()


def load_or_default(path: Path | None = None) -> AppConfig:
    """加载配置，失败时返回默认值（不抛异常）。

    用于启动时优雅降级：配置文件损坏时仍能用默认配置启动。

    Args:
        path: 配置文件路径

    Returns:
        AppConfig 实例（加载失败时为默认值）
    """
    try:
        return load_config(path)
    except ConfigError as e:
        logger.warning("配置加载失败，使用默认值: %s", e)
        return AppConfig()
