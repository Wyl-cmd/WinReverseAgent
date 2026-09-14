"""kosong.providers.descriptors — 提供商与模型描述符基类。

Descriptor-First 架构的数据契约：
- ProviderCapabilities: 提供商能力位（工具调用 / 视觉 / 流式 / 系统消息 / 缓存）
- ModelDescriptor: 单个模型的元信息（上下文窗口 / 出参上限 / 千 token 价格）
- ProviderDescriptor: 提供商描述（API 端点 / Key 环境变量 / 模型清单）

各厂商描述符（anthropic/deepseek/google/ollama/openai）基于此构建，
ProviderRegistry 据此路由，ProviderRuntime 据此构造 HTTP 客户端。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProviderCapabilities:
    """提供商能力位。

    Attributes:
        supports_tools: 是否支持工具调用（function calling）
        supports_vision: 是否支持图像输入
        supports_streaming: 是否支持流式输出
        supports_system_messages: 是否支持独立 system 消息
        supports_prompt_caching: 是否支持提示词缓存
    """

    supports_tools: bool
    supports_vision: bool
    supports_streaming: bool
    supports_system_messages: bool
    supports_prompt_caching: bool


@dataclass
class ModelDescriptor:
    """单个模型的描述。

    Attributes:
        id: 模型 ID（API 调用用，如 'gpt-4o'）
        display_name: 展示名（TUI/CLI 显示用）
        context_window: 上下文窗口（token 数）
        max_output_tokens: 单次响应最大输出 token 数
        supports_tools: 该模型是否支持工具调用
        supports_vision: 该模型是否支持图像输入
        supports_streaming: 该模型是否支持流式输出
        input_price_per_million: 输入价格（美元 / 百万 token）
        output_price_per_million: 输出价格（美元 / 百万 token）
    """

    id: str
    display_name: str
    context_window: int
    max_output_tokens: int
    supports_tools: bool
    supports_vision: bool
    supports_streaming: bool
    input_price_per_million: float
    output_price_per_million: float


@dataclass
class ProviderDescriptor:
    """提供商描述。

    Attributes:
        name: 提供商唯一标识（如 'openai'、'anthropic'）
        display_name: 展示名
        api_base: API 基础端点
        api_key_env: API Key 的环境变量名
        models: 该提供商提供的模型清单
        capabilities: 提供商能力位
        default_headers: 附加请求头（如 anthropic-version）
    """

    name: str
    display_name: str
    api_base: str
    api_key_env: str
    models: list[ModelDescriptor]
    capabilities: ProviderCapabilities
    default_headers: dict[str, str] = field(default_factory=dict)


__all__ = [
    "ModelDescriptor",
    "ProviderCapabilities",
    "ProviderDescriptor",
]
