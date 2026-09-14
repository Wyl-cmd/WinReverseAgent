"""kosong — LLM 抽象层（Descriptor-First 提供商架构，自 KXNS 复用）。

对外统一出口：
- generate: 流式补全入口（自动区分 anthropic / OpenAI 协议）
- ProviderRuntime / ProviderRegistry / OpenAIShim: 运行时与协议桥
- types: 消息 / 内容分片 / 工具调用 / 用量等数据契约
- providers.descriptors: 提供商与模型描述符基类
"""

from __future__ import annotations

from kosong.generate import generate
from kosong.providers.descriptors import (
    ModelDescriptor,
    ProviderCapabilities,
    ProviderDescriptor,
)
from kosong.providers.registry import ProviderRegistry
from kosong.providers.runtime import ProviderRuntime
from kosong.providers.shim import OpenAIShim
from kosong.types import (
    AudioURLPart,
    ContentPart,
    GenerateResult,
    ImageURLPart,
    Message,
    MessageRole,
    TextPart,
    ThinkPart,
    TokenUsage,
    Tool,
    ToolCall,
    ToolCallPart,
    ToolParameter,
    ToolResult,
    Usage,
    VideoURLPart,
)

__all__ = [
    "AudioURLPart",
    "ContentPart",
    "GenerateResult",
    "ImageURLPart",
    "Message",
    "MessageRole",
    "ModelDescriptor",
    "OpenAIShim",
    "ProviderCapabilities",
    "ProviderDescriptor",
    "ProviderRegistry",
    "ProviderRuntime",
    "TextPart",
    "ThinkPart",
    "TokenUsage",
    "Tool",
    "ToolCall",
    "ToolCallPart",
    "ToolParameter",
    "ToolResult",
    "Usage",
    "VideoURLPart",
    "generate",
]
