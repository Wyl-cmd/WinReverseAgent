"""winreverse.tui.screens.llm_config — LLM 配置页面。

提供 LLM 相关配置项的查看与编辑：
- Provider 选择（anthropic/openai/deepseek/google/ollama）
- 模型 ID
- API Key（密码模式输入，留空则从环境变量读取）
- Base URL（OpenAI 协议兼容端点，如 https://api.moonshot.cn/v1）
- Max Tokens（最大输出 token 数）
- Temperature（采样温度 0.0-2.0）

编辑后通过 apply_to_config() 方法应用到 AppConfig，由 SettingsApp.action_save() 统一保存。

参考：实施方案 §9.3
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container
from textual.widgets import Input, Label, Select, Static

from winreverse.config import AppConfig, LLMConfig

# Provider 选项列表（label, value）—— Textual Select 要求 (label, value) 顺序


class LLMConfigPane(Container):
    """LLM 配置页面。

    显示并编辑 LLM 相关配置项，通过 apply_to_config() 将界面值回写到 AppConfig。

    Attributes:
        config: 应用配置（用于初始化界面值）
    """

    DEFAULT_CSS = """
    LLMConfigPane {
        padding: 1 2;
    }
    LLMConfigPane Label {
        width: 16;
        height: 1;
        margin: 1 0 0 0;
    }
    LLMConfigPane Input {
        width: 1fr;
        margin: 0 0 1 0;
    }
    LLMConfigPane Select {
        width: 1fr;
        margin: 0 0 1 0;
    }
    LLMConfigPane #field-help {
        color: $text-muted;
        margin: 0 0 1 0;
    }
    """

    def __init__(self, config: AppConfig) -> None:
        """初始化 LLM 配置页面。

        Args:
            config: 应用配置（从中读取 llm 段初始化界面值）
        """
        super().__init__()
        self.config = config

    def compose(self) -> ComposeResult:
        """构建表单布局。"""
        llm = self.config.llm
        yield Static("[bold]LLM 配置[/bold]", id="title")
        yield Static(
            "LLM 走 OpenAI 协议（/v1/chat/completions），国内模型均兼容。按 Ctrl+S 或 's' 保存。",
            id="field-help",
        )

        yield Label("模型 ID", id="lbl-model")
        yield Input(value=llm.model, id="model", placeholder="如 kimi-k2 / deepseek-chat / gpt-4o")

        yield Label("API Key", id="lbl-api-key")
        yield Input(
            value=llm.api_key,
            id="api-key",
            password=True,
            placeholder="留空则从环境变量读取",
        )

        yield Label("Base URL", id="lbl-base-url")
        yield Input(
            value=llm.base_url,
            id="base-url",
            placeholder="OpenAI 协议兼容端点（如 https://api.moonshot.cn/v1）",
        )

        yield Label("Max Tokens", id="lbl-max-tokens")
        yield Input(
            value=str(llm.max_tokens),
            id="max-tokens",
            type="integer",
            placeholder="如 8192",
        )

        yield Label("Temperature", id="lbl-temperature")
        yield Input(
            value=str(llm.temperature),
            id="temperature",
            type="number",
            placeholder="0.0 - 2.0",
        )

    def apply_to_config(self, config: AppConfig) -> None:
        """将界面中的配置值回写到 AppConfig。

        Args:
            config: 待更新的 AppConfig 实例（原地修改）
        """
        config.llm = LLMConfig(
            provider="openai",
            model=self._get_input_value("model", config.llm.model),
            api_key=self._get_input_value("api-key", config.llm.api_key),
            base_url=self._get_input_value("base-url", config.llm.base_url),
            max_tokens=self._get_int_value("max-tokens", config.llm.max_tokens),
            temperature=self._get_float_value("temperature", config.llm.temperature),
        )

    def _get_input_value(self, widget_id: str, default: str) -> str:
        """安全读取 Input widget 的值。"""
        try:
            widget = self.query_one(f"#{widget_id}", Input)
            return widget.value
        except Exception:
            return default

    def _get_select_value(self, widget_id: str, default: str) -> str:
        """安全读取 Select widget 的值。"""
        try:
            widget = self.query_one(f"#{widget_id}", Select)
            value = widget.value
            if isinstance(value, str) and value:
                return value
            return default
        except Exception:
            return default

    def _get_int_value(self, widget_id: str, default: int) -> int:
        """安全读取整数 Input 的值。"""
        raw = self._get_input_value(widget_id, str(default))
        try:
            return int(raw)
        except ValueError:
            return default

    def _get_float_value(self, widget_id: str, default: float) -> float:
        """安全读取浮点数 Input 的值。"""
        raw = self._get_input_value(widget_id, str(default))
        try:
            return float(raw)
        except ValueError:
            return default
