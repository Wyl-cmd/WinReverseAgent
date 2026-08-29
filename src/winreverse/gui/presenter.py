"""winreverse.gui.presenter — GUI 表单逻辑层（与渲染解耦，可单测）。

负责 GUI 需要的全部业务操作，app.py 的窗口层只做字段绑定：
- load_form / save_form：AppConfig ↔ FormModel 双向转换（走 config.settings）
- list_tools_status：外部工具 + wheel 依赖状态（供"工具管理"页展示）
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from winreverse.config.settings import (
    ensure_config_exists,
    load_config,
    save_config,
)


class LLMForm(BaseModel):
    """LLM 配置表单字段。"""

    model_config = {"validate_assignment": True}

    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = Field(default=8192, ge=256, le=200000)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)


class AgentForm(BaseModel):
    """Agent 配置表单字段。"""

    model_config = {"validate_assignment": True}

    max_turns: int = Field(default=50, ge=1, le=500)
    yolo: bool = False
    default_agent_type: str = "default"
    max_context_size: int = Field(default=100000, ge=4096, le=2000000)
    compaction_strategy: str = "layered"
    auto_compact: bool = True
    compaction_trigger_ratio: float = Field(default=0.8, ge=0.1, le=1.0)


class FormModel(BaseModel):
    """GUI 表单整体模型（LLM + Agent 两页）。

    validate_assignment 开启：GUI 层直接改属性也会触发范围校验，
    保证写入配置前表单值始终合法。
    """

    model_config = {"validate_assignment": True}

    llm: LLMForm = Field(default_factory=LLMForm)
    agent: AgentForm = Field(default_factory=AgentForm)


def load_form(config_path: Path | None = None) -> tuple[Path, FormModel]:
    """加载配置为表单模型。

    Args:
        config_path: 配置文件路径（None 用默认路径，缺失时自动创建默认配置）

    Returns:
        (实际使用的配置文件路径, 表单模型)
    """
    if config_path is not None and config_path.exists():
        config = load_config(config_path)
        resolved = config_path
    else:
        resolved, config = ensure_config_exists(config_path)
    form = FormModel(
        llm=LLMForm(
            provider=config.llm.provider,
            model=config.llm.model,
            api_key=config.llm.api_key,
            base_url=config.llm.base_url,
            max_tokens=config.llm.max_tokens,
            temperature=config.llm.temperature,
        ),
        agent=AgentForm(
            max_turns=config.agent.max_turns,
            yolo=config.agent.yolo,
            default_agent_type=config.agent.default_agent_type,
            max_context_size=config.agent.max_context_size,
            compaction_strategy=config.agent.compaction_strategy,
            auto_compact=config.agent.auto_compact,
            compaction_trigger_ratio=config.agent.compaction_trigger_ratio,
        ),
    )
    return resolved, form


def save_form(form: FormModel, config_path: Path | None = None) -> Path:
    """把表单写回配置文件。

    Returns:
        配置文件路径

    Raises:
        ValueError: 表单校验失败（pydantic 错误透传）
    """
    if config_path is not None and config_path.exists():
        config = load_config(config_path)
        resolved = config_path
    else:
        resolved, config = ensure_config_exists(config_path)

    config.llm.provider = form.llm.provider
    config.llm.model = form.llm.model
    config.llm.api_key = form.llm.api_key
    config.llm.base_url = form.llm.base_url
    config.llm.max_tokens = form.llm.max_tokens
    config.llm.temperature = form.llm.temperature
    config.agent.max_turns = form.agent.max_turns
    config.agent.yolo = form.agent.yolo
    config.agent.default_agent_type = form.agent.default_agent_type
    config.agent.max_context_size = form.agent.max_context_size
    config.agent.compaction_strategy = form.agent.compaction_strategy
    config.agent.auto_compact = form.agent.auto_compact
    config.agent.compaction_trigger_ratio = form.agent.compaction_trigger_ratio

    save_config(config, resolved)
    return resolved


def list_tools_status() -> list[dict[str, Any]]:
    """列出外部工具与 Python 依赖状态（供工具管理页展示，只读）。

    Returns:
        混合列表：每项含 name/version/installed/required/kind（tool|wheel）；
        manifest 缺失时返回空列表（不抛错，GUI 展示"未找到"）。
    """
    from winreverse.tools.updater import ToolUpdater

    project_root = Path.cwd()
    tools_manifest = project_root / "tools" / "manifest.yaml"
    items: list[dict[str, Any]] = []
    if tools_manifest.exists():
        try:
            updater = ToolUpdater(manifest_path=tools_manifest, project_root=project_root)
            for info in updater.list_installed():
                items.append(
                    {
                        "kind": "tool",
                        "name": info.name,
                        "version": info.version,
                        "installed": info.installed,
                        "required": info.required,
                    }
                )
        except Exception:
            pass
    return items


def list_wheels_status() -> list[dict[str, Any]]:
    """列出 vendor wheels 依赖状态（只读，失败时返回空列表）。"""
    from winreverse.tools.version_checker import WheelChecker

    project_root = Path.cwd()
    wheels_manifest = project_root / "vendor" / "wheels_manifest.yaml"
    wheels_dir = project_root / "vendor" / "wheels"
    items: list[dict[str, Any]] = []
    if wheels_manifest.exists():
        try:
            checker = WheelChecker(wheels_manifest=wheels_manifest, wheels_dir=wheels_dir)
            report = checker.check_all()
            for r in report.results:
                items.append(
                    {
                        "kind": "wheel",
                        "name": r.name,
                        "version": r.version,
                        "installed": r.status == "ok",
                        "required": r.required,
                        "status": r.status,
                    }
                )
        except Exception:
            pass
    return items
