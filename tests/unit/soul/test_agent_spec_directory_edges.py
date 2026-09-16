"""测试模块：winreverse.soul.agent_spec（目录加载与提示来源优先级）

覆盖点：load_directory 遇到名为 *.yaml 的目录（glob 命中非文件）按坏文件跳过、
system_prompt_path 与 system_prompt 内联同时给出时外部文件优先、
LaborMarket.load_spec 加载即注册（get/require 可查）。
"""

from __future__ import annotations

from pathlib import Path

import yaml

from winreverse.soul.agent_spec import (
    AgentTypeDefinition,
    LaborMarket,
    ToolStrategy,
    load_agent_spec,
)


def _write_spec(path: Path, name: str = "agent-a") -> None:
    path.write_text(
        yaml.safe_dump({"name": name, "description": "demo"}),
        encoding="utf-8",
    )


def test_load_directory_skips_directory_named_yaml(tmp_path: Path) -> None:
    """glob('*.yaml') 也会命中目录：目录项触发 'not a file' AgentSpecError 被跳过，不崩。"""
    _write_spec(tmp_path / "real.yaml", "real-agent")
    (tmp_path / "fake.yaml").mkdir()

    market = LaborMarket()
    loaded = market.load_directory(tmp_path)

    assert [d.name for d in loaded] == ["real-agent"]
    assert market.get("fake") is None


def test_system_prompt_path_takes_precedence_over_inline(tmp_path: Path) -> None:
    """system_prompt_path 与内联 system_prompt 同时存在：外部文件内容胜出。"""
    (tmp_path / "prompt.md").write_text("FROM FILE", encoding="utf-8")
    spec_path = tmp_path / "spec.yaml"
    spec_path.write_text(
        yaml.safe_dump(
            {
                "name": "dual-source",
                "description": "d",
                "system_prompt": "FROM INLINE",
                "system_prompt_path": "prompt.md",
            }
        ),
        encoding="utf-8",
    )

    type_def = load_agent_spec(spec_path)
    assert type_def.system_prompt_template == "FROM FILE"


def test_load_spec_registers_into_market(tmp_path: Path) -> None:
    """load_spec 加载并注册：get 返回同一实例，require 可查，list_types 含它。"""
    _write_spec(tmp_path / "solo.yaml", "solo-agent")
    market = LaborMarket()

    type_def = market.load_spec(tmp_path / "solo.yaml")

    assert market.get("solo-agent") is type_def
    assert market.require("solo-agent") is type_def
    assert market.list_types() == [type_def]


def test_spec_defaults_roundtrip() -> None:
    """slots 冻结数据类的默认值与枚举策略往返稳定。"""
    type_def = AgentTypeDefinition(name="n", description="d")
    assert type_def.tool_strategy is ToolStrategy.INHERIT
    assert type_def.allowed_tools == ()
    assert type_def.supports_background is True
    assert type_def.default_model is None
