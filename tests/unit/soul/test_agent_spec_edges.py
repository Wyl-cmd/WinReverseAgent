"""测试模块：winreverse.soul.agent_spec 边界分支（独立新文件，不动既有用例）。

覆盖点：agent 包裹字段非映射、system_prompt_path 三态（可读/缺失警告/不可读
收敛为 AgentSpecError）、allowed_tools 非列表标量归空、load_directory 的 .yml
扩展名与坏文件跳过。模块仅依赖 PyYAML，平台无关，Linux 可直接实跑。
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from winreverse.soul.agent_spec import (
    AgentSpecError,
    LaborMarket,
    load_agent_spec,
)


class TestLoadAgentSpecEdges:
    """load_agent_spec 的结构与提示文件边界。"""

    def test_agent_wrapper_non_mapping_raises(self, tmp_path: Path) -> None:
        """{agent: <非映射>} 包裹结构 → AgentSpecError「应为映射」。"""
        spec = tmp_path / "bad.yaml"
        spec.write_text("agent: 42\n", encoding="utf-8")
        with pytest.raises(AgentSpecError, match="应为映射"):
            load_agent_spec(spec)

    def test_system_prompt_path_file_is_loaded(self, tmp_path: Path) -> None:
        """system_prompt_path 指向存在文件 → 读入内容作为模板。"""
        (tmp_path / "prompt.md").write_text("你是 {{target}} 分析员", encoding="utf-8")
        spec = tmp_path / "agent.yaml"
        spec.write_text(
            "name: pe-analyst\nsystem_prompt_path: prompt.md\n",
            encoding="utf-8",
        )
        type_def = load_agent_spec(spec)
        assert type_def.system_prompt_template == "你是 {{target}} 分析员"

    def test_system_prompt_path_missing_warns_and_empty_template(
        self,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """system_prompt_path 文件不存在 → 模板为空串并记录 warning。"""
        spec = tmp_path / "agent.yaml"
        spec.write_text(
            "name: pe-analyst\nsystem_prompt_path: absent.md\n",
            encoding="utf-8",
        )
        with caplog.at_level(logging.WARNING, logger="winreverse.soul.agent_spec"):
            type_def = load_agent_spec(spec)
        assert type_def.system_prompt_template == ""
        assert any("System prompt file not found" in rec.message for rec in caplog.records)

    def test_system_prompt_path_unreadable_raises(self, tmp_path: Path) -> None:
        """system_prompt_path 指向目录（read_text 抛 OSError）→ 收敛为 AgentSpecError。"""
        (tmp_path / "prompt.d").mkdir()
        spec = tmp_path / "agent.yaml"
        spec.write_text(
            "name: pe-analyst\nsystem_prompt_path: prompt.d\n",
            encoding="utf-8",
        )
        with pytest.raises(AgentSpecError, match="无法读取系统提示文件"):
            load_agent_spec(spec)

    def test_allowed_tools_non_list_scalar_becomes_empty(self, tmp_path: Path) -> None:
        """allowed_tools 为标量字符串（非列表）→ 归一为空元组。"""
        spec = tmp_path / "agent.yaml"
        spec.write_text(
            "name: pe-analyst\ndescription: x\nallowed_tools: pe_reader\n",
            encoding="utf-8",
        )
        type_def = load_agent_spec(spec)
        assert type_def.allowed_tools == ()


class TestLaborMarketYmlDirectory:
    """LaborMarket.load_directory 的 .yml 扩展名与坏文件跳过。"""

    def test_loads_yml_and_skips_invalid(self, tmp_path: Path) -> None:
        """*.yml 与 *.yaml 一并加载；缺 name 的坏文件跳过且不中断。"""
        (tmp_path / "a.yaml").write_text("name: alpha\ndescription: A\n", encoding="utf-8")
        (tmp_path / "b.yml").write_text(
            "name: beta\ndescription: B\ntool_strategy: allowlist\nallowed_tools:\n  - t1\n",
            encoding="utf-8",
        )
        (tmp_path / "broken.yml").write_text("description: 没有 name\n", encoding="utf-8")
        market = LaborMarket()
        loaded = market.load_directory(tmp_path)
        assert [t.name for t in loaded] == ["alpha", "beta"]
        assert market.get("beta") is not None
        assert market.get("beta").allowed_tools == ("t1",)  # type: ignore[union-attr]
