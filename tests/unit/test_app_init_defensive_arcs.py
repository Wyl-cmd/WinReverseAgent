"""被测模块: winreverse.app（Agent._ensure_initialized 防御弧）。

覆盖点（对照 coverage_guest.xml 真机缺口）: app.py:122 app_config=None 且未传
work_dir 覆盖时走 M1 AgentConfig.to_app_config() 兜底；app.py:154-155
register_all_tools 抛异常仅告警不中断初始化；app.py:176-177 .yml Skill 加载抛
异常仅告警且同目录 .yaml 正常注册。winreverse.app 导入链缺 yara 等 Windows
运行时依赖 → Linux 下如实报 collection error（基线接受态），待实机实跑回填。
"""

from __future__ import annotations

import logging
from pathlib import Path

import winreverse.app as app_module
from winreverse.app import Agent
from winreverse.app import AgentConfig as M1AgentConfig


def _make_agent(tmp_path: Path) -> Agent:
    """构造 llm 注入、config 走 M1 兼容层、work_dir 指向 tmp 的 Agent。"""
    return Agent(
        config=M1AgentConfig(model="m1-model", api_key="sk-1", work_dir=str(tmp_path)),
        llm=object(),
    )


class TestLegacyConfigFallback:
    """app.py:122 — app_config 为 None 且无 work_dir 覆盖时的兜底映射。"""

    def test_agent_config_to_app_config_fallback(self, tmp_path: Path) -> None:
        agent = _make_agent(tmp_path)
        agent._ensure_initialized()
        effective = agent._effective_config
        assert effective.agent.work_dir == str(tmp_path)
        assert effective.llm.model == "m1-model"
        assert effective.llm.api_key == "sk-1"
        assert agent._initialized is True


class TestRegisterAllToolsTolerance:
    """app.py:154-155 — 工具注册抛异常时仅告警，初始化继续。"""

    def test_register_failure_logs_warning_and_continues(
        self, tmp_path: Path, monkeypatch, caplog
    ) -> None:
        def _boom(registry):
            raise RuntimeError("boom-registration")

        monkeypatch.setattr(app_module, "register_all_tools", _boom)
        agent = _make_agent(tmp_path)
        with caplog.at_level(logging.WARNING, logger="winreverse.app"):
            agent._ensure_initialized()
        assert agent._initialized is True
        warns = [r for r in caplog.records if "工具注册失败" in r.getMessage()]
        assert len(warns) == 1
        assert "boom-registration" in warns[0].getMessage()


class TestYmlLoadFailureTolerance:
    """app.py:176-177 — .yml 加载抛异常仅告警，同目录 .yaml 正常注册。"""

    def test_yml_load_failure_warns_but_yaml_registers(
        self, tmp_path: Path, monkeypatch, caplog
    ) -> None:
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir()
        (skills_dir / "good.yaml").write_text(
            'name: yml_arc_good\ndescription: "yaml 正常路径"\n', encoding="utf-8"
        )
        (skills_dir / "bad.yml").write_text(
            'name: yml_arc_bad\ndescription: "yml 异常路径"\n', encoding="utf-8"
        )
        real_load = app_module.YamlSkillLoader.load

        def _load(self, yaml_file):
            if Path(yaml_file).suffix == ".yml":
                raise ValueError("yml-boom")
            return real_load(self, yaml_file)

        monkeypatch.setattr(app_module.YamlSkillLoader, "load", _load)
        agent = _make_agent(tmp_path)
        with caplog.at_level(logging.WARNING, logger="winreverse.app"):
            agent._ensure_initialized()
        names = {s["name"] for s in agent._skill_registry.list_skills()}
        assert "yml_arc_good" in names
        assert "yml_arc_bad" not in names
        warns = [r for r in caplog.records if "加载 Skill" in r.getMessage()]
        assert len(warns) == 1
        assert "bad.yml" in warns[0].getMessage()
        assert "yml-boom" in warns[0].getMessage()
