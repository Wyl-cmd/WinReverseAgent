"""被测模块: winreverse.cli list_skills_command（list-skills 命令编排回归）。

覆盖点: NoneType 崩溃回归锁——`agent._skill_registry.list_skills()` 前必须先
`_ensure_initialized()`（Agent 惰性初始化契约，缺失时 registry 为 None 即
AttributeError）；空 Skill 注册表的降级提示。仅依赖 winreverse.cli（Linux 可跑），
与 test_cli_list_skills_regression.py（直连 winreverse.app）互补。
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

import winreverse.cli as cli


class _FakeRegistry:
    def __init__(self, skills: list[dict[str, str]]) -> None:
        self._skills = skills

    def list_skills(self) -> list[dict[str, str]]:
        return self._skills


class _FakeAgent:
    """复刻 Agent 惰性初始化契约：构造后 _skill_registry 为 None。"""

    def __init__(self, skills: list[dict[str, str]]) -> None:
        self._skill_registry: _FakeRegistry | None = None
        self.ensure_calls = 0
        self._pending_skills = skills

    def _ensure_initialized(self) -> None:
        self.ensure_calls += 1
        self._skill_registry = _FakeRegistry(self._pending_skills)


def _install(monkeypatch: pytest.MonkeyPatch, agent: _FakeAgent) -> io.StringIO:
    monkeypatch.setattr(cli, "load_or_default", lambda: object())
    monkeypatch.setattr(cli, "create_agent_from_config", lambda config: agent)
    buf = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=buf, width=200))
    return buf


def test_list_skills_ensures_init_before_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """回归锁：跳过 _ensure_initialized 时本用例必败（registry 仍为 None）。"""
    agent = _FakeAgent([{"name": "demo_skill", "description": "演示技能"}])
    buf = _install(monkeypatch, agent)

    cli.list_skills_command()

    assert agent.ensure_calls == 1
    out = buf.getvalue()
    assert "demo_skill" in out
    assert "演示技能" in out
    assert "已注册 Skill" in out


def test_list_skills_empty_registry_degrades_gracefully(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """空注册表不崩溃，输出降级提示。"""
    agent = _FakeAgent([])
    buf = _install(monkeypatch, agent)

    cli.list_skills_command()

    assert agent.ensure_calls == 1
    assert "未找到任何 Skill" in buf.getvalue()
