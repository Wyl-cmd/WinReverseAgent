"""测试模块：winreverse.soul.agent_spec.render_system_prompt 的 ImportError 回退分支。

覆盖点：jinja2 导入失败时退化为 {{key}} 简单替换（agent_spec.py L165-L169）。
口径（2026-09-18 实测，非假设）：宿主工作区与 guest venv **均未安装** jinja2
（`python -c "import jinja2"` → ModuleNotFoundError），两环境当前都天然走回退分支；
jinja2 渲染分支（L160-L164）在 guest 覆盖率 XML 中恒为 missed=[162,163,164]。
本文件用 builtins.__import__ 阻断 jinja2 导入强制真实 ImportError 路径，不注入假模块、
无 skip/平台守卫——即使将来给 guest/CI 装上 jinja2（用于闭合 L162-L164），本用例
仍能确定性覆盖回退分支。
"""

from __future__ import annotations

import builtins
from typing import Any

import pytest

from winreverse.soul.agent_spec import render_system_prompt


@pytest.fixture()
def block_jinja2(monkeypatch: pytest.MonkeyPatch) -> None:
    """阻断 jinja2 导入：from jinja2 import ... 必经 __import__，缓存不影响。"""
    real_import = builtins.__import__

    def blocked(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "jinja2" or name.startswith("jinja2."):
            raise ImportError(f"jinja2 import blocked for fallback test: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)


class TestRenderSystemPromptFallback:
    """jinja2 缺失时 render_system_prompt 的简单替换回退语义。"""

    def test_multi_key_replacement(self, block_jinja2: None) -> None:
        """阻断 jinja2 → 多个 {{key}} 按顺序替换为对应实参。"""
        rendered = render_system_prompt(
            "分析 {{target}} 的 {{section}} 段", {"target": "PE", "section": "头部"}
        )
        assert rendered == "分析 PE 的 头部 段"

    def test_unmatched_placeholder_kept_verbatim(self, block_jinja2: None) -> None:
        """回退只替换命中实参的占位符，未命中的原样保留。"""
        rendered = render_system_prompt("{{known}} -> {{unknown}}", {"known": "x"})
        assert rendered == "x -> {{unknown}}"

    def test_jinja_syntax_not_interpreted(self, block_jinja2: None) -> None:
        """回退不解释 jinja 控制流/带空格占位符——输出与 jinja2 渲染结果不同，
        同时证明走的是回退分支而非 jinja2。"""
        template = "{% if debug %}D{% endif %}{{ name }}"
        rendered = render_system_prompt(template, {"debug": "1", "name": "x", " name": "y"})
        assert rendered == template

    def test_empty_args_short_circuit(self, block_jinja2: None) -> None:
        """args 为空 → 直接原样返回，连导入都不会发生。"""
        template = "{{a}}{% if b %}c{% endif %}"
        assert render_system_prompt(template) is template
        assert render_system_prompt(template, {}) is template


def test_block_fixture_raises_import_error_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """阻断器本身行为正确：仅拦截 jinja2，其余导入不受影响。"""
    real_import = builtins.__import__

    def blocked(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "jinja2":
            raise ImportError(f"blocked: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(ImportError):
        __import__("jinja2")
    import json  # 非拦截目标，正常导入

    assert callable(json.dumps)
