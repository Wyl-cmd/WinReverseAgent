"""被测模块: winreverse.soul.agent_spec.render_system_prompt。

覆盖点: 带参数模板渲染（jinja2 路径 agent_spec.py:162-164；本机未装 jinja2
时走 {{key}} 替换 fallback，两分支渲染结果一致，断言环境可移植）。
"""

from __future__ import annotations

from winreverse.soul.agent_spec import render_system_prompt


class TestRenderSystemPromptWithArgs:
    """带参渲染：jinja2 与替换 fallback 输出契约一致。"""

    def test_single_placeholder(self) -> None:
        out = render_system_prompt("target={{target}}", {"target": "notepad.exe"})
        assert out == "target=notepad.exe"

    def test_multiple_placeholders_keep_order(self) -> None:
        template = "analyze {{file}} with {{tool}} under {{file}}"
        out = render_system_prompt(template, {"file": "dump.dmp", "tool": "yara"})
        assert out == "analyze dump.dmp with yara under dump.dmp"

    def test_no_args_returns_template_untouched(self) -> None:
        template = "raw {{keep}} {{x}}"
        assert render_system_prompt(template) == template
        assert render_system_prompt(template, None) == template

    def test_unused_args_are_ignored(self) -> None:
        out = render_system_prompt("only {{a}}", {"a": "1", "b": "2"})
        assert out == "only 1"
