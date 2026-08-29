"""测试模块：winreverse.soul.context

覆盖 ContextManager 的多层上下文加载、@[include] 语法解析、按 agent_type 过滤等能力。
"""

from __future__ import annotations

from pathlib import Path

from winreverse.soul.context import ContextEntry, ContextLayer, ContextManager

# =============================================================================
# ContextLayer 枚举测试
# =============================================================================


class TestContextLayer:
    """ContextLayer 枚举测试。"""

    def test_has_four_layers(self) -> None:
        """包含 global/user/project/local 四层。"""
        layers = {layer.value for layer in ContextLayer}
        assert layers == {"global", "user", "project", "local"}

    def test_layer_values_are_strings(self) -> None:
        """枚举值均为字符串。"""
        for layer in ContextLayer:
            assert isinstance(layer.value, str)


# =============================================================================
# ContextManager 加载测试
# =============================================================================


class TestContextManagerLoading:
    """ContextManager 文件加载测试。"""

    def test_load_all_with_no_files(self, tmp_path: Path) -> None:
        """无任何 KXNS.md 文件时，entries 为空。"""
        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()
        assert mgr._entries == []

    def test_load_project_context(self, tmp_path: Path) -> None:
        """加载 project 层 KXNS.md。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text("# Project Context\n逆向工程指南", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        assert len(mgr._entries) == 1
        entry = mgr._entries[0]
        assert entry.layer == ContextLayer.PROJECT
        assert "逆向工程指南" in entry.content
        assert entry.source.name == "KXNS.md"

    def test_load_local_context(self, tmp_path: Path) -> None:
        """加载 local 层 KXNS.md。"""
        local_dir = tmp_path / ".winreverse" / "local"
        local_dir.mkdir(parents=True)
        (local_dir / "KXNS.md").write_text("# Local Context\n本地覆盖", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        assert len(mgr._entries) == 1
        assert mgr._entries[0].layer == ContextLayer.LOCAL

    def test_priority_ordering(self, tmp_path: Path) -> None:
        """project 与 local 同时存在时，local 优先级更高。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text("project", encoding="utf-8")
        (winreverse_dir / "local").mkdir()
        (winreverse_dir / "local" / "KXNS.md").write_text("local", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        assert len(mgr._entries) == 2
        sorted_entries = sorted(mgr._entries, key=lambda e: e.priority, reverse=True)
        assert sorted_entries[0].layer == ContextLayer.LOCAL
        assert sorted_entries[1].layer == ContextLayer.PROJECT

    def test_load_all_is_idempotent(self, tmp_path: Path) -> None:
        """重复调用 load_all 不重复加载。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text("context", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()
        mgr.load_all()

        assert len(mgr._entries) == 1


# =============================================================================
# @[include] 语法解析测试
# =============================================================================


class TestIncludeResolution:
    """@[include](path) 语法解析测试。"""

    def test_resolve_simple_include(self, tmp_path: Path) -> None:
        """解析简单的 @[include] 引用。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        included_file = winreverse_dir / "extra.md"
        included_file.write_text("被引用的内容", encoding="utf-8")
        (winreverse_dir / "KXNS.md").write_text(
            "主文档\n@[include](extra.md)\n结束", encoding="utf-8"
        )

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        assert len(mgr._entries) == 1
        content = mgr._entries[0].content
        assert "被引用的内容" in content
        assert "@[include]" not in content

    def test_resolve_nested_includes(self, tmp_path: Path) -> None:
        """解析嵌套的 @[include] 引用。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "level2.md").write_text("二级内容", encoding="utf-8")
        (winreverse_dir / "level1.md").write_text(
            "一级内容\n@[include](level2.md)", encoding="utf-8"
        )
        (winreverse_dir / "KXNS.md").write_text("@[include](level1.md)", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        content = mgr._entries[0].content
        assert "一级内容" in content
        assert "二级内容" in content

    def test_circular_include_detected(self, tmp_path: Path) -> None:
        """循环引用被检测并替换为提示信息。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "a.md").write_text("@[include](b.md)", encoding="utf-8")
        (winreverse_dir / "b.md").write_text("@[include](a.md)", encoding="utf-8")
        (winreverse_dir / "KXNS.md").write_text("@[include](a.md)", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        content = mgr._entries[0].content
        assert "circular include" in content

    def test_missing_include_returns_placeholder(self, tmp_path: Path) -> None:
        """不存在的 include 文件返回占位符。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text("@[include](nonexistent.md)", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        content = mgr._entries[0].content
        assert "include not found" in content


# =============================================================================
# system prompt 构建测试
# =============================================================================


class TestSystemPromptBuilding:
    """build_system_prompt 测试。"""

    def test_empty_context(self, tmp_path: Path) -> None:
        """无上下文时，system prompt 仅包含 base_prompt。"""
        mgr = ContextManager(work_dir=tmp_path)
        prompt = mgr.build_system_prompt("你是助手")
        assert prompt == "你是助手"

    def test_with_skill_summary(self, tmp_path: Path) -> None:
        """设置 skill 摘要后会附加到 prompt。"""
        mgr = ContextManager(work_dir=tmp_path)
        mgr.set_skill_catalog_summary("可用技能：PE 分析")
        prompt = mgr.build_system_prompt("你是助手")
        assert "你是助手" in prompt
        assert "可用技能：PE 分析" in prompt

    def test_with_context_entries(self, tmp_path: Path) -> None:
        """有上下文条目时，按优先级拼接。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text("项目规则", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()
        prompt = mgr.build_system_prompt("你是助手")

        assert "你是助手" in prompt
        assert "项目规则" in prompt
        assert "project context" in prompt


# =============================================================================
# agent_type 过滤测试
# =============================================================================


class TestAgentTypeFiltering:
    """get_context_for_agent 测试。"""

    def test_no_keywords_for_unknown_type(self, tmp_path: Path) -> None:
        """未知 agent_type 返回空字符串。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text("some content", encoding="utf-8")

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        result = mgr.get_context_for_agent("unknown_type")
        assert result == ""

    def test_filter_reverse_keywords(self, tmp_path: Path) -> None:
        """reverse agent_type 过滤出逆向相关上下文。"""
        winreverse_dir = tmp_path / ".winreverse"
        winreverse_dir.mkdir()
        (winreverse_dir / "KXNS.md").write_text(
            "本指南用于 reverse engineering 与 disassemble", encoding="utf-8"
        )

        mgr = ContextManager(work_dir=tmp_path)
        mgr.load_all()

        result = mgr.get_context_for_agent("reverse")
        assert "reverse" in result.lower()


# =============================================================================
# ContextEntry 模型测试
# =============================================================================


class TestContextEntry:
    """ContextEntry pydantic 模型测试。"""

    def test_create_entry(self, tmp_path: Path) -> None:
        """创建 ContextEntry 实例。"""
        entry = ContextEntry(
            content="test content",
            layer=ContextLayer.PROJECT,
            source=tmp_path / "test.md",
            priority=30,
        )
        assert entry.content == "test content"
        assert entry.layer == ContextLayer.PROJECT
        assert entry.priority == 30

    def test_default_priority(self, tmp_path: Path) -> None:
        """默认 priority 为 0。"""
        entry = ContextEntry(
            content="",
            layer=ContextLayer.GLOBAL,
            source=tmp_path / "test.md",
        )
        assert entry.priority == 0
