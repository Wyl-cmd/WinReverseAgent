"""被测模块: winreverse.soul.context（上下文文件 IO 异常路径）。

覆盖点: KXNS.md 路径被目录占据时静默跳过（_load_kxns_file OSError 分支）、
include 目标不可读时返回占位符（_resolve_includes OSError 分支）、纯空白
上下文不注入 system prompt。平台无关，Linux 可实跑。
"""

from __future__ import annotations

from pathlib import Path

from winreverse.soul.context import ContextManager

_BASE_PROMPT = "base"


def _make_manager(tmp_path: Path) -> ContextManager:
    return ContextManager(work_dir=tmp_path)


class TestContextIoErrorPaths:
    """上下文文件不可读时的容错行为。"""

    def test_kxns_path_occupied_by_directory_is_skipped(self, tmp_path: Path) -> None:
        """KXNS.md 位置是目录：exists() 为真但 read_text 抛 OSError，应静默跳过。"""
        kxns_dir = tmp_path / ".winreverse" / "KXNS.md"
        kxns_dir.mkdir(parents=True)

        manager = _make_manager(tmp_path)
        manager.load_all()

        assert manager.build_system_prompt(_BASE_PROMPT) == _BASE_PROMPT

    def test_unreadable_include_reports_placeholder(self, tmp_path: Path) -> None:
        """include 目标存在但不可读（目录）→ 返回 error reading 占位符而非崩溃。"""
        kxns_dir = tmp_path / ".winreverse"
        kxns_dir.mkdir()
        (kxns_dir / "KXNS.md").write_text("@[include](nested/secret.md)", encoding="utf-8")
        # 目标路径存在但是目录：read_text 抛 IsADirectoryError（OSError 子类）
        (kxns_dir / "nested" / "secret.md").mkdir(parents=True)

        manager = _make_manager(tmp_path)
        manager.load_all()
        prompt = manager.build_system_prompt(_BASE_PROMPT)

        assert "[error reading include: nested/secret.md]" in prompt

    def test_whitespace_only_context_not_injected(self, tmp_path: Path) -> None:
        """纯空白上下文条目不产生 context 段落。"""
        kxns_dir = tmp_path / ".winreverse"
        kxns_dir.mkdir()
        (kxns_dir / "KXNS.md").write_text("   \n\t\n", encoding="utf-8")

        manager = _make_manager(tmp_path)
        manager.load_all()
        prompt = manager.build_system_prompt(_BASE_PROMPT)

        assert prompt == _BASE_PROMPT
        assert "project context" not in prompt
