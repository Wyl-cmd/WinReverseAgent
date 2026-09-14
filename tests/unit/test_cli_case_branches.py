"""测试模块：winreverse.cli.case（错误分支与 collect 入证补充，自足文件）。

不改动既有 tests/unit/test_cli_case.py，本文件独立覆盖：
- CaseError 统一映射分支（红色提示 + typer.Exit(1)，不得裸异常崩溃）
- list 表格 / show 空证据提示 / add、verify、report 错误分支
- case collect：内存转储入证（进程附着/转储为 Windows 专有，
  以 winreverse.core.* 调用点边界 mock 驱动命令逻辑）
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from winreverse.cli import app

runner = CliRunner()


class TestCaseErrorBranches:
    """CaseError 统一映射分支：红色提示 + typer.Exit(1)，不得裸异常崩溃。"""

    def test_create_case_error_maps_to_exit1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """create_case 抛 CaseError 时命令应提示并退出 1。"""
        monkeypatch.chdir(tmp_path)

        from winreverse.forensics.case import CaseError

        def _boom(self: object, name: str, description: str = "") -> object:
            raise CaseError("案件目录不可写")

        monkeypatch.setattr("winreverse.forensics.case.CaseManager.create_case", _boom)
        result = runner.invoke(app, ["case", "create", "x"])
        assert result.exit_code == 1
        assert "案件目录不可写" in result.output

    def test_list_with_cases_shows_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """有案件时 list 输出表格（案件 ID / 名称 / 证据数）。"""
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["case", "create", "案件甲"]).exit_code == 0
        assert runner.invoke(app, ["case", "create", "案件乙"]).exit_code == 0
        result = runner.invoke(app, ["case", "list"])
        assert result.exit_code == 0, result.output
        assert "取证案件（2）" in result.output
        for case_dir in (tmp_path / "output" / "cases").iterdir():
            assert case_dir.name in result.output
        assert "案件甲" in result.output and "案件乙" in result.output

    def test_show_case_without_evidence_hints_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """刚建案（无证据）时 show 应提示暂无证据而非渲染空表。"""
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["case", "create", "空案"]).exit_code == 0
        case_id = next((tmp_path / "output" / "cases").iterdir()).name
        result = runner.invoke(app, ["case", "show", case_id])
        assert result.exit_code == 0, result.output
        assert "（暂无证据）" in result.output

    def test_add_missing_source_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """登记不存在的证据来源应退出 1 并说明来源不存在。"""
        monkeypatch.chdir(tmp_path)
        assert runner.invoke(app, ["case", "create", "c"]).exit_code == 0
        case_id = next((tmp_path / "output" / "cases").iterdir()).name
        result = runner.invoke(app, ["case", "add", case_id, str(tmp_path / "ghost.bin")])
        assert result.exit_code == 1
        assert "证据来源不存在" in result.output

    def test_verify_missing_case_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """验证不存在的案件应退出 1。"""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["case", "verify", "case_20260101_000000_zzzz"])
        assert result.exit_code == 1
        assert "不存在" in result.output

    def test_report_missing_case_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """导出不存在的案件报告应退出 1。"""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["case", "report", "case_20260101_000000_zzzz"])
        assert result.exit_code == 1
        assert "不存在" in result.output


class TestCaseCollectCommand:
    """case collect：内存转储入证（进程附着/转储为 Windows 专有，Linux 以边界 mock 驱动命令逻辑）。"""

    def _create_case(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["case", "create", "内存取证"])
        assert result.exit_code == 0, result.output
        return next((tmp_path / "output" / "cases").iterdir()).name

    def _stub_memdump_api(
        self,
        monkeypatch: pytest.MonkeyPatch,
        dump_process: object,
        memory_error: type[Exception] | None = None,
    ) -> None:
        """向 sys.modules 注入 memdump_api / memory_api 桩模块。

        真实 winreverse.core.memdump_api 与 core.memory_api 均在模块顶层
        import pymem（Windows 专有），Linux 上无法导入；桩只替换转储边界与
        异常类型，add_evidence 等命令逻辑真实执行。
        """
        fake_dump_module = types.ModuleType("winreverse.core.memdump_api")
        fake_dump_module.dump_process = dump_process  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "winreverse.core.memdump_api", fake_dump_module)
        # 修复(2026-09-12)：Windows guest 里 pymem 可导入，真实 memdump_api 早已被导入并把
        # 子模块挂成 winreverse.core 的属性；此时命令里的 `from winreverse.core import
        # memdump_api` 走属性查找，直接拿到真模块 → sys.modules 桩被绕过（Linux 因 pymem 缺失
        # 导入失败才"恰好"生效）。故同时替换包属性，使两端行为一致。
        import winreverse.core as _core_pkg

        monkeypatch.setattr(_core_pkg, "memdump_api", fake_dump_module, raising=False)

        fake_mem_module = types.ModuleType("winreverse.core.memory_api")
        fake_mem_module.MemoryAccessError = memory_error or type(  # type: ignore[attr-defined]
            "_MemoryAccessError", (RuntimeError,), {}
        )
        monkeypatch.setitem(sys.modules, "winreverse.core.memory_api", fake_mem_module)

    def test_collect_registers_mem_dump_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """转储成功路径：登记 MEM_DUMP 证据（含采集方式与 --max-mb 透传）。"""
        case_id = self._create_case(tmp_path, monkeypatch)
        dump_dir = tmp_path / "output" / "memory_dumps" / "case_4321_collect"
        dump_dir.mkdir(parents=True)
        (dump_dir / "region_0.dmp").write_bytes(b"\x00\x01")

        fake_pm = SimpleNamespace(process_handle=4321)
        monkeypatch.setattr("winreverse.cli.mem._attach", lambda target: (fake_pm, 4321))
        calls: dict[str, object] = {}

        def _fake_dump(handle: int, out_dir: Path, max_total_bytes: int) -> SimpleNamespace:
            calls["handle"] = handle
            calls["max_total_bytes"] = max_total_bytes
            return SimpleNamespace(
                output_dir=str(out_dir),
                dumped_count=1,
                region_count=2,
                total_bytes=2,
                suspicious_count=0,
            )

        self._stub_memdump_api(monkeypatch, _fake_dump)
        result = runner.invoke(app, ["case", "collect", case_id, "4321"])
        assert result.exit_code == 0, result.output
        assert "内存证据已入案" in result.output
        assert calls["handle"] == 4321
        assert calls["max_total_bytes"] == 512 * 1024 * 1024  # 默认 --max-mb 512

        from winreverse.forensics.case import CaseManager, EvidenceType

        case = CaseManager(tmp_path / "output" / "cases").load_case(case_id)
        assert len(case.evidences) == 1
        evidence = case.evidences[0]
        assert evidence.type is EvidenceType.MEM_DUMP
        assert "pid=4321" in evidence.collector
        assert evidence.path  # 已复制入案件目录

    def test_collect_dump_failure_maps_to_exit1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """转储失败（MemoryAccessError）应提示采集失败并退出 1，不登记证据。"""

        class _MemoryAccessError(RuntimeError): ...

        case_id = self._create_case(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "winreverse.cli.mem._attach", lambda target: (SimpleNamespace(process_handle=1), 1)
        )

        def _fail(handle: int, out_dir: Path, max_total_bytes: int) -> object:
            raise _MemoryAccessError("打开进程失败")

        self._stub_memdump_api(monkeypatch, _fail, memory_error=_MemoryAccessError)
        result = runner.invoke(app, ["case", "collect", case_id, "1"])
        assert result.exit_code == 1
        assert "采集失败" in result.output

        from winreverse.forensics.case import CaseManager

        case = CaseManager(tmp_path / "output" / "cases").load_case(case_id)
        assert case.evidences == []
