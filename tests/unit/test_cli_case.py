"""测试模块：winreverse.cli.case

测试 winreverse case 取证案件子命令（create/list/show/add/verify/report 全流程）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from winreverse.cli import app

runner = CliRunner()


class TestCaseWorkflow:
    """case 命令端到端工作流测试（相对 output/cases，用 chdir 隔离）。"""

    def test_full_workflow(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """建案 → 入证 → 验证 → 报告 的完整命令链。"""
        monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]
        # 建案
        result = runner.invoke(app, ["case", "create", "应急响应", "--desc", "木马排查"])
        assert result.exit_code == 0, result.output
        cases = list((tmp_path / "output" / "cases").iterdir())
        assert len(cases) == 1
        case_id = cases[0].name

        # 入证
        evidence_file = tmp_path / "sample.bin"
        evidence_file.write_bytes(b"MALICIOUS_PAYLOAD")
        result = runner.invoke(
            app, ["case", "add", case_id, str(evidence_file), "--type", "raw_file"]
        )
        assert result.exit_code == 0, result.output
        assert "证据已登记" in result.output

        # 详情
        result = runner.invoke(app, ["case", "show", case_id])
        assert result.exit_code == 0
        assert "MALICIOUS" not in result.output  # show 只显示元数据
        assert "证据链" in result.output

        # 验证（未被篡改）
        result = runner.invoke(app, ["case", "verify", case_id])
        assert result.exit_code == 0
        assert "证据链完整" in result.output

        # 报告
        result = runner.invoke(app, ["case", "report", case_id])
        assert result.exit_code == 0
        report = json.loads(
            (tmp_path / "output" / "cases" / case_id / "report.json").read_text(encoding="utf-8")
        )
        assert report["evidence_count"] == 1
        assert report["verification"]["passed"] is True

    def test_verify_detects_tampering_exits_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """证据被篡改时 verify 命令退出码非零。"""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["case", "create", "c"])
        assert result.exit_code == 0
        case_id = next((tmp_path / "output" / "cases").iterdir()).name

        evidence_file = tmp_path / "e.bin"
        evidence_file.write_bytes(b"orig")
        result = runner.invoke(app, ["case", "add", case_id, str(evidence_file)])
        assert result.exit_code == 0

        # 直接篡改已入库的证据文件
        stored = next((tmp_path / "output" / "cases" / case_id / "evidence").iterdir())
        stored.write_bytes(b"tampered")

        result = runner.invoke(app, ["case", "verify", case_id])
        assert result.exit_code == 1
        assert "证据链被破坏" in result.output

    def test_list_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """无案件时提示创建。"""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["case", "list"])
        assert result.exit_code == 0
        assert "暂无案件" in result.output

    def test_show_missing_case_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """查看不存在的案件退出码非零。"""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["case", "show", "case_20260101_000000_zzzz"])
        assert result.exit_code == 1
        assert "不存在" in result.output

    def test_add_invalid_type_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """未知证据类型退出码非零。"""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["case", "create", "c"])
        case_id = next((tmp_path / "output" / "cases").iterdir()).name
        evidence_file = tmp_path / "e.bin"
        evidence_file.write_bytes(b"x")
        result = runner.invoke(
            app, ["case", "add", case_id, str(evidence_file), "--type", "bad_type"]
        )
        assert result.exit_code == 1
        assert "未知证据类型" in result.output
