"""测试模块：winreverse.forensics.case

覆盖：建案 / 加载 / 列表、证据登记（复制/外部、文件/目录哈希）、
证据链完整性验证（篡改与缺失检测）、报告导出、路径越界防护。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from winreverse.forensics.case import (
    CaseError,
    CaseManager,
    EvidenceType,
)


class TestCreateCase:
    """建案测试。"""

    def test_create_with_auto_id(self, tmp_path: Path) -> None:
        """自动生成 case_YYYYMMDD_HHMMSS_xxxx 格式 ID 并落盘清单。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("应急响应", description="测试案件")
        assert case.case_id.startswith("case_")
        assert len(case.case_id.split("_")) == 4
        assert case.name == "应急响应"
        manifest = manager.case_dir(case.case_id) / "case.json"
        assert manifest.is_file()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        assert data["schema_version"] == "1.0"
        assert data["evidence_count"] == 0

    def test_create_with_custom_id(self, tmp_path: Path) -> None:
        """使用指定 ID 建案。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("x", case_id="case_20260101_000000_abcd")
        assert case.case_id == "case_20260101_000000_abcd"

    def test_create_rejects_bad_id(self, tmp_path: Path) -> None:
        """非法 ID 格式被拒绝。"""
        manager = CaseManager(tmp_path / "cases")
        with pytest.raises(CaseError, match="格式非法"):
            manager.create_case("x", case_id="not-a-case-id")

    def test_create_rejects_duplicate(self, tmp_path: Path) -> None:
        """重复 ID 被拒绝。"""
        manager = CaseManager(tmp_path / "cases")
        manager.create_case("a", case_id="case_20260101_000000_abcd")
        with pytest.raises(CaseError, match="案件已存在"):
            manager.create_case("b", case_id="case_20260101_000000_abcd")


class TestLoadAndList:
    """加载与列表测试。"""

    def test_load_case_roundtrip(self, tmp_path: Path) -> None:
        """保存后加载字段一致。"""
        manager = CaseManager(tmp_path / "cases")
        created = manager.create_case("案件A", description="desc")
        loaded = manager.load_case(created.case_id)
        assert loaded.name == "案件A"
        assert loaded.description == "desc"
        assert loaded.evidences == []

    def test_load_missing_case(self, tmp_path: Path) -> None:
        """加载不存在的案件报错。"""
        manager = CaseManager(tmp_path / "cases")
        with pytest.raises(CaseError, match="不存在"):
            manager.load_case("case_20260101_000000_zzzz")

    def test_load_broken_manifest(self, tmp_path: Path) -> None:
        """清单损坏报错。"""
        manager = CaseManager(tmp_path / "cases")
        bad_dir = manager.cases_root / "case_20260101_000000_abcd"
        bad_dir.mkdir(parents=True)
        (bad_dir / "case.json").write_text("{broken", encoding="utf-8")
        with pytest.raises(CaseError, match="解析失败"):
            manager.load_case("case_20260101_000000_abcd")

    def test_list_cases_sorted(self, tmp_path: Path) -> None:
        """列表按 case_id 升序且只含有效案件。"""
        manager = CaseManager(tmp_path / "cases")
        manager.create_case("b", case_id="case_20260101_000000_bbbb")
        manager.create_case("a", case_id="case_20260101_000000_aaaa")
        # 无清单的目录被忽略
        (manager.cases_root / "not_a_case").mkdir(parents=True)
        cases = manager.list_cases()
        assert [c.case_id for c in cases] == [
            "case_20260101_000000_aaaa",
            "case_20260101_000000_bbbb",
        ]


class TestAddEvidence:
    """证据登记测试。"""

    def test_add_file_evidence_copied(self, tmp_path: Path) -> None:
        """文件证据复制入案件目录并记录复制件哈希。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        src = tmp_path / "sample.bin"
        src.write_bytes(b"MALICIOUS")
        ev = manager.add_evidence(
            case.case_id, EvidenceType.RAW_FILE, src, collector="manual", notes="样本"
        )
        assert ev.sha256 == hashlib.sha256(b"MALICIOUS").hexdigest()
        assert ev.collector == "manual"
        stored = manager.get_evidence_path(case.case_id, ev.evidence_id)
        assert stored.is_file()
        assert stored.name.startswith(ev.evidence_id)
        assert stored.read_bytes() == b"MALICIOUS"

    def test_add_dir_evidence_tree_hash(self, tmp_path: Path) -> None:
        """目录证据用确定性树哈希（内容不变则哈希不变）。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        dump_dir = tmp_path / "dump"
        dump_dir.mkdir()
        (dump_dir / "region_0.bin").write_bytes(b"aa")
        (dump_dir / "region_1.bin").write_bytes(b"bb")
        ev1 = manager.add_evidence(case.case_id, EvidenceType.MEM_DUMP, dump_dir)
        ev2 = manager.add_evidence(case.case_id, EvidenceType.MEM_DUMP, dump_dir)
        assert ev1.sha256 == ev2.sha256  # 相同内容 → 相同树哈希

    def test_add_evidence_external_no_copy(self, tmp_path: Path) -> None:
        """copy_into_case=False 时登记外部路径，不复制。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        src = tmp_path / "outside.dmp"
        src.write_bytes(b"MDMP")
        ev = manager.add_evidence(case.case_id, EvidenceType.MINIDUMP, src, copy_into_case=False)
        assert ev.path == ""
        assert ev.original_path == str(src)
        assert not list((manager.case_dir(case.case_id) / "evidence").iterdir())

    def test_add_evidence_missing_source(self, tmp_path: Path) -> None:
        """来源不存在报错。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        with pytest.raises(CaseError, match="不存在"):
            manager.add_evidence(case.case_id, EvidenceType.RAW_FILE, tmp_path / "nope")


class TestVerifyCase:
    """证据链验证测试。"""

    def test_verify_passes_on_intact_case(self, tmp_path: Path) -> None:
        """未被篡改的案件验证通过。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        src = tmp_path / "a.bin"
        src.write_bytes(b"data")
        manager.add_evidence(case.case_id, EvidenceType.RAW_FILE, src)
        result = manager.verify_case(case.case_id)
        assert result.passed is True
        assert result.checked_count == 1
        assert result.passed_count == 1

    def test_verify_detects_tampering(self, tmp_path: Path) -> None:
        """证据文件被篡改时验证失败并说明原因。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        src = tmp_path / "a.bin"
        src.write_bytes(b"original")
        ev = manager.add_evidence(case.case_id, EvidenceType.RAW_FILE, src)
        stored = manager.get_evidence_path(case.case_id, ev.evidence_id)
        stored.write_bytes(b"tampered!")
        result = manager.verify_case(case.case_id)
        assert result.passed is False
        assert result.failures
        assert "SHA256 不匹配" in result.failures[0]["reason"]

    def test_verify_detects_missing_evidence(self, tmp_path: Path) -> None:
        """证据文件被删除时验证失败。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        src = tmp_path / "a.bin"
        src.write_bytes(b"data")
        ev = manager.add_evidence(case.case_id, EvidenceType.RAW_FILE, src)
        manager.get_evidence_path(case.case_id, ev.evidence_id).unlink()
        result = manager.verify_case(case.case_id)
        assert result.passed is False
        assert "缺失" in result.failures[0]["reason"]


class TestExportReport:
    """报告导出测试。"""

    def test_export_report_includes_verification(self, tmp_path: Path) -> None:
        """报告包含案件清单与验证结果。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c", description="d")
        src = tmp_path / "a.bin"
        src.write_bytes(b"data")
        manager.add_evidence(case.case_id, EvidenceType.RAW_FILE, src)
        report_path = manager.export_report(case.case_id)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["case_id"] == case.case_id
        assert report["evidence_count"] == 1
        assert report["verification"]["passed"] is True
        assert "exported_at" in report

    def test_export_report_custom_path(self, tmp_path: Path) -> None:
        """指定输出路径生效。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        out = tmp_path / "custom_report.json"
        result_path = manager.export_report(case.case_id, out)
        assert result_path == out
        assert out.is_file()


class TestPathSafety:
    """路径安全测试。"""

    def test_get_evidence_unknown_id(self, tmp_path: Path) -> None:
        """未知证据 ID 报错。"""
        manager = CaseManager(tmp_path / "cases")
        case = manager.create_case("c")
        with pytest.raises(CaseError, match="证据不存在"):
            manager.get_evidence_path(case.case_id, "ev_ffffff")
