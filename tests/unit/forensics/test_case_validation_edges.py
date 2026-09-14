"""被测模块: winreverse.forensics.case（清单校验与证据路径安全边界）。

覆盖点: Evidence/Case 字段非法解析拒绝、evidences 非列表、外部登记路径
解析、清单被篡改为越界路径时 get_evidence_path 拒绝 + verify_case 记失败、
证据复制中断时半成品清理。平台无关，Linux 可实跑。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import winreverse.forensics.case as case_module
from winreverse.forensics.case import Case, CaseError, CaseManager, Evidence, EvidenceType

_VALID_ID = "case_20260913_120000_abcd"


def _make_case(tmp_path: Path) -> CaseManager:
    manager = CaseManager(cases_root=tmp_path / "cases")
    manager.create_case("边界测试案件", case_id=_VALID_ID)
    return manager


def _rewrite_manifest(manager: CaseManager, case_id: str, evidences: list[dict]) -> None:
    """直接改写 case.json 清单（模拟清单被外部篡改/手工编辑）。"""
    manifest = manager.case_dir(case_id) / "case.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["evidences"] = evidences
    manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


class TestManifestValidation:
    """清单与证据记录的字段校验拒绝路径。"""

    def test_evidence_from_dict_rejects_non_numeric_size(self) -> None:
        with pytest.raises(CaseError, match="证据记录字段非法"):
            Evidence.from_dict({"size": "not-a-number"})

    def test_evidence_from_dict_rejects_unknown_type(self) -> None:
        with pytest.raises(CaseError, match="证据记录字段非法"):
            Evidence.from_dict({"type": "no_such_type"})

    def test_case_from_dict_rejects_non_list_evidences(self) -> None:
        data = Case(case_id=_VALID_ID, name="x").to_dict()
        data["evidences"] = "should-be-a-list"
        with pytest.raises(CaseError, match="evidences 字段应为列表"):
            Case.from_dict(data)

    def test_load_case_rejects_manifest_with_bad_case_id(self, tmp_path: Path) -> None:
        manager = _make_case(tmp_path)
        manifest = manager.case_dir(_VALID_ID) / "case.json"
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["case_id"] = "tampered_id"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(CaseError, match="案件 ID 格式非法"):
            manager.load_case(_VALID_ID)


class TestEvidencePathSafety:
    """证据路径解析：外部登记与越界拒绝。"""

    def test_external_evidence_resolves_to_original_path(self, tmp_path: Path) -> None:
        manager = _make_case(tmp_path)
        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"raw")
        evidence = manager.add_evidence(
            _VALID_ID, EvidenceType.RAW_FILE, outside, copy_into_case=False
        )
        assert evidence.path == ""
        assert manager.get_evidence_path(_VALID_ID, evidence.evidence_id) == outside

    def test_traversal_path_is_rejected(self, tmp_path: Path) -> None:
        manager = _make_case(tmp_path)
        _rewrite_manifest(
            manager,
            _VALID_ID,
            [
                {
                    "evidence_id": "ev_evil01",
                    "type": "raw_file",
                    "path": "../escaped.txt",
                    "sha256": "0" * 64,
                    "size": 1,
                }
            ],
        )
        with pytest.raises(CaseError, match="证据路径越界"):
            manager.get_evidence_path(_VALID_ID, "ev_evil01")

    def test_verify_case_records_traversal_as_failure(self, tmp_path: Path) -> None:
        manager = _make_case(tmp_path)
        _rewrite_manifest(
            manager,
            _VALID_ID,
            [
                {
                    "evidence_id": "ev_evil01",
                    "type": "raw_file",
                    "path": "../escaped.txt",
                    "sha256": "0" * 64,
                    "size": 1,
                }
            ],
        )
        result = manager.verify_case(_VALID_ID)
        assert not result.passed
        assert result.checked_count == 1
        assert result.passed_count == 0
        assert result.failures[0]["evidence_id"] == "ev_evil01"
        assert "证据路径越界" in result.failures[0]["reason"]


class TestAddEvidenceFailureCleanup:
    """证据复制中断时不留半成品、清单不入账。"""

    def test_copy_failure_raises_and_cleans_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager = _make_case(tmp_path)
        source = tmp_path / "sample.bin"
        source.write_bytes(b"payload")

        def _boom(src: object, dst: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(case_module.shutil, "copy2", _boom)
        with pytest.raises(CaseError, match="证据复制失败"):
            manager.add_evidence(_VALID_ID, EvidenceType.RAW_FILE, source)

        # 半成品已清理：evidence/ 目录下无孤儿文件
        evidence_dir = manager.case_dir(_VALID_ID) / "evidence"
        assert list(evidence_dir.iterdir()) == []
        # 清单未追加失败证据
        assert manager.load_case(_VALID_ID).evidences == []
