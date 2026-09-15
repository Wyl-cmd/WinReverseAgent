"""被测模块: winreverse.forensics.case（get_evidence_path）。
覆盖点: os.path.commonpath 抛 ValueError 时的越界翻译弧（418-419 行）——
commonpath 混用盘符/绝对相对路径时 ValueError 必须转 CaseError 并保留 __cause__。
平台无关（monkeypatch stdlib，不注假模块），Linux 可实跑。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from winreverse.forensics.case import CaseError, CaseManager, EvidenceType


def _make_case_with_evidence(tmp_path: Path, mgr: CaseManager) -> tuple[str, str]:
    source = tmp_path / "artifact.bin"
    source.write_bytes(b"evidence-payload")
    case = mgr.create_case("边界弧用例")
    evidence = mgr.add_evidence(case.case_id, EvidenceType.RAW_FILE, source)
    return case.case_id, evidence.evidence_id


def test_evidence_path_resolves_within_case_dir(tmp_path: Path) -> None:
    """前置基线：正常证据路径必须解析到案件目录内。"""
    mgr = CaseManager(tmp_path / "cases")
    case_id, evidence_id = _make_case_with_evidence(tmp_path, mgr)

    resolved = mgr.get_evidence_path(case_id, evidence_id)

    assert resolved.is_relative_to(mgr.case_dir(case_id).resolve())
    assert resolved.exists()


def test_commonpath_value_error_translates_to_case_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """commonpath 抛 ValueError（如跨盘符）时必须翻译为 CaseError 且保留因果链。"""

    def _raise_value_error(_paths: object) -> str:
        raise ValueError("path is on mount 'D:', start on mount 'C:'")

    monkeypatch.setattr(os.path, "commonpath", _raise_value_error)
    mgr = CaseManager(tmp_path / "cases")
    case_id, evidence_id = _make_case_with_evidence(tmp_path, mgr)

    with pytest.raises(CaseError, match="证据路径越界") as exc_info:
        mgr.get_evidence_path(case_id, evidence_id)

    assert isinstance(exc_info.value.__cause__, ValueError)
