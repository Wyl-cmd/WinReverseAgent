"""winreverse.forensics.case — 取证案件与证据链管理。

提供内存取证 / 移动取证的案件（case）工作流：
1. 建案：每个案件一个独立目录（cases/<case_id>/），内含 case.json 清单
2. 入证：将采集产物（内存转储 / minidump / 文件 / Android 镜像）登记为证据，
   计算 SHA256 建立基线
3. 验证：重算全部证据哈希与清单对照，发现篡改/损坏（证据链完整性）
4. 报告：导出案件 JSON 报告；内存转储证据可联动 memanalysis_api 深度分析

设计原则：
- 纯本地文件操作，无网络、无进程依赖
- case.json 为唯一事实来源（Single Source of Truth），结构稳定可外部工具消费
- 证据文件默认复制入案件目录（保留原始采集产物不动），记录复制后哈希

参考：数字取证通用证据链规范（Chain of Custody）
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

# 案件 ID 格式：case_YYYYMMDD_HHMMSS_xxxx（时间戳 + 4 位随机后缀防碰撞）
_CASE_ID_PATTERN = re.compile(r"^case_\d{8}_\d{6}_[0-9a-f]{4}$")

# case.json 清单文件名
_MANIFEST_FILENAME = "case.json"

# 清单 schema 版本
_SCHEMA_VERSION = "1.0"


class EvidenceType(str, Enum):
    """证据类型。"""

    MEM_DUMP = "mem_dump"  # memdump_api 产出的区域转储目录
    MINIDUMP = "minidump"  # 标准 .dmp 文件
    RAW_FILE = "raw_file"  # 任意文件（样本、日志、配置等）
    ANDROID_IMAGE = "android_image"  # LiME raw 内存镜像
    ANDROID_DATA = "android_data"  # adb 提取的应用/系统数据
    ANALYSIS_REPORT = "analysis_report"  # 分析报告（JSON/HTML）


class CaseError(RuntimeError):
    """案件操作失败的统一异常。"""


@dataclass
class Evidence:
    """单条证据记录。

    Attributes:
        evidence_id: 证据 ID（ev_xxxx 短 ID）
        type: 证据类型
        path: 证据文件/目录路径（相对案件目录；空字符串表示登记外部路径）
        original_path: 采集来源原始路径（仅记录，不校验）
        sha256: 证据内容 SHA256（目录证据为清单文件哈希）
        size: 证据大小（字节；目录为清单文件大小）
        collected_at: 入证时间（UTC ISO 格式）
        collector: 采集工具/方式说明（如 'memory.dump' / 'adb pull'）
        notes: 备注
    """

    evidence_id: str
    type: EvidenceType
    path: str
    sha256: str
    size: int
    collected_at: str = ""
    original_path: str = ""
    collector: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {
            "evidence_id": self.evidence_id,
            "type": self.type.value,
            "path": self.path,
            "original_path": self.original_path,
            "sha256": self.sha256,
            "size": self.size,
            "collected_at": self.collected_at,
            "collector": self.collector,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        """从字典构造（加载 case.json 用）。"""
        return cls(
            evidence_id=str(data.get("evidence_id", "")),
            type=EvidenceType(data.get("type", EvidenceType.RAW_FILE.value)),
            path=str(data.get("path", "")),
            original_path=str(data.get("original_path", "")),
            sha256=str(data.get("sha256", "")),
            size=int(data.get("size", 0)),
            collected_at=str(data.get("collected_at", "")),
            collector=str(data.get("collector", "")),
            notes=str(data.get("notes", "")),
        )


@dataclass
class Case:
    """取证案件。

    Attributes:
        case_id: 案件 ID（case_YYYYMMDD_HHMMSS_xxxx）
        name: 案件名称
        created_at: 建案时间（UTC ISO 格式）
        description: 案件描述
        evidences: 证据列表（按入证顺序）
    """

    case_id: str
    name: str
    created_at: str = ""
    description: str = ""
    evidences: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典（case.json 格式）。"""
        return {
            "schema_version": _SCHEMA_VERSION,
            "case_id": self.case_id,
            "name": self.name,
            "created_at": self.created_at,
            "description": self.description,
            "evidence_count": len(self.evidences),
            "evidences": [e.to_dict() for e in self.evidences],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Case:
        """从字典构造（加载 case.json 用）。

        Raises:
            CaseError: 清单结构非法
        """
        case_id = str(data.get("case_id", ""))
        if not _CASE_ID_PATTERN.match(case_id):
            raise CaseError(f"案件 ID 格式非法: {case_id!r}")
        evidences_raw = data.get("evidences", [])
        if not isinstance(evidences_raw, list):
            raise CaseError("evidences 字段应为列表")
        return cls(
            case_id=case_id,
            name=str(data.get("name", "")),
            created_at=str(data.get("created_at", "")),
            description=str(data.get("description", "")),
            evidences=[Evidence.from_dict(e) for e in evidences_raw if isinstance(e, dict)],
        )


@dataclass
class VerificationResult:
    """证据链完整性验证结果。

    Attributes:
        case_id: 案件 ID
        checked_count: 校验的证据条数
        passed_count: 通过条数
        failures: 失败明细（evidence_id → 原因）
    """

    case_id: str
    checked_count: int = 0
    passed_count: int = 0
    failures: list[dict[str, str]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """证据链是否完整。"""
        return not self.failures

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {
            "case_id": self.case_id,
            "checked_count": self.checked_count,
            "passed_count": self.passed_count,
            "passed": self.passed,
            "failures": self.failures,
        }


class CaseManager:
    """案件管理器。

    管理工作目录下 cases/ 的全部案件：
        <cases_root>/
        └── <case_id>/
            ├── case.json       # 案件清单（含证据链）
            └── evidence/       # 证据文件（复制入库）

    用法：
        manager = CaseManager(cases_root=Path("cases"))
        case = manager.create_case("木马应急响应", description="...")
        entry = manager.add_evidence(case.case_id, EvidenceType.MEM_DUMP, Path("dump/"))
        report = manager.verify_case(case.case_id)
    """

    def __init__(self, cases_root: str | Path) -> None:
        """初始化案件管理器。

        Args:
            cases_root: 案件根目录（不存在时自动创建）
        """
        self.cases_root = Path(cases_root)

    # ------------------------- 案件生命周期 -------------------------

    def create_case(
        self,
        name: str,
        *,
        description: str = "",
        case_id: str | None = None,
    ) -> Case:
        """创建新案件。

        Args:
            name: 案件名称
            description: 案件描述
            case_id: 指定案件 ID（None 自动生成 case_YYYYMMDD_HHMMSS_xxxx）

        Returns:
            Case 实例（已落盘 case.json）

        Raises:
            CaseError: 案件 ID 已存在或格式非法
        """
        if case_id is None:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            case_id = f"case_{timestamp}_{uuid.uuid4().hex[:4]}"
        else:
            if not _CASE_ID_PATTERN.match(case_id):
                raise CaseError(f"案件 ID 格式非法: {case_id!r}（应为 case_YYYYMMDD_HHMMSS_xxxx）")
            if self.case_dir(case_id).exists():
                raise CaseError(f"案件已存在: {case_id}")

        case = Case(
            case_id=case_id,
            name=name,
            created_at=datetime.now(UTC).isoformat(),
            description=description,
        )
        case_dir = self.case_dir(case_id)
        (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
        self._save_case(case)
        return case

    def case_dir(self, case_id: str) -> Path:
        """案件目录路径。"""
        return self.cases_root / case_id

    def list_cases(self) -> list[Case]:
        """列出全部案件（按 case_id 升序）。"""
        if not self.cases_root.is_dir():
            return []
        cases: list[Case] = []
        for entry in sorted(self.cases_root.iterdir()):
            if entry.is_dir() and (entry / _MANIFEST_FILENAME).is_file():
                cases.append(self.load_case(entry.name))
        return cases

    def load_case(self, case_id: str) -> Case:
        """加载案件清单。

        Raises:
            CaseError: 案件不存在或清单损坏
        """
        manifest = self.case_dir(case_id) / _MANIFEST_FILENAME
        if not manifest.is_file():
            raise CaseError(f"案件不存在或清单缺失: {case_id}")
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CaseError(f"case.json 解析失败: {e}") from e
        return Case.from_dict(data)

    def _save_case(self, case: Case) -> None:
        """将案件清单写入 case.json。"""
        case_dir = self.case_dir(case.case_id)
        case_dir.mkdir(parents=True, exist_ok=True)
        manifest = case_dir / _MANIFEST_FILENAME
        manifest.write_text(
            json.dumps(case.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # ------------------------- 证据管理 -------------------------

    def add_evidence(
        self,
        case_id: str,
        evidence_type: EvidenceType,
        source_path: str | Path,
        *,
        collector: str = "",
        notes: str = "",
        copy_into_case: bool = True,
    ) -> Evidence:
        """登记证据：复制入案件目录并计算 SHA256 建立完整性基线。

        Args:
            case_id: 案件 ID
            evidence_type: 证据类型
            source_path: 证据来源路径（文件或目录）
            collector: 采集工具/方式说明
            notes: 备注
            copy_into_case: True 复制入案件目录（默认，保留原始产物）；
                False 仅登记外部路径（不复制，哈希记录当前内容）

        Returns:
            Evidence 证据记录

        Raises:
            CaseError: 案件不存在 / 来源路径不存在
        """
        case = self.load_case(case_id)
        source = Path(source_path)
        if not source.exists():
            raise CaseError(f"证据来源不存在: {source}")

        evidence_id = f"ev_{uuid.uuid4().hex[:6]}"
        rel_path = ""
        stored_path = source

        if copy_into_case:
            evidence_dir = self.case_dir(case_id) / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            target = evidence_dir / f"{evidence_id}_{source.name}"
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
            rel_path = str(target.relative_to(self.case_dir(case_id)))
            stored_path = target

        if stored_path.is_dir():
            sha256, size = self._hash_tree(stored_path)
        else:
            data = stored_path.read_bytes()
            sha256 = hashlib.sha256(data).hexdigest()
            size = len(data)

        evidence = Evidence(
            evidence_id=evidence_id,
            type=evidence_type,
            path=rel_path,
            original_path=str(source),
            sha256=sha256,
            size=size,
            collected_at=datetime.now(UTC).isoformat(),
            collector=collector,
            notes=notes,
        )
        case.evidences.append(evidence)
        self._save_case(case)
        return evidence

    def _hash_tree(self, directory: Path) -> tuple[str, int]:
        """对目录证据计算确定性哈希（相对路径 + 内容逐项哈希后总哈希）。

        Returns:
            (总哈希, 清单序列化大小)
        """
        hasher = hashlib.sha256()
        entries = sorted(p for p in directory.rglob("*") if p.is_file())
        for file_path in entries:
            rel = file_path.relative_to(directory).as_posix()
            hasher.update(rel.encode("utf-8"))
            hasher.update(file_path.read_bytes())
        return hasher.hexdigest(), sum(f.stat().st_size for f in entries)

    def get_evidence_path(self, case_id: str, evidence_id: str) -> Path:
        """解析证据的实际存储路径。

        Raises:
            CaseError: 证据不存在或路径越界
        """
        case = self.load_case(case_id)
        evidence = next((e for e in case.evidences if e.evidence_id == evidence_id), None)
        if evidence is None:
            raise CaseError(f"证据不存在: {evidence_id}")
        if not evidence.path:
            # 外部登记路径
            return Path(evidence.original_path)
        resolved = (self.case_dir(case_id) / evidence.path).resolve()
        case_root = self.case_dir(case_id).resolve()
        if not str(resolved).startswith(str(case_root)):
            raise CaseError(f"证据路径越界: {evidence.path}")
        return resolved

    # ------------------------- 完整性验证 -------------------------

    def verify_case(self, case_id: str) -> VerificationResult:
        """验证案件证据链完整性（重算全部证据哈希对照清单）。

        Returns:
            VerificationResult（passed=True 表示证据链未被篡改）
        """
        case = self.load_case(case_id)
        result = VerificationResult(case_id=case_id)
        for evidence in case.evidences:
            result.checked_count += 1
            try:
                evidence_path = self.get_evidence_path(case_id, evidence.evidence_id)
            except CaseError as e:
                result.failures.append({"evidence_id": evidence.evidence_id, "reason": str(e)})
                continue
            if not Path(evidence_path).exists():
                result.failures.append(
                    {
                        "evidence_id": evidence.evidence_id,
                        "reason": f"证据文件缺失: {evidence_path}",
                    }
                )
                continue
            path = Path(evidence_path)
            if path.is_dir():
                actual_sha, _ = self._hash_tree(path)
            else:
                actual_sha = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_sha != evidence.sha256:
                result.failures.append(
                    {
                        "evidence_id": evidence.evidence_id,
                        "reason": f"SHA256 不匹配（可能被篡改）: 清单 {evidence.sha256[:16]}... 实际 {actual_sha[:16]}...",
                    }
                )
                continue
            result.passed_count += 1
        return result

    # ------------------------- 报告导出 -------------------------

    def export_report(self, case_id: str, output_path: str | Path | None = None) -> Path:
        """导出案件 JSON 报告（清单 + 证据链，可直接归档）。

        Args:
            case_id: 案件 ID
            output_path: 报告输出路径（None 写入案件目录 report.json）

        Returns:
            报告文件路径
        """
        case = self.load_case(case_id)
        verification = self.verify_case(case_id)
        report: dict[str, Any] = {
            **case.to_dict(),
            "verification": verification.to_dict(),
            "exported_at": datetime.now(UTC).isoformat(),
        }
        target = (
            Path(output_path) if output_path is not None else self.case_dir(case_id) / "report.json"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return target
