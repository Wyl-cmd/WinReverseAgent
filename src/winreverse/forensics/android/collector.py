"""winreverse.forensics.android.collector — Android 取证采集编排。

将 AdbClient 的只读采集能力与 CaseManager 的证据链管理编排起来：
- 设备信息快照 → 落盘 JSON → 入案（ANDROID_DATA）
- 已安装包清单 → 落盘 → 入案
- 文件拉取 → 复制入案
- LiME 内存采集 → 生成引导（GPL 隔离，不自动执行）
- 镜像分析 → Volatility 3 桥接（VSL，运行时安装）

所有产物作为证据登记，自动建立 SHA256 基线。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from winreverse.forensics.android.adb import AdbClient, DeviceInfo
from winreverse.forensics.android.lime import LimeGuide, build_lime_guide
from winreverse.forensics.case import CaseManager, EvidenceType


class CollectError(RuntimeError):
    """采集编排失败的统一异常。"""


@dataclass
class CollectResult:
    """一次采集动作的结果。

    Attributes:
        evidence_id: 证据 ID
        stored_path: 产物在案件内的存储路径
        sha256: 证据哈希
        summary: 人可读摘要
    """

    evidence_id: str
    stored_path: str
    sha256: str
    summary: str

    def to_dict(self) -> dict[str, str]:
        """转为 JSON 兼容字典。"""
        return {
            "evidence_id": self.evidence_id,
            "stored_path": self.stored_path,
            "sha256": self.sha256,
            "summary": self.summary,
        }


class AndroidCollector:
    """Android 取证采集编排器（adb 只读采集 + 证据链入案）。"""

    def __init__(
        self,
        case_manager: CaseManager,
        adb: AdbClient | None = None,
        *,
        work_root: str | Path = "output/android_collect",
    ) -> None:
        """初始化采集编排器。

        Args:
            case_manager: 案件管理器（证据落库目标）
            adb: adb 客户端（None 延迟到首次使用时构造，避免无 adb 时初始化失败）
            work_root: 采集中间产物根目录
        """
        self._cases = case_manager
        self._adb = adb
        self._work_root = Path(work_root)

    @property
    def adb(self) -> AdbClient:
        """adb 客户端（懒构造）。"""
        if self._adb is None:
            self._adb = AdbClient()
        return self._adb

    def _collect_work_dir(self, case_id: str, kind: str) -> Path:
        """采集中间产物目录：work_root/<case_id>/<kind>_<时间戳>。"""
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        return self._work_root / case_id / f"{kind}_{timestamp}"

    def _register(
        self,
        case_id: str,
        evidence_type: EvidenceType,
        product: Path,
        *,
        collector: str,
        notes: str = "",
    ) -> CollectResult:
        """将采集产物登记为案件证据。"""
        evidence = self._cases.add_evidence(
            case_id, evidence_type, product, collector=collector, notes=notes
        )
        try:
            stored = self._cases.get_evidence_path(case_id, evidence.evidence_id)
        except Exception:
            stored = product
        return CollectResult(
            evidence_id=evidence.evidence_id,
            stored_path=str(stored),
            sha256=evidence.sha256,
            summary=notes or collector,
        )

    # ------------------------- 采集动作 -------------------------

    def collect_device_info(self, case_id: str, serial: str) -> CollectResult:
        """采集设备属性快照并入案。

        Raises:
            CollectError: adb 不可用 / 设备离线 / 案件不存在
        """
        info: DeviceInfo = self.adb.get_device_info(serial)
        product = self._collect_work_dir(case_id, "device_info")
        product.mkdir(parents=True, exist_ok=True)
        (product / "getprop_snapshot.json").write_text(
            json.dumps(info.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return self._register(
            case_id,
            EvidenceType.ANDROID_DATA,
            product,
            collector=f"adb getprop serial={serial}",
            notes=f"{info.brand} {info.model} Android {info.android_version} "
            f"(补丁 {info.security_patch or '未知'})",
        )

    def collect_packages(self, case_id: str, serial: str) -> CollectResult:
        """采集已安装第三方应用清单并入案。"""
        packages = self.adb.list_packages(serial, third_party_only=True)
        product = self._collect_work_dir(case_id, "packages")
        product.mkdir(parents=True, exist_ok=True)
        (product / "third_party_packages.txt").write_text(
            "\n".join(packages) + "\n", encoding="utf-8"
        )
        return self._register(
            case_id,
            EvidenceType.ANDROID_DATA,
            product,
            collector=f"adb pm list -3 serial={serial}",
            notes=f"第三方应用 {len(packages)} 个",
        )

    def collect_processes(self, case_id: str, serial: str) -> CollectResult:
        """采集进程快照并入案。"""
        processes = self.adb.list_processes(serial)
        product = self._collect_work_dir(case_id, "processes")
        product.mkdir(parents=True, exist_ok=True)
        (product / "ps_snapshot.json").write_text(
            json.dumps(processes, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return self._register(
            case_id,
            EvidenceType.ANDROID_DATA,
            product,
            collector=f"adb ps -A serial={serial}",
            notes=f"进程 {len(processes)} 个",
        )

    def collect_file(self, case_id: str, serial: str, remote_path: str) -> CollectResult:
        """拉取设备文件并入案。

        Raises:
            CollectError: 拉取失败
        """
        product = self._collect_work_dir(case_id, "file")
        try:
            pulled = self.adb.pull_file(serial, remote_path, product / "pulled")
        except Exception as e:
            raise CollectError(f"文件拉取失败: {remote_path}: {e}") from e
        return self._register(
            case_id,
            EvidenceType.ANDROID_DATA,
            pulled,
            collector=f"adb pull serial={serial}",
            notes=f"远端路径 {remote_path}",
        )

    def lime_guide(
        self,
        serial: str,
        *,
        local_module_path: str = "lime.ko",
        dump_path: str = "/data/local/tmp/ram.lime",
    ) -> LimeGuide:
        """生成 LiME 内存采集引导（GPL 隔离，不自动执行）。"""
        # 尽力获取内核版本以提示匹配性；失败不阻断引导
        kernel_release = self.adb.get_kernel_release(serial)
        return build_lime_guide(
            serial,
            kernel_release=kernel_release,
            local_module_path=local_module_path,
            dump_path=dump_path,
        )
