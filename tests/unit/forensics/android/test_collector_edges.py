"""被测模块: winreverse.forensics.android.collector（边界路径）。

覆盖点: CollectResult.to_dict 序列化 / adb 懒构造与缓存 /
_register 取证路径回退 / collect_file 拉取失败包装为 CollectError。
全部 mock adb 子进程，无真机依赖，Linux 可实跑。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from winreverse.forensics.android import collector as collector_module
from winreverse.forensics.android.adb import AdbClient
from winreverse.forensics.android.collector import AndroidCollector, CollectError, CollectResult
from winreverse.forensics.case import CaseManager


class FakeAdb(AdbClient):
    """绕过二进制解析的 adb 桩（不调用 _resolve_adb）。"""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def list_processes(self, serial: str) -> list[dict[str, Any]]:
        self.calls.append(f"ps:{serial}")
        return [{"pid": "1", "name": "system_server"}]


class PullFailAdb(FakeAdb):
    """pull_file 恒失败的 adb 桩。"""

    def pull_file(self, serial: str, remote_path: str, dest: Path) -> Path:
        raise OSError(f"device '{serial}' offline")


def _make_case(tmp_path: Path) -> tuple[CaseManager, str]:
    manager = CaseManager(tmp_path / "cases")
    case = manager.create_case("collector 边界")
    return manager, case.case_id


class TestCollectResultToDict:
    """CollectResult.to_dict 全字段序列化。"""

    def test_to_dict_roundtrip_all_fields(self) -> None:
        result = CollectResult(
            evidence_id="EV-1",
            stored_path="cases/c1/evidence/ps",
            sha256="abc",
            summary="进程 1 个",
        )
        data = result.to_dict()
        assert data == {
            "evidence_id": "EV-1",
            "stored_path": "cases/c1/evidence/ps",
            "sha256": "abc",
            "summary": "进程 1 个",
        }


class TestLazyAdbProperty:
    """adb 属性懒构造且缓存（None → 首次访问构造，之后复用）。"""

    def test_adb_lazy_constructed_and_cached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager, _ = _make_case(tmp_path)
        collector = AndroidCollector(manager, None, work_root=tmp_path / "work")
        assert collector._adb is None

        constructed: list[FakeAdb] = []

        def fake_factory() -> FakeAdb:
            stub = FakeAdb()
            constructed.append(stub)
            return stub

        monkeypatch.setattr(collector_module, "AdbClient", fake_factory)
        first = collector.adb
        second = collector.adb
        assert constructed == [first]
        assert first is second


class TestRegisterPathFallback:
    """_register 在取证据路径失败时回退到原始产物路径。"""

    def test_collect_processes_falls_back_to_product_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager, case_id = _make_case(tmp_path)
        adb = FakeAdb()
        collector = AndroidCollector(manager, adb, work_root=tmp_path / "work")
        monkeypatch.setattr(
            manager,
            "get_evidence_path",
            lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("证据目录缺失")),
        )

        result = collector.collect_processes(case_id, "emulator-5554")

        assert result.evidence_id
        assert "processes_" in result.stored_path
        assert Path(result.stored_path).is_dir()
        assert result.sha256
        assert result.summary == "进程 1 个"
        json_snapshot = Path(result.stored_path) / "ps_snapshot.json"
        assert json_snapshot.is_file()
        assert "system_server" in json_snapshot.read_text(encoding="utf-8")


class TestCollectFileFailure:
    """collect_file 拉取异常包装为 CollectError 且保留上下文。"""

    def test_pull_failure_raises_collect_error(self, tmp_path: Path) -> None:
        manager, case_id = _make_case(tmp_path)
        collector = AndroidCollector(manager, PullFailAdb(), work_root=tmp_path / "work")

        with pytest.raises(CollectError, match=r"文件拉取失败.*offline") as excinfo:
            collector.collect_file(case_id, "emulator-5554", "/data/local/tmp/evil.so")

        assert "/data/local/tmp/evil.so" in str(excinfo.value)
