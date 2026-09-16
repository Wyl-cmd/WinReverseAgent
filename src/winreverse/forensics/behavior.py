"""winreverse.forensics.behavior — 动态行为监控（进程隔离后端）。

实现 engine.sandbox_runner.SandboxRunner 契约的进程隔离后端
（原 M8 规划的 C 方案），**即插即用**设计：
- 零环境配置：不装驱动 / 不启用 Windows Sandbox / 不写系统目录，
  任何 Windows 10/11（含 Home）解压即用
- 零新依赖：psutil（已有）+ winreg（标准库）+ 子进程启动
- 原理：运行样本前后对「进程 / 网络 / 文件 / 注册表」四个维度
  做高频快照 diff，把增量记为行为事件

监控维度：
1. 进程：样本及其子进程树的创建（cmdline 记录 → IOC）
2. 网络：样本树发起的远端连接（地址/端口 → IOC）
3. 文件：监控目录的释放/修改（沙箱副本目录 + 用户指定目录）
4. 注册表：持久化键的变更（Run/RunOnce 等，可配置）

风险评分（规则版，0-100）：外联、持久化、释放可执行文件、
创建子进程等行为按权重累加封顶。

隔离与清理：样本副本只在会话目录内运行；destroy 终止残留进程树
并删除副本，仅保留行为报告（原始样本不被触碰）。

Windows Sandbox 增强：见 sandbox_wsb.py（检测到可用时才建议使用，
本模块不依赖）。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from winreverse.core.memanalysis_api import extract_iocs_from_text

# 会话目录根（相对工作目录）
_SESSIONS_ROOT = Path("output") / "behavior_sessions"

# 可执行扩展名（释放物风险判定）
_EXECUTABLE_EXTS = (".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".com", ".pif")

# 风险权重（因子名 → 分值）
_RISK_WEIGHTS: dict[str, int] = {
    "外联网络": 20,
    "注册表持久化": 25,
    "释放可执行文件": 20,
    "创建子进程": 10,
    "写入监控目录": 5,
}
_RISK_CAP = 100


class BehaviorError(RuntimeError):
    """行为监控失败的统一异常。"""


@dataclass
class BehaviorEvent:
    """单条行为事件。

    Attributes:
        timestamp: 事件时间（UTC ISO 格式）
        kind: 事件类型（process / network / file / registry）
        detail: 事件明细
        risk: 该事件贡献的风险分（0 表示仅记录）
        factor: 风险因子名（risk 为 0 时为空）
    """

    timestamp: str
    kind: str
    detail: dict[str, Any]
    risk: int = 0
    factor: str = ""

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {
            "timestamp": self.timestamp,
            "kind": self.kind,
            "detail": self.detail,
            "risk": self.risk,
            "factor": self.factor,
        }


@dataclass
class BehaviorReport:
    """一次行为监控的完整报告。

    Attributes:
        session_id: 会话 ID
        sample: 样本文件名
        duration_seconds: 实际监控时长
        exit_code: 样本退出码（仍运行/启动失败时为 None）
        events: 行为事件列表（按时间升序）
        process_tree: 样本进程树（pid/ppid/cmdline）
        outbound_connections: 远端连接去重列表
        dropped_files: 释放/修改的文件列表
        iocs: 从命令行/网络/文件路径提取的 IOC
        risk_score: 风险评分（0-100）
        risk_factors: 命中的风险因子（去重）
    """

    session_id: str
    sample: str
    duration_seconds: float = 0.0
    exit_code: int | None = None
    events: list[BehaviorEvent] = field(default_factory=list)
    process_tree: list[dict[str, Any]] = field(default_factory=list)
    outbound_connections: list[str] = field(default_factory=list)
    dropped_files: list[str] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """转为 JSON 兼容字典。"""
        return {
            "session_id": self.session_id,
            "sample": self.sample,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "process_tree": self.process_tree,
            "outbound_connections": self.outbound_connections,
            "dropped_files": self.dropped_files,
            "iocs": self.iocs,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BehaviorReport:
        """从 JSON 字典构造（加载已落盘报告）。"""
        report = cls(
            session_id=str(data.get("session_id", "")),
            sample=str(data.get("sample", "")),
            duration_seconds=float(data.get("duration_seconds", 0)),
            exit_code=data.get("exit_code"),
        )
        report.events = [
            BehaviorEvent(
                timestamp=str(e.get("timestamp", "")),
                kind=str(e.get("kind", "")),
                detail=dict(e.get("detail", {})),
                risk=int(e.get("risk", 0)),
                factor=str(e.get("factor", "")),
            )
            for e in data.get("events", [])
            if isinstance(e, dict)
        ]
        report.process_tree = list(data.get("process_tree", []))
        report.outbound_connections = list(data.get("outbound_connections", []))
        report.dropped_files = list(data.get("dropped_files", []))
        report.iocs = list(data.get("iocs", []))
        report.risk_score = int(data.get("risk_score", 0))
        report.risk_factors = list(data.get("risk_factors", []))
        return report


# =============================================================================
# 快照助手（四维）
# =============================================================================


def _snapshot_processes() -> dict[int, dict[str, Any]]:
    """进程快照：pid → (ppid, name, cmdline, create_time)。"""
    snapshot: dict[int, dict[str, Any]] = {}
    for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "create_time"]):
        try:
            snapshot[proc.info["pid"]] = {
                "ppid": proc.info["ppid"],
                "name": proc.info["name"] or "",
                "cmdline": " ".join(proc.info["cmdline"] or [])[:500],
                "create_time": proc.info["create_time"] or 0,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return snapshot


def _process_info(pid: int) -> dict[str, Any] | None:
    """单个进程的四要素（ppid/name/cmdline/create_time）。

    进程已退出 / 无权限时返回 None —— 供样本启动瞬间归档进程信息，
    避免短命样本退出后进程树无法重建（真机实测 2026-09-15 暴露）。
    """
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            return {
                "ppid": proc.ppid(),
                "name": proc.name() or "",
                "cmdline": " ".join(proc.cmdline() or [])[:500],
                "create_time": proc.create_time() or 0,
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _snapshot_connections() -> set[str]:
    """网络连接快照：远端 endpoint 集合（排除回环/未连接）。"""
    endpoints: set[str] = set()
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return endpoints
    for conn in connections:
        remote = conn.raddr
        if not remote:
            continue
        if remote.ip in ("127.0.0.1", "::1", "0.0.0.0"):
            continue
        endpoints.add(f"{remote.ip}:{remote.port}")
    return endpoints


def _snapshot_dir(directory: Path) -> dict[str, tuple[float, int]]:
    """目录树快照：相对路径 → (mtime, size)。"""
    snapshot: dict[str, tuple[float, int]] = {}
    if not directory.is_dir():
        return snapshot
    for file_path in directory.rglob("*"):
        if file_path.is_file():
            try:
                stat = file_path.stat()
                snapshot[file_path.relative_to(directory).as_posix()] = (
                    stat.st_mtime,
                    stat.st_size,
                )
            except OSError:
                continue
    return snapshot


def _diff_dir_snapshots(
    before: dict[str, tuple[float, int]],
    after: dict[str, tuple[float, int]],
) -> list[str]:
    """目录快照 diff：新增或变化的文件相对路径。"""
    changed: list[str] = []
    for rel, (mtime, size) in after.items():
        old = before.get(rel)
        if old is None or abs(old[0] - mtime) > 1e-6 or old[1] != size:
            changed.append(rel)
    return sorted(changed)


def _file_factor(rel_path: str) -> str:
    """文件事件 → 风险因子（可执行释放 / 普通写入）。"""
    if rel_path.lower().endswith(_EXECUTABLE_EXTS):
        return "释放可执行文件"
    return "写入监控目录"


def _read_registry_key(hive: int, subkey: str) -> dict[str, str]:
    """读取注册表键的全部值（键不存在返回空）。"""
    import winreg

    values: dict[str, str] = {}
    try:
        with winreg.OpenKey(hive, subkey) as key:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                values[str(name)] = str(value)
                index += 1
    except OSError:
        pass
    return values


def _default_registry_keys() -> list[tuple[int, str]]:
    """默认监控的持久化注册表键（非 Windows 平台返回空）。"""
    try:
        import winreg
    except ImportError:
        return []
    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    run_once = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    return [
        (winreg.HKEY_CURRENT_USER, run_key),
        (winreg.HKEY_CURRENT_USER, run_once),
    ]


def _snapshot_registry(keys: list[tuple[int, str]]) -> dict[str, dict[str, str]]:
    """注册表快照：'HKCU\\子键' → 值字典。"""
    import winreg

    hive_names = {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM"}
    snapshot: dict[str, dict[str, str]] = {}
    for hive, subkey in keys:
        label = f"{hive_names.get(hive, str(hive))}\\{subkey}"
        snapshot[label] = _read_registry_key(hive, subkey)
    return snapshot


def _registry_diff(
    before: dict[str, dict[str, str]],
    after: dict[str, dict[str, str]],
) -> list[tuple[str, str, str]]:
    """注册表 diff：返回 (键路径, 值名, 新值) 列表。"""
    changes: list[tuple[str, str, str]] = []
    for label, values in after.items():
        baseline_values = before.get(label, {})
        for name, value in values.items():
            if baseline_values.get(name) != value:
                changes.append((label, name, value))
    return changes


def _sample_tree_connections(pids: set[int]) -> set[str]:
    """收集样本树进程的远端连接 endpoint。"""
    endpoints: set[str] = set()
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            for conn in proc.net_connections(kind="inet"):
                remote = conn.raddr
                if remote and remote.ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                    endpoints.add(f"{remote.ip}:{remote.port}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return endpoints


def _launcher_command(sample_path: Path) -> list[str]:
    """按样本类型构造启动命令（脚本类样本经解释器启动）。

    必须用绝对路径：Popen 的 cwd 已切到沙箱副本目录，
    相对路径会基于新 cwd 解析而失效。
    """
    absolute = str(sample_path.resolve())
    suffix = sample_path.suffix.lower()
    if suffix in (".bat", ".cmd"):
        return ["cmd.exe", "/c", absolute]
    if suffix == ".ps1":
        return [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            absolute,
        ]
    return [absolute]


def _now_iso() -> str:
    """当前 UTC ISO 时间。"""
    return datetime.now(UTC).isoformat()


def _dumps(data: dict[str, Any]) -> str:
    """JSON 序列化（ensure_ascii=False + 缩进）。"""
    return json.dumps(data, ensure_ascii=False, indent=2)


# =============================================================================
# 会话状态
# =============================================================================


@dataclass
class _Session:
    """行为监控会话内部状态。"""

    session_id: str
    sample_path: Path
    isolated_path: Path
    session_dir: Path
    watch_dirs: list[Path]
    registry_keys: list[tuple[int, str]]
    baseline_processes: dict[int, dict[str, Any]] = field(default_factory=dict)
    baseline_connections: set[str] = field(default_factory=set)
    baseline_files: dict[Path, dict[str, tuple[float, int]]] = field(default_factory=dict)
    baseline_registry: dict[str, dict[str, str]] = field(default_factory=dict)
    proc: subprocess.Popen[bytes] | None = None
    sample_pids: set[int] = field(default_factory=set)
    # 样本树进程信息归档（pid → 四要素）：样本退出后仍可重建进程树
    sample_process_info: dict[int, dict[str, Any]] = field(default_factory=dict)
    ran: bool = False
    report: BehaviorReport | None = None


# =============================================================================
# 进程隔离行为监控后端（实现 SandboxRunner 契约）
# =============================================================================


class ProcessIsolationRunner:
    """进程隔离行为监控后端（即插即用，实现 SandboxRunner 契约）。

    用法：
        runner = ProcessIsolationRunner()
        session = runner.prepare("sample.exe", {})
        runner.run(session, duration=30)
        report = runner.collect(session)
        runner.destroy(session)
    """

    def __init__(
        self,
        *,
        sessions_root: str | Path | None = None,
        watch_dirs: list[str | Path] | None = None,
        registry_keys: list[tuple[int, str]] | None = None,
        poll_interval: float = 0.5,
    ) -> None:
        """初始化后端。

        Args:
            sessions_root: 会话目录根（默认 output/behavior_sessions）
            watch_dirs: 额外监控的目录（默认监控样本副本所在目录）
            registry_keys: 注册表监控键（None 用默认持久化键）
            poll_interval: 轮询间隔（秒）
        """
        self._sessions_root = Path(sessions_root) if sessions_root is not None else _SESSIONS_ROOT
        self._watch_dirs = [Path(d) for d in (watch_dirs or [])]
        self._registry_keys = (
            registry_keys if registry_keys is not None else _default_registry_keys()
        )
        self._poll_interval = poll_interval
        self._sessions: dict[str, _Session] = {}

    # ------------------------- SandboxRunner 契约 -------------------------

    def prepare(self, sample_path: str, config: dict[str, Any]) -> str:
        """复制样本到隔离会话目录并建立四维基线快照。

        Args:
            sample_path: 样本文件路径
            config: 兼容 SandboxRunner 契约（当前无必填项）

        Returns:
            会话 ID

        Raises:
            BehaviorError: 样本不存在
        """
        sample = Path(sample_path)
        if not sample.is_file():
            raise BehaviorError(f"样本不存在: {sample}")
        _ = config
        session_id = f"bhv_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
        session_dir = self._sessions_root / session_id
        sandbox_dir = session_dir / "sandbox"
        sandbox_dir.mkdir(parents=True, exist_ok=True)

        isolated_path = sandbox_dir / sample.name
        shutil.copy2(sample, isolated_path)

        watch_dirs = [sandbox_dir, *self._watch_dirs]
        baseline_files = {d: _snapshot_dir(d) for d in watch_dirs}

        session = _Session(
            session_id=session_id,
            sample_path=sample,
            isolated_path=isolated_path,
            session_dir=session_dir,
            watch_dirs=watch_dirs,
            registry_keys=self._registry_keys,
            baseline_processes=_snapshot_processes(),
            baseline_connections=_snapshot_connections(),
            baseline_files=baseline_files,
            baseline_registry=_snapshot_registry(self._registry_keys),
            report=BehaviorReport(session_id=session_id, sample=sample.name),
        )
        self._sessions[session_id] = session
        return session_id

    def run(self, session_id: str, duration: int) -> dict[str, Any]:
        """启动样本并轮询采集行为事件，直到样本退出或超时。

        Args:
            session_id: prepare 返回的会话 ID
            duration: 监控时长（秒，1-3600）

        Returns:
            事件流摘要（完整数据经 collect 获取）

        Raises:
            BehaviorError: 会话不存在 / 已运行 / 样本启动失败
        """
        session = self._require_session(session_id)
        if session.proc is not None or session.ran:
            raise BehaviorError("会话已运行")

        duration = max(1, min(int(duration), 3600))
        started = time.monotonic()

        # .bat/.cmd/.ps1 必须经解释器启动，直接 Popen 会静默失败
        try:
            session.proc = subprocess.Popen(
                _launcher_command(session.isolated_path),
                cwd=str(session.isolated_path.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as e:
            raise BehaviorError(f"样本启动失败: {e}") from e
        session.sample_pids.add(session.proc.pid)
        root_info = _process_info(session.proc.pid)
        if root_info is not None:
            # 样本自身进程在启动瞬间归档（它通常不会出现在子进程事件里）
            session.sample_process_info[session.proc.pid] = root_info
        session.ran = True

        try:
            self._poll_loop(session, duration, started)
        finally:
            self._final_diff(session)

        report = session.report
        assert report is not None
        report.duration_seconds = round(time.monotonic() - started, 2)
        if session.proc is not None:
            try:
                report.exit_code = session.proc.poll()
            except OSError:
                report.exit_code = None

        self._score_and_extract(session)
        return {
            "session_id": session_id,
            "event_count": len(report.events),
            "outbound": len(report.outbound_connections),
            "dropped": len(report.dropped_files),
            "risk_score": report.risk_score,
        }

    def collect(self, session_id: str) -> dict[str, Any]:
        """收集完整行为报告（落盘 behavior_report.json）。

        Raises:
            BehaviorError: 会话不存在 / 尚未运行
        """
        session = self._require_session(session_id)
        report = session.report
        if not session.ran or report is None:
            raise BehaviorError("尚未运行样本（先调用 run）")
        data = report.to_dict()
        report_path = session.session_dir / "behavior_report.json"
        report_path.write_text(_dumps(data), encoding="utf-8")
        data["report_path"] = str(report_path)
        return data

    def destroy(self, session_id: str) -> None:
        """终止样本残留进程树并删除会话副本（保留行为报告）。

        Raises:
            BehaviorError: 会话不存在
        """
        session = self._require_session(session_id)
        for pid in list(session.sample_pids):
            try:
                proc = psutil.Process(pid)
                for child in proc.children(recursive=True):
                    child.terminate()
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        session.sample_pids.clear()
        shutil.rmtree(session.isolated_path.parent, ignore_errors=True)
        self._sessions.pop(session_id, None)

    # ------------------------- 内部逻辑 -------------------------

    def _require_session(self, session_id: str) -> _Session:
        """获取会话（不存在抛错）。"""
        session = self._sessions.get(session_id)
        if session is None:
            raise BehaviorError(f"会话不存在: {session_id}")
        return session

    def _poll_loop(self, session: _Session, duration: int, started: float) -> None:
        """轮询 diff：进程 / 网络 / 文件 / 注册表四维增量。"""
        report = session.report
        assert report is not None
        while time.monotonic() - started < duration:
            time.sleep(self._poll_interval)
            self._diff_processes(session)
            self._diff_network(session)
            self._diff_files(session)
            self._diff_registry(session)

            # 样本提前退出则结束
            if session.proc is not None and session.proc.poll() is not None:
                break

    def _diff_processes(self, session: _Session) -> None:
        """进程维度 diff：识别样本树内新增的子进程。"""
        report = session.report
        assert report is not None
        current = _snapshot_processes()
        known = set(session.baseline_processes) | session.sample_pids
        for pid, info in current.items():
            if pid in known:
                continue
            if info["ppid"] in session.sample_pids:
                # 样本树内的子进程
                session.sample_pids.add(pid)
                session.sample_process_info[pid] = {k: v for k, v in info.items() if k != "pid"}
                report.events.append(
                    BehaviorEvent(
                        timestamp=_now_iso(),
                        kind="process",
                        detail={"pid": pid, **info},
                        risk=_RISK_WEIGHTS["创建子进程"],
                        factor="创建子进程",
                    )
                )
        session.baseline_processes = current

    def _diff_network(self, session: _Session) -> None:
        """网络维度 diff：样本树新增的远端连接。"""
        report = session.report
        assert report is not None
        current_endpoints = _snapshot_connections()
        sample_endpoints = _sample_tree_connections(session.sample_pids)
        new_endpoints = sample_endpoints - session.baseline_connections - current_endpoints
        for endpoint in sorted(new_endpoints):
            report.events.append(
                BehaviorEvent(
                    timestamp=_now_iso(),
                    kind="network",
                    detail={"remote": endpoint},
                    risk=_RISK_WEIGHTS["外联网络"],
                    factor="外联网络",
                )
            )
            if endpoint not in report.outbound_connections:
                report.outbound_connections.append(endpoint)
        session.baseline_connections |= current_endpoints

    def _diff_files(self, session: _Session) -> None:
        """文件维度 diff：监控目录的新增/变更文件。"""
        report = session.report
        assert report is not None
        for watch_dir in session.watch_dirs:
            baseline = session.baseline_files.get(watch_dir, {})
            for rel in _diff_dir_snapshots(baseline, _snapshot_dir(watch_dir)):
                factor = _file_factor(rel)
                report.events.append(
                    BehaviorEvent(
                        timestamp=_now_iso(),
                        kind="file",
                        detail={"path": str(watch_dir / rel)},
                        risk=_RISK_WEIGHTS[factor],
                        factor=factor,
                    )
                )
                if rel not in report.dropped_files:
                    report.dropped_files.append(rel)
            session.baseline_files[watch_dir] = _snapshot_dir(watch_dir)

    def _diff_registry(self, session: _Session) -> None:
        """注册表维度 diff：持久化键变更。"""
        report = session.report
        assert report is not None
        for key_path, name, value in _registry_diff(
            session.baseline_registry, _snapshot_registry(session.registry_keys)
        ):
            report.events.append(
                BehaviorEvent(
                    timestamp=_now_iso(),
                    kind="registry",
                    detail={"key": key_path, "name": name, "value": value},
                    risk=_RISK_WEIGHTS["注册表持久化"],
                    factor="注册表持久化",
                )
            )
        session.baseline_registry = _snapshot_registry(session.registry_keys)

    def _final_diff(self, session: _Session) -> None:
        """收尾做一次最终 diff（捕获轮询间隙的尾部行为）。"""
        self._diff_registry(session)

    def _score_and_extract(self, session: _Session) -> None:
        """按事件计算风险评分、汇总进程树并提取 IOC。"""
        report = session.report
        assert report is not None

        processes = _snapshot_processes()
        for pid in sorted(session.sample_pids):
            # 样本树进程优先取实时快照；进程已退出则回退到归档信息
            # （短命样本收尾时 pid 已不存在，仅靠实时快照会丢整棵进程树）
            info = processes.get(pid) or session.sample_process_info.get(pid)
            if info:
                report.process_tree.append({"pid": pid, **info})

        score = 0
        factors: list[str] = []
        for event in report.events:
            if event.risk <= 0:
                continue
            score += event.risk
            if event.factor and event.factor not in factors:
                factors.append(event.factor)
        report.risk_score = min(score, _RISK_CAP)
        report.risk_factors = factors

        # IOC：命令行 + 网络 + 文件路径拼接后复用内存取证的 IOC 规则
        text_pool = "\n".join(
            [
                *(info.get("cmdline", "") for info in report.process_tree),
                *report.outbound_connections,
                *report.dropped_files,
                *[str(e.detail.get("cmdline", "")) for e in report.events if e.kind == "process"],
            ]
        )
        all_hits = extract_iocs_from_text(text_pool)
        # 过滤已知噪音（回环地址 / 系统目录），保留真实线索
        noise_prefixes = (
            "127.0.0.1",
            "::1",
            "C:\\WINDOWS",
            "C:\\Users\\WDAGUtility",
        )
        noise_upper = tuple(n.upper() for n in noise_prefixes)
        report.iocs = [
            hit.to_dict() for hit in all_hits if not hit.value.upper().startswith(noise_upper)
        ]
