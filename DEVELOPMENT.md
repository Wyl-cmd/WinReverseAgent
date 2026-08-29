# WinReverseAgent 开发流程与规范

> 本文档记录测试代码编写规范、测试框架搭建步骤、项目本体构建流程及各阶段验收标准。
> 环境基线对齐 KXNSv2（uv + hatchling + src layout + pytest），增强项为 black/ruff/mypy 代码质量工具链（import 排序由 ruff 内置 I 规则统一处理）。

## 文档信息

| 字段 | 值 |
|---|---|
| 版本 | v1.0 |
| 日期 | 2026-07-26 |
| 适用阶段 | M1-M10 全程 |
| 关联文档 | [Windows原生逆向Agent_实施方案.md](../Windows原生逆向Agent_实施方案.md) |

---

## 一、环境基线与工具链

### 1.1 环境要求

| 项 | 版本 | 说明 |
|---|---|---|
| 操作系统 | Windows 10/11 64 位 | 逆向专用，Linux/macOS 不支持 |
| Python | 3.12+ | 对齐 KXNS `requires-python = ">=3.12"` |
| 包管理 | uv 0.9+ | 对齐 KXNS，使用 workspace + lock |
| 构建后端 | hatchling | 对齐 KXNS |
| 代码风格 | black + ruff + mypy（import 排序由 ruff 内置 I 规则统一处理） | 实施方案 §1.4.1 硬约束（KXNS 未配置，本项目增强） |
| 测试框架 | pytest 8+ + pytest-asyncio + pytest-cov | 对齐 KXNS + 增加覆盖率 |

### 1.2 一次性环境准备

```powershell
# 1. 安装 uv（如未安装）
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# 2. 进入项目根目录
cd h:\work\trea\win-逆向agent\WinReverseAgent

# 3. 同步全部依赖（含 dev 组）
uv sync --group dev

# 4. 安装逆向专用依赖（可选，按需）
uv sync --extra reverse

# 5. 验证环境
uv run winreverse-doctor
```

### 1.3 工具链命令速查

| 任务 | 命令 |
|---|---|
| 同步依赖 | `uv sync --group dev` |
| 增加依赖 | 编辑 `pyproject.toml` 后 `uv sync` |
| 运行单元测试 | `uv run pytest tests/unit -q` |
| 运行全量测试（不含 live） | `.\scripts\test_ci.ps1` |
| 运行本机完整验收（含 live） | `.\scripts\test_local.ps1` |
| Lint 检查 | `uv run ruff check .` |
| 格式化 | `uv run ruff format .` |
| 类型检查 | `uv run mypy src/winreverse` |
| import 排序 | `uv run ruff check --select I --fix .` |
| 覆盖率报告 | `uv run pytest --cov-report=html:output/coverage/html` |
| 全量质量门禁 | `.\scripts\lint.ps1` |

---

## 二、目录结构与职责

### 2.1 项目目录布局（src layout，对齐 KXNS）

```
WinReverseAgent/
├── pyproject.toml              # 项目配置（依赖、工具链、pytest、black/ruff/mypy）
├── uv.lock                     # uv 锁文件（对齐 KXNS）
├── .python-version             # Python 版本（3.12）
├── README.md                   # 项目说明
├── DEVELOPMENT.md              # 本文档
│
├── src/                        # 源码根（src layout）
│   └── winreverse/             # 主包
│       ├── __init__.py
│       ├── __main__.py         # python -m winreverse 入口
│       ├── app.py              # Agent 主入口
│       ├── doctor.py           # 环境自检
│       ├── cli/                # Typer CLI
│       ├── core/               # 能力封装层（pymem/pefile/capstone 薄包装）
│       ├── engine/             # 工具调度层（bus/context/injector/mcp_adapter）
│       ├── soul/               # Soul 引擎（复用 KXNS）
│       ├── llm/                # LLM 适配层（复用 KXNS）
│       ├── skill/              # Skill 引擎（复用 + 扩展 YAML）
│       ├── tools/              # 工具更新器等
│       ├── config/             # 配置系统
│       ├── session/            # 会话管理
│       ├── wire/               # 事件流
│       ├── background/         # 后台任务
│       ├── ui/                 # UI（shell/tui）
│       └── utils/              # 工具函数
│
├── packages/                   # uv workspace 成员
│   └── kosong/                 # LLM Provider 抽象（复用 KXNS）
│       └── src/kosong/
│
├── tests/                      # 测试目录
│   ├── conftest.py             # 全局 fixture 与 pytest 配置
│   ├── unit/                   # 单元测试（CI 必跑）
│   │   ├── core/
│   │   ├── engine/
│   │   ├── tools/
│   │   └── skill/
│   ├── integration/            # 集成测试（CI 跑，标记 live 的跳过）
│   ├── e2e/                    # 端到端测试（CI 跑，标记 slow 的默认跳过）
│   └── local/                  # 本机手动验收（CI 不跑）
│
├── skills/                     # 预置技能包（YAML 格式）
├── sandbox/                    # 【预留】木马杀箱（M8 占位）
├── signatures/                 # 【预留】木马特征库（M8 占位）
│
├── tools/                      # 外部工具箱
│   ├── manifest.yaml           # 工具清单
│   ├── updater.py              # 工具更新器
│   ├── version_checker.py      # 版本校验器
│   ├── tshark/                 # tshark.exe（gitignore）
│   ├── yara/                   # yara64.exe（gitignore）
│   ├── die/                    # diec.exe（gitignore）
│   ├── radare2/                # r2.exe（gitignore）
│   └── ghidra/                 # ghidra（gitignore，~546MB）
│
├── vendor/                     # 第三方依赖
│   ├── wheels/                 # Python wheel 包（gitignore）
│   └── wheels_manifest.yaml    # Python 依赖清单
│
├── output/                     # 输出结果
│   ├── scans/                  # 扫描结果
│   ├── malware_reports/        # 木马分析报告（M8 预留）
│   └── coverage/               # 测试覆盖率报告（gitignore）
│
├── scripts/                    # 脚本
│   ├── test_ci.ps1             # CI 一致单元测试
│   ├── test_local.ps1          # 本机完整验收
│   └── lint.ps1                # 全量质量门禁
│
└── .github/workflows/ci.yml    # GitHub Actions CI
```

### 2.2 模块依赖方向（单向，禁止循环）

```
入口层（main/doctor/cli/settings_ui）
        ↓
业务编排层（soul/skill）
        ↓
工具调度层（engine: bus/context/mcp_adapter）
        ↓
能力封装层（core/sandbox/tools/llm）
        ↓
基础设施层（utils/config/session/wire/background）
```

**强制约束**（ruff TID252 规则检测）：
- 上层可依赖下层，下层不可反向依赖上层
- 同层之间尽量无依赖；必要时通过 `engine/bus.py` 解耦
- 禁止相对导入，强制绝对导入（ruff `ban-relative-imports = "all"`）

---

## 三、测试代码编写规范

### 3.1 测试分层

| 层级 | 目录 | 用途 | CI 策略 | 覆盖率要求 |
|---|---|---|---|---|
| **单元测试** | `tests/unit/` | 针对单个函数/类的隔离测试 | 必跑 | ≥ 85% |
| **集成测试** | `tests/integration/` | 跨模块协作测试 | 跑，`live` 标记跳过 | 关键路径覆盖 |
| **端到端测试** | `tests/e2e/` | 完整 Skill 流程 | 跑，`slow` 标记默认跳过 | 4 个示例 Skill 全覆盖 |
| **本机验收** | `tests/local/` | 依赖真实环境的服务 | CI 不跑，本机手动 | — |

### 3.2 测试标记（markers）

在 `pyproject.toml` 中已注册以下标记：

| 标记 | 含义 | 默认行为 |
|---|---|---|
| `live` | 依赖本机服务/网络/真实工具 | CI 跳过（`-m "not live"`） |
| `slow` | 重负载测试（真实工具/网络/子进程） | 本地默认跳过，需 `--run-slow` 或 `-m slow` |
| `windows_only` | 仅 Windows 平台 | 非 Windows 自动跳过 |
| `requires_admin` | 需要管理员权限 | 非管理员自动跳过 |

使用示例：

```python
import pytest

@pytest.mark.live
def test_real_tshark_capture():
    """真实抓包测试，CI 跳过"""
    ...

@pytest.mark.slow
def test_large_pe_analysis():
    """大文件分析，本地默认跳过"""
    ...

@pytest.mark.windows_only
@pytest.mark.requires_admin
def test_memory_attach():
    """仅 Windows + 管理员权限"""
    ...
```

### 3.3 命名规范

| 对象 | 规范 | 示例 |
|---|---|---|
| 测试文件 | `test_<被测模块名>.py` | `test_memory_api.py` |
| 测试类 | `Test<被测类名>` | `TestToolInterface` |
| 测试函数 | `test_<被测方法名>_<场景>` | `test_attach_process_not_found` |
| fixture | `<场景>_<类型>` | `temp_dir`、`sample_config`、`mock_pymem` |
| 测试数据 | `<场景>_<类型>.<ext>` | `sample_pe32.bin`、`eicar_test.txt` |

### 3.4 测试代码风格

```python
"""测试模块：core.memory_api

测试 pymem 薄包装层的附加/读写/扫描能力。
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from winreverse.core.memory_api import attach, read_int, ProcessAttachError


class TestAttach:
    """附加进程相关测试"""

    def test_attach_success(self, mock_pymem: MagicMock) -> None:
        """附加存在的进程应返回 Pymem 实例"""
        # Arrange（准备）
        mock_pymem.return_value.process_id = 1234
        # Act（执行）
        result = attach("game.exe")
        # Assert（断言）
        assert result.process_id == 1234

    def test_attach_process_not_found(self, mock_pymem_not_found: MagicMock) -> None:
        """附加不存在的进程应抛 ProcessAttachError"""
        with pytest.raises(ProcessAttachError, match="进程未找到"):
            attach("nonexistent.exe")


class TestReadInt:
    """读取整数相关测试"""

    def test_read_int_normal(self) -> None:
        """正常读取应返回预期值"""
        pm = MagicMock()
        pm.read_int.return_value = 100
        assert read_int(pm, 0x400000) == 100
```

### 3.5 AAA 模式（Arrange-Act-Assert）

所有测试函数必须遵循 AAA 模式：

1. **Arrange**：准备测试数据与 mock
2. **Act**：调用被测函数
3. **Assert**：断言结果

### 3.6 fixture 使用规范

- 全局共享 fixture 放 `tests/conftest.py`
- 模块专属 fixture 放 `tests/unit/<module>/conftest.py`
- 工厂函数 fixture 用 `factory` 后缀：`make_sample_pe`、`make_temp_config`
- 资源清理用 `yield` 模式：

```python
@pytest.fixture
def temp_config_file(tmp_path: Path) -> Iterator[Path]:
    """临时配置文件，测试后自动清理"""
    config = tmp_path / "config.toml"
    config.write_text("[main]\nmodel = 'test'\n", encoding="utf-8")
    yield config
    # 清理（tmp_path 自动清理，这里仅示意）
```

### 3.7 mock 规范

- 优先使用 `pytest-mock` 的 `mocker` fixture
- mock 外部依赖（HTTP/子进程/文件系统），不 mock 被测代码本身
- HTTP mock 用 `responses` 库
- 子进程 mock 用 `subprocess.run` 的 patch

```python
def test_check_updates_online(mocker, responses):
    """测试在线版本检查"""
    responses.add(
        responses.GET,
        "https://api.github.com/repos/wireshark/wireshark/releases/latest",
        json={"tag_name": "v4.6.7"},
        status=200,
    )
    updater = ToolUpdater(Path("tools/manifest.yaml"))
    latest = updater.fetch_latest_versions(strategy=["online"])
    assert latest["tshark"] == "4.6.7"
```

---

## 四、测试框架搭建步骤

### 4.1 已完成的框架搭建（本次交付）

1. **pyproject.toml 配置完整**：
   - `[project]` 依赖列表
   - `[dependency-groups] dev` 测试依赖
   - `[tool.pytest.ini_options]` pytest 配置（含 markers、覆盖率、严格模式）
   - `[tool.coverage.run]` / `[tool.coverage.report]` 覆盖率配置
   - `[tool.black]` / `[tool.ruff]` / `[tool.mypy]` 工具链配置（import 排序由 ruff 内置 I 规则处理）

2. **目录结构创建**：
   - `tests/unit/{core,engine,tools,skill}/`
   - `tests/integration/`
   - `tests/e2e/`
   - `tests/local/`
   - 各目录含 `.gitkeep` 占位

3. **kosong workspace 包占位**：
   - `packages/kosong/pyproject.toml`
   - `packages/kosong/src/kosong/__init__.py`

### 4.2 待搭建项（M1 阶段实施）

| # | 任务 | 验收标准 |
|---|---|---|
| 1 | `tests/conftest.py` 全局 fixture | 包含 `temp_dir`、`sample_config`、`mock_messages` 等 |
| 2 | `scripts/test_ci.ps1` | 与 GitHub Actions 一致的单元测试脚本 |
| 3 | `scripts/test_local.ps1` | 本机完整验收脚本（含 live） |
| 4 | `scripts/lint.ps1` | 全量质量门禁脚本 |
| 5 | `.github/workflows/ci.yml` | GitHub Actions CI 配置 |
| 6 | 核心接口契约测试 | `tests/unit/engine/test_bus.py` 验证 `ToolInterface` Protocol |
| 7 | 4 个示例 Skill 端到端测试 | `tests/e2e/test_skill_flows.py` |

### 4.3 测试框架验证流程

```
1. 编写接口契约（Protocol 定义）
        ↓
2. 编写针对接口的测试用例（TDD：先写测试）
        ↓
3. 运行测试 → 期望全部失败（接口未实现）
        ↓
4. 实现最小骨架代码使测试通过
        ↓
5. 重构与完善
        ↓
6. 验证覆盖率 ≥ 85%
```

---

## 五、项目本体构建流程

### 5.1 里程碑与优先级（P0/P1/P2）

#### P0（MVP 必须，最小可用闭环）

| 里程碑 | 任务 | 验收标准 |
|---|---|---|
| **M1** 骨架 | 创建目录结构、配置工具链、修复 KXNS Windows 兼容性、最小可启动版本 | `uv run winreverse --help` 可用；`uv run winreverse-doctor` 通过 |
| **M2** Python 依赖 | wheel 打包、core/*.py 薄包装、doctor 校验 | `import pymem/pefile/capstone/yara` 成功；core API 单测通过 |
| **M4** Skill 引擎 + 静态工具 | 扩展 loader 支持 YAML、注册 4 个静态工具、4 个示例 Skill | 端到端跑通 1 个 Skill |
| **M5** 上下文对接 | Soul 引擎接入、端到端集成测试 | 端到端跑通 2 个 Skill |
| **M7** 最小打包 | PyInstaller 目录分发 | 干净 Windows 环境解压即用 |

#### P1（体验完善，重要）

| 里程碑 | 任务 | 验收标准 |
|---|---|---|
| **M3** 外部工具 + 更新器 | manifest.yaml、updater.py、version_checker.py、5 个外部工具下载 | `--update-tools` 可用；SHA256 校验通过 |
| **M6** 可视化设置页 | Textual TUI、工具管理中心 | `--settings` 打开设置页面 |
| **M10** 质量回归 | 每 milestone 结束时执行质量门禁 | CI 全绿；覆盖率 ≥ 85% |

#### P2（未来预留，暂不实现）

| 里程碑 | 任务 | 状态 |
|---|---|---|
| **M8** 木马动态分析 | 杀箱后端、监控代理、LLM 行为分析器 | 仅预留 Protocol 与目录占位 |
| **M9** MCP 标准化接口 | transport/auth/adapter 实现 | 仅预留 Protocol 契约 |

### 5.2 各阶段验收标准

#### M1 验收标准

- [ ] `uv sync --group dev` 成功
- [ ] `uv run pytest tests/unit -q` 通过（含接口契约测试）
- [ ] `uv run ruff check .` 零警告
- [ ] `uv run black --check .` 零差异
- [ ] `uv run mypy src/winreverse` 零错误
- [ ] `uv run winreverse --help` 显示帮助
- [ ] `uv run winreverse-doctor` 完成自检
- [ ] 覆盖率 ≥ 85%

#### M2 验收标准

- [ ] `vendor/wheels/` 含 5 个 wheel 包
- [ ] `vendor/wheels_manifest.yaml` 完整
- [ ] `core/memory_api.py` / `pe_api.py` / `disasm_api.py` 实现完整
- [ ] `tests/unit/core/` 单测覆盖率 ≥ 90%
- [ ] doctor 检查 wheel 完整性通过

#### M4 验收标准

- [ ] `skill/loader.py` 支持 YAML + SKILL.md 双格式
- [ ] `engine/bus.py` 注册 4 个静态工具（pe.parse / string.extract / yara.scan / ioc.lookup）
- [ ] `skills/` 含 4 个示例 YAML
- [ ] `tests/unit/skill/test_loader.py` 通过
- [ ] `tests/unit/engine/test_bus.py` 通过

#### M5 验收标准

- [ ] Soul 引擎接入完成
- [ ] 端到端跑通 2 个 Skill（如 `auto_lock_health` + `pe_analyzer`）
- [ ] `tests/e2e/test_skill_flows.py` 通过

#### M7 验收标准

- [ ] PyInstaller spec 配置完整
- [ ] 干净 Windows 环境解压即用
- [ ] 用户使用文档完整

### 5.3 开发工作流（TDD）

```
1. 阅读实施方案 §1.4 设计原则
        ↓
2. 定义/确认接口契约（Protocol）
        ↓
3. 编写测试用例（tests/unit/）
        ↓
4. 运行测试 → 期望失败
   uv run pytest tests/unit/<module> -q
        ↓
5. 实现代码使测试通过
        ↓
6. 运行质量门禁
   .\scripts\lint.ps1
        ↓
7. 提交（pre-commit 钩子自动检查）
        ↓
8. CI 自动运行全量测试
```

---

## 六、代码质量门禁

### 6.1 工具链配置

详见 [pyproject.toml](pyproject.toml) 的以下段：

| 工具 | 配置段 | 强制级别 |
|---|---|---|
| black | `[tool.black]` | CI 必须通过（实际由 ruff format 执行，100% 兼容） |
| ruff | `[tool.ruff]` | CI 必须通过（含 lint + format + import 排序 I 规则） |
| mypy | `[tool.mypy]` | CI 必须通过 |
| pytest | `[tool.pytest.ini_options]` | CI 必须通过 |
| coverage | `[tool.coverage.*]` | ≥ 85% |

### 6.2 CI 流水线

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: windows-latest    # Windows 项目，必须用 Windows runner
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: uv sync --group dev
      - name: Lint (ruff)
        run: uv run ruff check .
      - name: Format check (ruff format, 替代 black)
        run: uv run ruff format --check .

      - name: Type check (mypy)
        run: uv run mypy src/winreverse

      # 注：import 排序由 ruff 内置的 I 规则统一检查，不再使用独立 isort

      - name: Unit tests
        run: uv run pytest tests/unit -q --tb=short -m "not live"
        env:
          WINREVERSE_TEST_MODE: "ci"
```

### 6.3 本地质量门禁脚本

`scripts/lint.ps1`（M1 阶段交付）：

```powershell
# 全量质量门禁（CI 等价）
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> ruff check ..." -ForegroundColor Cyan
uv run ruff check .
if ($LASTEXITCODE -ne 0) { Write-Host "ruff 失败" -ForegroundColor Red; exit 1 }

Write-Host "==> ruff format --check ..." -ForegroundColor Cyan
uv run ruff format --check .
if ($LASTEXITCODE -ne 0) { Write-Host "ruff format 失败" -ForegroundColor Red; exit 1 }

Write-Host "==> mypy ..." -ForegroundColor Cyan
uv run mypy src/winreverse
if ($LASTEXITCODE -ne 0) { Write-Host "mypy 失败" -ForegroundColor Red; exit 1 }

# 注：import 排序由 ruff 内置的 I 规则统一检查，不再使用独立 isort

Write-Host "==> pytest (unit) ..." -ForegroundColor Cyan
uv run pytest tests/unit -q --tb=short -m "not live"
if ($LASTEXITCODE -ne 0) { Write-Host "pytest 失败" -ForegroundColor Red; exit 1 }

Write-Host "✓ 全部质量门禁通过" -ForegroundColor Green
```

---

## 七、变更管理

### 7.1 接口契约变更

任何对**对外契约**（`ToolInterface` / `SkillLoader` / `LLMProvider` / `SandboxRunner` / MCP Protocol 系列）的修改必须：

1. 先在文档中提出变更提案
2. 评估对调用方的影响
3. 提供迁移脚本或兼容期（至少 1 个 minor 版本）
4. 更新所有相关测试用例

### 7.2 文档同步要求

- 修改模块职责 → 同步更新 `README.md` 与本 `DEVELOPMENT.md`
- 新增工具 → 同步更新 `tools/manifest.yaml` 与 `外部工具与依赖清单对比.md`
- 新增 Skill → 同步更新 `skills/` 与实施方案 §6
- 修改依赖 → 同步更新 `pyproject.toml` 与 `vendor/wheels_manifest.yaml`

### 7.3 代码审查清单

提交前自检：

- [ ] 测试用例已编写且通过
- [ ] `ruff check .` 零警告
- [ ] `ruff format --check .` 零差异（替代 black，100% 兼容）
- [ ] `mypy src/winreverse` 零错误
- [ ] `ruff check --select I .` 零差异（import 排序由 ruff 内置 I 规则检查）
- [ ] 覆盖率不下降
- [ ] 公开 API 有完整类型注解
- [ ] 复杂逻辑有「为什么」注释
- [ ] 模块顶部有职责说明 docstring
- [ ] 无相对导入（`from . import xxx` 禁用）

---

## 八、常见问题

### Q1: 为什么不用 KXNS 的 src/kxns/ 而用 src/winreverse/？

A: 包名对齐项目名 `winreverse-agent`，便于 PyInstaller 打包与分发。内部模块裁剪自 KXNS 但包名独立。

### Q2: 为什么 KXNS 没配 black/ruff/mypy 而本项目要配？

A: 实施方案 §1.4.1 是硬约束，要求代码一致性。KXNS 是已有项目未配置，本项目从源头强制执行，避免技术债。

### Q3: 测试中如何 mock pymem 等 native 库？

A: 用 `pytest-mock` 的 `mocker.patch`。例：

```python
def test_attach(mocker):
    mock_pymem = mocker.patch("winreverse.core.memory_api.Pymem")
    mock_pymem.return_value.process_id = 1234
    result = attach("game.exe")
    assert result.process_id == 1234
```

### Q4: 为什么 tests/local/ 不进 CI？

A: `tests/local/` 依赖真实环境（真实进程、真实网络、真实工具二进制），CI 环境无法满足。本机用 `.\scripts\test_local.ps1` 跑。

### Q5: 如何新增一个外部工具？

A:
1. 在 `tools/manifest.yaml` 添加条目（name/version/url/sha256/entry）
2. 在 `tools/updater.py` 无需改动（数据驱动）
3. 在 `engine/bus.py` 注册 `ToolInterface` 实现
4. 在 `tests/unit/tools/` 添加单测
5. 运行 `uv run pytest tests/unit/tools/ -q` 验证

---

## 九、参考文档

- [Windows原生逆向Agent_实施方案.md](../Windows原生逆向Agent_实施方案.md) — 项目整体方案
- [外部工具与依赖清单对比.md](../外部工具与依赖清单对比.md) — 工具选型依据
- [KXNSv2-main README](../KXNSv2-main/README.md) — 上游项目参考
- [uv 官方文档](https://docs.astral.sh/uv/)
- [pytest 官方文档](https://docs.pytest.org/)
- [ruff 官方文档](https://docs.astral.sh/ruff/)
- [mypy 官方文档](https://mypy.readthedocs.io/)

---

**文档结束。本文件随项目演进持续更新，每次 milestone 结束时同步审查。**
