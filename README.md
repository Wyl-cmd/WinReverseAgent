# WinReverseAgent

> Windows 原生逆向工程 AI Agent

基于 KXNS Hunter CLI v2 的通用层（Soul 引擎、LLM 编排、Skill 机制、会话管理、Rich UI）改造而成的 Windows 原生逆向辅助工具，面向游戏逆向、协议分析、PE 文件分析、内存扫描、内存取证、木马行为分析等场景。

## 核心特性

- **纯 Windows 原生**：无 WSL / 虚拟化软件依赖
- **二进制打包 + 自动更新**：Python 库 wheel 打包；外部工具便携版 exe + DLL
- **绿色便携**：解压即用，不污染系统环境
- **内存取证**（进程级）：内存区域枚举与可疑注入检测、全进程转储、minidump、字符串/IOC 提取、PE 雕刻、YARA 扫描
- **取证案件模式**：案件/证据链管理（SHA256 完整性基线、篡改检测、JSON 报告导出）
- **Android 取证**：adb 只读采集（设备信息/应用清单/进程/文件提取）、LiME 采集引导、Volatility 3 / ALEAPP 运行时桥接
- **上下文压缩引擎**：token 阈值自动压缩（Micro/Snip/LLM 总结三层，工具调用配对保护，CJK 感知估算，源自 kimi-cli 架构）
- **GUI + TUI**：DearPyGui 图形配置界面（主推）+ Textual TUI（备用）
- **Agent 基础设施**：文件读写/编辑/搜索 + shell 调用（危险命令守卫），LLM 具备完整工作能力
- **Skill 机制**：YAML 格式封装复杂逆向流程
- **MCP 标准化接口预留**：架构层预留，未来可平滑启用
- **代码一致性**：black + ruff + mypy + isort 强制检查

## 环境要求

- Windows 10/11（64 位）
- Python 3.12+
- [uv](https://docs.astral.sh/uv/) 包管理器
- 管理员权限（内存读写需要）

## LLM 配置（OpenAI 协议统一）

本项目 LLM 层**仅支持 OpenAI 协议**（`/v1/chat/completions`）。国内模型
（Kimi / DeepSeek / 通义 Qwen / 智谱 GLM / 豆包 等）与各类网关、本地推理
（vLLM / Ollama openai 模式）均兼容该协议，由 OpenAI 官方 Python SDK 驱动。

```powershell
# 方式一：图形界面（主推）
winreverse gui
#   Base URL:  OpenAI 协议兼容端点，如 https://api.moonshot.cn/v1
#              留空则用 OpenAI 官方端点（国内直连通常不可达）
#   Model:     模型 ID，如 kimi-k2 / deepseek-chat / qwen-plus / glm-4
#   API Key:   对应平台的 key（可留空走环境变量 OPENAI_API_KEY）

# 方式二：配置文件（便携包 = exe 旁 config.toml；源码 = cwd 或 ~/.winreverse/config.toml）
# [llm]
# provider = "openai"
# model = "kimi-k2"
# base_url = "https://api.moonshot.cn/v1"
# api_key = "..."

# 方式三：环境变量
set OPENAI_API_KEY=sk-xxx
```

常见兼容端点示例：

| 平台 | Base URL | 示例模型 |
|------|----------|---------|
| Kimi（月之暗面） | `https://api.moonshot.cn/v1` | kimi-k2 |
| DeepSeek | `https://api.deepseek.com/v1` | deepseek-chat |
| 通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | qwen-plus |
| 智谱 GLM | `https://open.bigmodel.cn/api/paas/v4` | glm-4 |
| Ollama（本地） | `http://127.0.0.1:11434/v1` | 任意本地模型 |

故障排查：事件日志/终端若报「无法连接 LLM 端点」，优先核对 Base URL
（国内直连 api.openai.com 通常不可达）与网络/代理；`winreverse doctor`
可自检环境，`winreverse gui` 可重配。

## 快速开始

### 开发环境配置

```powershell
# 安装 uv（如未安装）
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# 进入项目目录
cd WinReverseAgent

# 同步依赖（含开发依赖）
uv sync --group dev

# 验证环境
uv run winreverse-doctor
```

### 运行测试

```powershell
# CI 一致的单元测试（不含 live 集成）
.\scripts\test_ci.ps1

# 本机完整验收（含 live 集成）
.\scripts\test_local.ps1

# 仅运行单元测试
uv run pytest tests\unit -q

# 生成覆盖率报告
uv run pytest --cov-report=html:output\coverage\html
```

### 代码质量检查

```powershell
# Lint 检查
uv run ruff check .

# 格式化检查
uv run black --check .

# 类型检查
uv run mypy src\winreverse

# import 排序检查
uv run isort --check-only .

# 全量质量门禁（CI 等价）
.\scripts\lint.ps1
```

### 内存取证速查（木马行为分析）

```powershell
# 1. 枚举可疑进程的内存区域（可执行私有内存 / RWX = 注入候选）
winreverse mem regions svchost.exe

# 2. 全进程内存转储（raw bin + manifest.json 清单）
winreverse mem dump <pid> --out output\mydump

# 3. 一键取证分析（IOC / 熵 / PE 雕刻 / YARA）
winreverse mem analyze output\mydump --rules rules.yar --json report.json

# 或走 LLM 编排的完整流程
winreverse skill trojan_memory_triage -p svchost.exe
```

内存取证工具链（`memory.regions` / `memory.dump` / `memory.dump_minidump` /
`memory.strings` / `memory.iocs` / `memory.carve_pe` / `memory.analyze`）
仅依赖 ctypes + Windows API + 已 vendor 的 pefile / yara-python，
无新增第三方依赖，随主包内置分发；也可被 WinDbg / Volatility 消费
（`memory.dump_minidump` 产物为标准 .dmp）。

### 取证案件模式

```powershell
winreverse case create "木马应急响应" --desc "疑似远控"
winreverse case collect <案件ID> <pid>          # 内存转储 + 自动入证（SHA256 基线）
winreverse case add <案件ID> <文件路径>          # 登记任意文件/目录证据
winreverse case verify <案件ID>                 # 证据链完整性验证（篡改检测）
winreverse case report <案件ID>                 # 导出 JSON 报告
```

### Android 取证

```powershell
winreverse android devices                       # 列出设备（需 adb）
winreverse android info <serial>                 # 设备属性快照
winreverse android packages <serial>             # 第三方应用清单
winreverse android pull <serial> <远端> <本地>    # 只读文件提取
winreverse android lime <serial>                 # LiME 内存采集引导（GPL 隔离）
winreverse android analyze-image ram.lime linux.pslist   # Volatility 3 分析
```

许可证边界：adb（Google platform-tools）经 `tools/manifest.yaml` 下载；
LiME（GPL-2.0）只出引导命令不分发；Volatility 3（VSL）与 ALEAPP（MIT）
为运行时安装/下载通道，`winreverse android analyze-image` 失败时会给出指引。

### 图形配置界面（GUI 主推，TUI 备用）

```powershell
winreverse gui        # DearPyGui 图形配置（LLM / Agent / 上下文压缩 / 工具状态）
winreverse settings   # Textual TUI 设置页（备用）
```

DearPyGui（MIT）wheel 已 vendor 离线打包；上下文压缩策略
（simple / selective / layered）、窗口大小、触发比例均可在 GUI 修改。

## 项目结构

```
WinReverseAgent/
├── src/winreverse/        # 主源码包（src layout，对齐 KXNS）
│   ├── core/              # 单点能力 API（pe/disasm/yara/die/memory/memdump/memanalysis）
│   ├── engine/tools/      # LLM 工具封装（47 个：领域 41 + 文件/shell 基础 6）
│   ├── forensics/         # 取证工作流（case 证据链 + android 采集编排）
│   ├── soul/              # agent loop + 上下文压缩引擎（compaction）
│   ├── gui/               # DearPyGui 配置界面（presenter 可单测）
│   ├── cli/               # Typer CLI（mem / case / android / tools / gui）
│   └── tui/               # Textual TUI（备用）
├── packages/kosong/       # workspace 成员：LLM Provider 抽象
├── tests/                 # 测试目录（unit/integration/e2e/local）
├── skills/                # 预置技能包（YAML）
├── tools/                 # 外部工具箱（tshark/yara/die/adb/radare2/ghidra）
├── vendor/wheels/         # Python 依赖 wheel 包（含 dearpygui）
├── scripts/               # 测试与构建脚本
└── output/                # 运行产物（cases / memory_dumps / coverage）
```

## 路线图

- [x] P1 上下文压缩引擎（compaction 移植自 kimi-cli 架构，挂载 agent loop）
- [x] P2 取证案件模式（证据链 / SHA256 基线 / 篡改检测 / 报告）
- [x] P3 Android 取证全量集成（adb 采集 + LiME 引导 + vol3/aleapp 桥接）
- [x] P4 DearPyGui GUI 配置界面（TUI 保留备用）
- [ ] P5 会话持久化与恢复（~/.winreverse/sessions，对齐 kimi-cli sessions）
- [ ] P6 ALEAPP 制品解析深入集成（提取目录自动归档入案）
- [ ] P7 木马动态杀箱（Windows Sandbox，原 M8 规划）

## 文档

- [开发流程与规范](DEVELOPMENT.md)
- [项目实施方案](../Windows原生逆向Agent_实施方案.md)
- [外部工具与依赖清单对比](../外部工具与依赖清单对比.md)

## 许可证

MIT
