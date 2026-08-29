# =============================================================================
# build_exe.ps1 — WinReverseAgent 便携版打包脚本（PyInstaller onedir）
# =============================================================================
# 用法：在项目根目录执行  .\scripts\build_exe.ps1
# 产物：dist\WinReverseAgent-Portable\  （完整便携包，拷走即用）
#   ├── winreverse.exe           # 主程序（cmd: winreverse <命令>）
#   ├── tools\                   # 外部工具（tshark/yara/die/adb/radare2/ghidra）
#   ├── skills\                  # 预置 Skill
#   ├── vendor\wheels_manifest.yaml
#   └── 使用说明.txt
# =============================================================================

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "=== WinReverseAgent 便携版打包 ===" -ForegroundColor Cyan

# [1/4] PyInstaller 就位
Write-Host "[1/4] 检查 PyInstaller..." -ForegroundColor Yellow
if (-not (& .\.venv\Scripts\python.exe -c "import PyInstaller" 2>$null)) {
    uv pip install --python .\.venv\Scripts\python.exe pyinstaller
}

# [2/4] PyInstaller 构建
Write-Host "[2/4] PyInstaller 构建（onedir，约 2-5 分钟）..." -ForegroundColor Yellow
& .\.venv\Scripts\pyinstaller.exe winreverse.spec --clean --noconfirm
if ($LASTEXITCODE -ne 0) { throw "PyInstaller 构建失败" }

# [3/4] 组装便携包：dist\WinReverseAgent + 随包资源
Write-Host "[3/4] 组装便携包..." -ForegroundColor Yellow
$dist = Join-Path $root "dist\WinReverseAgent"
$portable = Join-Path $root "dist\WinReverseAgent-Portable"
# 保留用户配置（重打包不丢失 API Key 等设置）
$userConfig = Join-Path $portable "config.toml"
if (Test-Path $userConfig) { Copy-Item $userConfig (Join-Path $root "dist\_user_config.bak") -Force }
# 清理可能运行中的旧版进程（防止占用新包文件）
Stop-Process -Name winreverse.exe -Force -ErrorAction SilentlyContinue
if (Test-Path $portable) {
    try { Remove-Item $portable -Recurse -Force -ErrorAction Stop }
    catch {
        Write-Warning "旧便携包被占用，将输出到 WinReverseAgent-Portable-new"
        $portable = Join-Path $root "dist\WinReverseAgent-Portable-new"
    }
}
Move-Item $dist $portable
if (Test-Path (Join-Path $root "dist\_user_config.bak")) {
    Copy-Item (Join-Path $root "dist\_user_config.bak") $userConfig -Force
    Remove-Item (Join-Path $root "dist\_user_config.bak") -Force
}

# 随包资源：外部工具 / skills / wheel 清单
Copy-Item (Join-Path $root "tools") (Join-Path $portable "tools") -Recurse
Copy-Item (Join-Path $root "skills") (Join-Path $portable "skills") -Recurse
Copy-Item (Join-Path $root "vendor") (Join-Path $portable "vendor") -Recurse -Force
Copy-Item (Join-Path $root "assets") (Join-Path $portable "assets") -Recurse -Force

# 启动说明
@'
WinReverseAgent 便携版使用说明
==============================
1. 所有命令在本目录打开终端执行（工具按 exe 所在目录定位资源）：
     winreverse doctor              环境自检
     winreverse mem --help          内存取证
     winreverse behavior --help     动态行为分析
     winreverse case --help         取证案件
     winreverse android --help      Android 取证
     winreverse net --help          网络分析
     winreverse gui                 图形配置界面

2. 内存读写 / 抓包 / 动态监控其他进程需要管理员权限运行终端。

3. 首次使用 LLM 编排：winreverse gui 填入 API Key（或设
   ANTHROPIC_API_KEY / OPENAI_API_KEY 环境变量）。

4. 升级外部工具：winreverse tools check / tools update <名称>。
'@ | Out-File (Join-Path $portable "使用说明.txt") -Encoding utf8

# [4/4] 冒烟验证
Write-Host "[4/4] 便携包冒烟验证..." -ForegroundColor Yellow
$exe = Join-Path $portable "winreverse.exe"
& $exe --version
& $exe doctor | Out-Null
& $exe mem --help | Out-Null
if ($LASTEXITCODE -ne 0) { throw "CLI 冒烟验证失败" }
& $exe gui --check
if ($LASTEXITCODE -ne 0) { throw "GUI 自检失败（UI 树构建）" }
& $exe settings --check
if ($LASTEXITCODE -ne 0) { throw "TUI 自检失败（textual 组件加载）" }
# 双击行为守卫：非交互环境（输出重定向）应打印 TUI 提示并正常退出
& $exe | Out-Null
if ($LASTEXITCODE -ne 0) { throw "无参数运行守卫验证失败" }
Write-Host "  无参数守卫验证通过（桌面双击将进入 TUI）" -ForegroundColor Green

$sizeGB = [math]::Round((Get-ChildItem $portable -Recurse | Measure-Object Length -Sum).Sum / 1GB, 2)
Write-Host "=== 完成: $portable（$sizeGB GB）===" -ForegroundColor Green
Write-Host "整个目录拷贝到任意 Windows 10/11 x64 机器解压即用。" -ForegroundColor Green
