# 本机完整验收：单元测试 + live 集成（CI 不跑 tests/local）
# 对齐 KXNS scripts/test_local.sh，改为 PowerShell 实现
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 切换到项目根目录
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "==> 运行本机完整验收（含 live 集成）..." -ForegroundColor Cyan
uv run pytest tests/unit tests/local -q --tb=short $args
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "✓ 完整验收通过" -ForegroundColor Green
} else {
    Write-Host "✗ 完整验收失败" -ForegroundColor Red
}
exit $exitCode
