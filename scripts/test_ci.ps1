# 与 GitHub Actions 一致的 CI 单元测试（不含 live 集成）
# 对齐 KXNS scripts/test_ci.sh，改为 PowerShell 实现
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 切换到项目根目录（脚本所在目录的上一级）
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

# 设置测试环境变量（与 CI 一致）
$env:WINREVERSE_TEST_MODE = "ci"

Write-Host "==> 运行 CI 一致的单元测试 ..." -ForegroundColor Cyan
uv run pytest tests/unit -q --tb=short -m "not live" $args
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "✓ 单元测试通过" -ForegroundColor Green
} else {
    Write-Host "✗ 单元测试失败" -ForegroundColor Red
}
exit $exitCode
