# 全量质量门禁（CI 等价）
# 对齐 DEVELOPMENT.md §6.3
# 注：使用 ruff format 替代 black（100% 兼容，且避免 black 在大项目上的性能问题）
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "==> ruff check ..." -ForegroundColor Cyan
uv run ruff check .
if ($LASTEXITCODE -ne 0) { Write-Host "✗ ruff check 失败" -ForegroundColor Red; exit 1 }

Write-Host "==> ruff format --check ..." -ForegroundColor Cyan
uv run ruff format --check .
if ($LASTEXITCODE -ne 0) { Write-Host "✗ ruff format 失败" -ForegroundColor Red; exit 1 }

Write-Host "==> mypy ..." -ForegroundColor Cyan
uv run mypy src/winreverse
if ($LASTEXITCODE -ne 0) { Write-Host "✗ mypy 失败" -ForegroundColor Red; exit 1 }

# 注：import 排序由 ruff 内置的 I 规则统一检查，不再使用独立 isort

Write-Host "==> pytest (unit) ..." -ForegroundColor Cyan
uv run pytest tests/unit -q --tb=short -m "not live"
if ($LASTEXITCODE -ne 0) { Write-Host "✗ pytest 失败" -ForegroundColor Red; exit 1 }

Write-Host "✓ 全部质量门禁通过" -ForegroundColor Green
