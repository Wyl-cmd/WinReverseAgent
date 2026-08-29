"""PyInstaller spec for WinReverseAgent 便携版。

用法:
    pyinstaller winreverse.spec --clean --noconfirm

构建产物: dist/WinReverseAgent/（onedir 目录模式，配合随包分发的
tools/、skills/、tools/manifest.yaml 构成完整便携包；构建脚本
scripts/build_exe.ps1 会自动拷贝这些资源）。

要点:
- kosong / winreverse 为 uv workspace editable 安装，通过 pathex 指向源码
- textual（CSS 数据）、dearpygui（内置字体/主题）需要收集数据文件
- winreg / pymem / capstone / yara / die 为二进制扩展，hiddenimports 兜底
"""

from __future__ import annotations

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve()
SRC = ROOT / "src"
KOSONG_SRC = ROOT / "packages" / "kosong" / "src"

datas = []

# textual 的 CSS / 界面数据
datas += collect_data_files("textual")
# textual 懒加载 widget（textual.widgets._tab_pane 等）必须全量收集
textual_submodules = collect_submodules("textual")
# dearpygui 的内置字体/主题数据
datas += collect_data_files("dearpygui")
# kosong 的包内数据（若有）
datas += collect_data_files("kosong")
# 应用 logo（GUI 窗口图标）
_logo = ROOT / "assets" / "logo.png"
if _logo.is_file():
    datas.append((str(_logo), "assets"))

hiddenimports = [
    # workspace editable 包
    "kosong",
    *collect_submodules("kosong"),
    # TUI：textual 懒加载 widget 全量
    *textual_submodules,
    # 平台模块
    "winreg",
    "ctypes.wintypes",
    # 第三方二进制扩展
    "pymem",
    "capstone",
    "yara",
    "die",
    # CLI / 配置链
    "typer",
    "tomlkit",
    "pydantic",
    # GUI（可选依赖，随包分发后始终可用）
    "dearpygui",
]

a = Analysis(
    [str(SRC / "winreverse" / "__main__.py")],
    pathex=[str(SRC), str(KOSONG_SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "IPython",
        "pytest",
        "playwright",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="winreverse",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    icon=str(ROOT / "assets" / "app.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="WinReverseAgent",
)
