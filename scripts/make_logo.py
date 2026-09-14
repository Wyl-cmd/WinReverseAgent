"""make_logo.py — 从原始 logo 生成打包资产（圆形倒角风格）。

用法（在项目根目录）：
    .venv/Scripts/python.exe scripts/make_logo.py [源图路径]

产物：
    assets/logo.png   512x512 透明大圆角 PNG（GUI 窗口图标）
    assets/app.ico    多尺寸 exe 图标（16/24/32/48/64/128/256）

风格：大圆角（半径 = 边长 22%）+ 抗锯齿（4x 超采样），不锋利。
源图默认取项目上级目录的 icon.png（实际为 JPEG 亦支持）。
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCES = [
    ROOT.parent / "icon.png",
    ROOT / "assets" / "logo_src.png",
]
ASSETS = ROOT / "assets"
# 圆角半径比例（相对边长；22% 为现代应用图标常用的柔和圆角）
_CORNER_RATIO = 0.22
# 抗锯齿超采样倍数
_SUPERSAMPLE = 4


def _rounded_mask(size: int, radius: int, scale: int) -> Image.Image:
    """生成抗锯齿圆角遮罩（L 模式，255=不透明）。"""
    big = size * scale
    mask = Image.new("L", (big, big), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle(
        (0, 0, big - 1, big - 1),
        radius=radius * scale,
        fill=255,
    )
    return mask.resize((size, size), Image.LANCZOS)


def make_logo(source: Path) -> tuple[Path, Path]:
    """从源图生成圆形倒角的 logo.png 与 app.ico。

    Args:
        source: 原始 logo 路径（PNG/JPEG 均可）

    Returns:
        (logo.png 路径, app.ico 路径)

    Raises:
        FileNotFoundError: 源图不存在
    """
    if not source.is_file():
        raise FileNotFoundError(f"源 logo 不存在: {source}")

    img = Image.open(source).convert("RGBA")

    # 居中裁剪为正方形（非方图先取最大内切方形）
    width, height = img.size
    side = min(width, height)
    left = (width - side) // 2
    top = (height - side) // 2
    img = img.crop((left, top, left + side, top + side))

    # 圆角遮罩（抗锯齿）
    size = 512
    img = img.resize((size, size), Image.LANCZOS)
    mask = _rounded_mask(size, int(size * _CORNER_RATIO), _SUPERSAMPLE)
    img.putalpha(mask)

    ASSETS.mkdir(parents=True, exist_ok=True)
    logo_path = ASSETS / "logo.png"
    img.save(logo_path, "PNG")

    # exe 图标：多尺寸 ico（圆角版缩放）
    ico_path = ASSETS / "app.ico"
    img.save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    return logo_path, ico_path


def main() -> int:
    """入口：解析源图路径（参数或默认），生成资产。"""
    source = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else next((p for p in DEFAULT_SOURCES if p.is_file()), DEFAULT_SOURCES[0])
    )
    logo_path, ico_path = make_logo(source)
    print(f"logo: {logo_path}")
    print(f"ico:  {ico_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
