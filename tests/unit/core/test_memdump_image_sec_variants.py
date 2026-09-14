"""被测模块: winreverse.core.memdump_api（MemoryRegion SEC_IMAGE 变体与可执行/可写判定）。

覆盖点: MEM_IMAGE_SEC 别名区的 is_image/type_name/is_mapped 路由；映像区 RWX
仍判 suspicious（不限于私有内存）；PAGE_EXECUTE_READ 可执行不可写；私有可执行区
suspicious；to_dict 的 protect_raw 透传与 SEC 变体 type 归一。
引用 pymem 等 Windows 运行时依赖 → Linux 下如实报 collection error（基线接受态），
待 Windows 实机（依赖就位）实跑回填。
"""

from __future__ import annotations

from winreverse.core.memdump_api import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_IMAGE_SEC,
    MEM_MAPPED,
    MEM_PRIVATE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
    MemoryRegion,
)


class TestImageSecVariant:
    """MEM_IMAGE_SEC（SEC_IMAGE 映射别名）必须与 MEM_IMAGE 同路由。"""

    def test_sec_variant_is_image_not_mapped(self) -> None:
        region = MemoryRegion(
            base_address=0x7FF0000, size=0x1000, state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READ, type=MEM_IMAGE_SEC,
        )
        assert region.is_image is True
        assert region.is_mapped is False
        assert region.is_private is False
        assert region.type_name == "image"

    def test_plain_image_type_name(self) -> None:
        region = MemoryRegion(
            base_address=0x400000, size=0x1000, state=MEM_COMMIT,
            protect=PAGE_READWRITE, type=MEM_IMAGE,
        )
        assert region.type_name == "image"


class TestSuspiciousBeyondPrivate:
    """suspicious 判定的非私有分支：映像/映射区 RWX 仍命中。"""

    def test_image_rwx_is_suspicious(self) -> None:
        region = MemoryRegion(
            base_address=0x7FF0000, size=0x2000, state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READWRITE, type=MEM_IMAGE_SEC,
        )
        assert region.is_suspicious is True

    def test_image_rx_not_suspicious(self) -> None:
        region = MemoryRegion(
            base_address=0x7FF0000, size=0x2000, state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READ, type=MEM_IMAGE,
        )
        assert region.is_suspicious is False

    def test_private_exec_read_is_suspicious(self) -> None:
        region = MemoryRegion(
            base_address=0x1000, size=0x1000, state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READ, type=MEM_PRIVATE,
        )
        assert region.is_executable is True
        assert region.is_writable is False
        assert region.is_suspicious is True


class TestWritabilityTable:
    """is_writable 只认四种可写保护，PAGE_EXECUTE_READ 不可写。"""

    def test_execute_read_not_writable(self) -> None:
        region = MemoryRegion(
            base_address=0x2000, size=0x1000, state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READ, type=MEM_MAPPED,
        )
        assert region.is_writable is False
        assert region.is_executable is True

    def test_readwrite_mapped_writable(self) -> None:
        region = MemoryRegion(
            base_address=0x3000, size=0x1000, state=MEM_COMMIT,
            protect=PAGE_READWRITE, type=MEM_MAPPED,
        )
        assert region.is_writable is True


class TestToDictRawPassthrough:
    """to_dict：protect_raw 透传原始位，SEC 变体 type 归一为 image。"""

    def test_sec_variant_to_dict(self) -> None:
        region = MemoryRegion(
            base_address=0xABC000, size=4096, state=MEM_COMMIT,
            protect=PAGE_EXECUTE_READWRITE, type=MEM_IMAGE_SEC,
        )
        d = region.to_dict()
        assert d["type"] == "image"
        assert d["protect_raw"] == PAGE_EXECUTE_READWRITE
        assert d["base_address"] == "0xABC000"
        assert d["suspicious"] is True
