"""Small deterministic RGB PNG fixtures for isolated inspector tests."""
from __future__ import annotations

import struct
import zlib


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload)) + kind + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff)
    )


def rgb_png(width: int, height: int, *, sparse: bool = False) -> bytes:
    """Full PNG for bounded test images; sparse content for hostile IHDR tests."""
    header = (
        struct.pack(">II", width, height)
        + bytes((8, 2, 0, 0, 0))
    )
    if sparse:
        # Deliberately invalid pixel payload: the test only checks the
        # envelope, and the raster's declared dimensions must be rejected.
        raw = b"\x00\x00\x00\x00"
    else:
        if not 0 < width * height <= 1_000_000:
            raise ValueError("Fixture pixel budget")
        raw = (b"\x00" + b"\x00" * (3 * width)) * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(raw))
        + png_chunk(b"IEND", b"")
    )
