"""Deterministic, synthetic PDF fixtures without third-party Python dependencies.

Never include institutional data or copied documents. Test pages are original
text or pixel drawings created by this module. Not an official evidence source.
"""
from __future__ import annotations

import zlib

_NATIVE_TEXT = "EXPEDIENTE OBRA 2026"
_OCR_TEXT = "OBRA 2026"

# Original 5x7 bitmap glyphs, deliberately simple so the scanned fixture
# contains image pixels (not a PDF text operator or an embedded font).
GLYPHS = {
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "6": ("00110", "01000", "10000", "11110", "10001", "10001", "01110"),
    " ": ("00000",) * 7
}


def _stream(payload: bytes, extra: bytes = b"") -> bytes:
    return (
        b"<< /Length " + str(len(payload)).encode("ascii") + b" " + extra +
        b">>\nstream\n" + payload + b"\nendstream"
    )


def _pdf(objects: list[bytes]) -> bytes:
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, data in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(data)
        output.extend(b"\nendobj\n")
    startxref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\n"
        f"startxref\n{startxref}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def native_pdf() -> bytes:
    """One page of ordinary PDF text; pdftotext must find _NATIVE_TEXT."""
    content = (
        "BT\n/F1 24 Tf\n70 720 Td\n(" + _NATIVE_TEXT + ") Tj\nET\n"
    ).encode("ascii")
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        _stream(content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    ])


def _image_bitmap(word: str, *, scale: int = 9) -> tuple[int, int, bytes]:
    """Render a synthetic greyscale scan with pixel glyphs, no font library."""
    if not word or any(letter not in GLYPHS for letter in word):
        raise ValueError("Unsupported synthetic glyph")
    width = 640
    height = 120
    cells = 6 * scale
    x0 = (width - (len(word) * cells - scale)) // 2
    y0 = (height - 7 * scale) // 2
    pixels = bytearray(b"\xff" * (width * height))
    for i, letter in enumerate(word):
        for y, row in enumerate(GLYPHS[letter]):
            for x, pixel in enumerate(row):
                if pixel == "1":
                    start_x = x0 + i * cells + x * scale
                    start_y = y0 + y * scale
                    for sy in range(start_y, start_y + scale):
                        for sx in range(start_x, start_x + scale):
                            pixels[sy * width + sx] = 0
    return width, height, bytes(pixels)


def scanned_pdf(*, raster: tuple[int, int, bytes] | None = None) -> bytes:
    """One page with only image pixels, intentionally NO PDF text layer.

    A pre-rendered grayscale image may be supplied for the real-engine smoke.
    The default original glyph bitmap keeps unit fixtures stdlib-only.
    """
    width, height, gray = raster if raster is not None else _image_bitmap(_OCR_TEXT)
    if (not isinstance(width, int) or not isinstance(height, int)
            or width < 1 or height < 1 or width > 4000 or height > 4000
            or width * height > 8 * 1024 * 1024
            or len(gray) != width * height):
        raise ValueError("Invalid grayscale raster dimensions or pixel count")
    compressed = zlib.compress(gray, level=9)
    content = (b"q\n612 0 0 792 0 0 cm\n/Im0 Do\nQ\n" if raster is not None
               else b"q\n450 0 0 120 75 600 cm\n/Im0 Do\nQ\n")
    image = _stream(
        compressed,
        (f"/Type /XObject /Subtype /Image /Width {width} /Height {height} "
         "/ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode").encode("ascii")
    )
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Contents 4 0 R /Resources << /XObject << /Im0 5 0 R >> >> >>"),
        _stream(content),
        image
    ])


def malformed_pdf() -> bytes:
    """Clearly truncated synthetic PDF: fails structural validation."""
    return native_pdf()[:90]
