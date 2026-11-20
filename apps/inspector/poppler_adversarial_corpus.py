"""R1.16: deterministic, bounded synthetic Poppler differential PDF corpus.

These inputs are designed to exercise code paths and numeric boundaries, not
to certify CVE exploitability or remediations. Never use institutional PDFs.
"""
from __future__ import annotations

import hashlib
import struct

from fixtures import _pdf, _stream
from poppler_isolated_sanitizer import clipped_pdf, sampled_32bit_pdf


def _segment(number: int, segment_type: int, page: int, payload: bytes) -> bytes:
    if not (1 <= number <= 255 and 0 <= segment_type <= 63 and 0 <= page <= 255):
        raise ValueError("Out of range JBIG2 synthetic segment")
    if len(payload) > 256:
        raise ValueError("Oversized JBIG2 segment")
    return (
        struct.pack(">I", number) + bytes((segment_type, 0, page))
        + struct.pack(">I", len(payload)) + payload
    )


def _jbig2_image_pdf(segments: bytes) -> bytes:
    if len(segments) > 512:
        raise ValueError("Oversized synthetic JBIG2 stream")
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Contents 4 0 R /Resources << /XObject << /Im1 5 0 R >> >> >>"),
        _stream(b"q\n100 0 0 100 50 50 cm\n/Im1 Do\nQ\n"),
        _stream(
            segments,
            b"/Type /XObject /Subtype /Image /Width 1 /Height 1 "
            b"/ColorSpace /DeviceGray /BitsPerComponent 1 "
            b"/Filter /JBIG2Decode",
        ),
    ])


def jbig2_custom_huffman_pdf(low_value: int) -> bytes:
    """JBIG2 code-table segment 53 with a two's-complement low bound.

    INT_MIN directly reaches the subtraction that CVE-2026-93313 changes if
    the code-table segment is parsed. No large allocations or document data.
    """
    if low_value not in (-(1 << 31), 0):
        raise ValueError("Only pinned synthetic boundary values allowed")
    code_table = (
        b"\x00" + struct.pack(">ii", low_value, low_value)
        + b"\x00"  # two one-bit Huffman prefixes; deliberately bounded
    )
    page_info = struct.pack(">IIII", 1, 1, 72, 72) + b"\x00\x00\x00"
    return _jbig2_image_pdf(
        _segment(1, 53, 0, code_table)
        + _segment(2, 48, 1, page_info)
        + _segment(3, 51, 1, b"")
    )


def jbig2_oversized_page_pdf() -> bytes:
    """Exercise allocation rejection. A normal allocation must not be attempted."""
    page_info = (
        struct.pack(">IIII", 0x7FFFFFFF, 0x7FFFFFFF, 72, 72)
        + b"\x00\x00\x00"
    )
    return _jbig2_image_pdf(
        _segment(1, 48, 1, page_info)
        + _segment(2, 51, 1, b"")
    )


def splash_far_clipped_pdf() -> bytes:
    """An extreme clipped triangle. Raster viewport can avoid unsafe path."""
    content = (
        b"q\n1 0 0 1 0 600000000 cm\n"
        b"0 0 m\n100 10 l\n30 90 l\nh\nW n\n"
        b"0 0 10 10 re\nf\nQ\n"
    )
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        _stream(content),
    ])


def synthetic_differential_pdfs() -> dict[str, bytes]:
    corpus = {
        "sampled32": sampled_32bit_pdf(),
        "jbig2_intmin": jbig2_custom_huffman_pdf(-(1 << 31)),
        "jbig2_zero": jbig2_custom_huffman_pdf(0),
        "jbig2_large_page": jbig2_oversized_page_pdf(),
        "splash_triangle": clipped_pdf(),
        "splash_far": splash_far_clipped_pdf(),
    }
    if len(corpus) != 6:
        raise ValueError("Incomplete adversarial test corpus")
    for name, blob in corpus.items():
        if not name.isidentifier() or not blob.startswith(b"%PDF-") or len(blob) >= 8192:
            raise ValueError("Invalid or oversized synthetic PDF")
    return corpus


def corpus_sha256() -> dict[str, str]:
    return {
        name: hashlib.sha256(blob).hexdigest()
        for name, blob in synthetic_differential_pdfs().items()
    }
