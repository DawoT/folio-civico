"""R1.17 synthetic reachability inputs: source-method tests, never CVE exploits.

The TrueType font was generated offline with FontTools FontBuilder using only
two original geometric glyphs, then encoded as fixed SHA-pinned base64 to avoid
requiring third-party font-generation packages at test/runtime.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import struct

from fixtures import _pdf, _stream
from poppler_adversarial_corpus import _jbig2_image_pdf, _segment

SYNTHETIC_TTF_SHA256 = "843b720df261131b2d0ce15ea4ace1157f96527bd194fac69da5612b35773078"
SYNTHETIC_TTF_B64 = (
    Path(__file__).resolve().parent
    / "research_patches/folio_r117_synthetic_ttf.b64"
)
PAGE_DIMENSION_CASES = {
    "jbig2_zero_width": (0, 1, 0),
    "jbig2_zero_height": (1, 0, 0),
    "jbig2_zero_stripe": (1, 0xFFFFFFFF, 0),
}
FONT_CASE_NAME = "type42_synthetic"


def read_synthetic_font(path: Path = SYNTHETIC_TTF_B64) -> bytes:
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size < 4096:
        raise ValueError("Missing or untrusted synthetic font")
    try:
        payload = base64.b64decode(path.read_bytes().strip(), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Synthetic font encoding failed") from exc
    if (len(payload) != 956 or hashlib.sha256(payload).hexdigest()
            != SYNTHETIC_TTF_SHA256 or payload[:4] != b"\x00\x01\x00\x00"):
        raise ValueError("Synthetic font SHA-256 or structure mismatch")
    return payload


def minimal_type42_pdf(font: bytes | None = None) -> bytes:
    """A synthetic one-page PDF embedding a two-glyph TrueType font."""
    ttf = read_synthetic_font() if font is None else font
    if (len(ttf) != 956 or hashlib.sha256(ttf).hexdigest()
            != SYNTHETIC_TTF_SHA256):
        raise ValueError("Unpinned synthetic TrueType font")
    descriptor = (
        b"<< /Type /FontDescriptor /FontName /FolioSynthetic-Regular "
        b"/Flags 32 /FontBBox [0 -200 600 800] /ItalicAngle 0 "
        b"/Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 "
        b"/FontFile2 7 0 R >>"
    )
    pdf = _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        _stream(b"BT /F1 24 Tf 75 400 Td (A) Tj ET\n"),
        (b"<< /Type /Font /Subtype /TrueType "
         b"/BaseFont /FolioSynthetic-Regular /FirstChar 65 /LastChar 65 "
         b"/Widths [600] /FontDescriptor 6 0 R "
         b"/Encoding /WinAnsiEncoding >>"),
        descriptor,
        _stream(ttf),
    ])
    if len(pdf) >= 4096 or b"/FontFile2 7 0 R" not in pdf:
        raise ValueError("Synthetic Type42 case malformed or too large")
    return pdf


def invalid_jbig2_page_pdfs() -> dict[str, bytes]:
    """Small page-info segments whose bitmap ctor fails before reset()."""
    fixtures = {}
    for name, (width, height, stripe) in PAGE_DIMENSION_CASES.items():
        data = (
            struct.pack(">IIII", width, height, 72, 72)
            + b"\x00" + struct.pack(">H", stripe)
        )
        fixtures[name] = _jbig2_image_pdf(
            _segment(1, 48, 1, data) + _segment(2, 51, 1, b"")
        )
        if len(fixtures[name]) > 1024:
            raise ValueError("Oversized synthetic JBIG2 rejection")
    return fixtures


def additional_reachability_pdfs() -> dict[str, bytes]:
    cases = {**invalid_jbig2_page_pdfs(), FONT_CASE_NAME: minimal_type42_pdf()}
    if len(cases) != 4 or any(
        not name.isidentifier() or not data.startswith(b"%PDF-")
        or len(data) >= 4096
        for name, data in cases.items()
    ):
        raise ValueError("Incomplete bounded reachability corpus")
    return cases


def additional_corpus_sha256() -> dict[str, str]:
    return {
        name: hashlib.sha256(data).hexdigest()
        for name, data in additional_reachability_pdfs().items()
    }
