"""R1.31: two bounded, synthetic one-page PDFs for source-level width research.

The wide PDF has no external references, images, fonts, annotations or scripts.
It is intentionally outside ordinary PDF page-size constraints; acceptance
and translation to a Splash bitmap MUST be measured, never presumed.
"""
from __future__ import annotations

import hashlib

from fixtures import _pdf, _stream

EXTREME_WIDTH = 536870919
EXPECTED_PDF_SHA256 = {
    "normal": "22382dd323479ea0ce553d09cda1109b80cc71f8ba8aff62f259994c9b61b1da",
    "wide": "e05b6b6a907a0742006dc6a2e8e5d67ed01c6ff0fd65f0fa3f3389841ef41345",
}


def make_pdf(width: int) -> bytes:
    if type(width) is not int or width not in (8, EXTREME_WIDTH):
        raise ValueError("Unapproved synthetic page width")
    media_box = f"[0 0 {width} 1]".encode("ascii")
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox " + media_box
         + b" /Contents 4 0 R >>"),
        _stream(b"q\nQ\n"),
    ])


def pdf_corpus() -> dict[str, bytes]:
    corpus = {"normal": make_pdf(8), "wide": make_pdf(EXTREME_WIDTH)}
    for name, content in corpus.items():
        if len(content) >= 2048 or not content.startswith(b"%PDF-1.4"):
            raise ValueError("Invalid bounded synthetic PDF")
        if hashlib.sha256(content).hexdigest() != EXPECTED_PDF_SHA256[name]:
            raise ValueError("Synthetic PDF integrity mismatch")
    return corpus
