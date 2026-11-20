"""R1.38: PNG IHDR/CRC/budget must be checked before OCR's Tesseract."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from png_fixtures import png_chunk, rgb_png

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("folio_png_guard", ROOT / "inspector.py")
assert SPEC and SPEC.loader
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)

PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF"
SHA = hashlib.sha256(PDF).hexdigest()
BOUND = (501, 501)


class RasterEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / "ocr-page.png"

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_rgb_png_is_admitted_with_independent_pixel_bounds(self):
        for dimensions, budget in (
            ((500, 500), BOUND),
            ((1, 1), (1, 1)),
            ((1488, 2105), (1488, 2106)),
        ):
            with self.subTest(dimensions=dimensions):
                if dimensions[0] * dimensions[1] > 1_000_000:
                    # A real, minimal-image header is sufficient for envelope
                    # verification; this does NOT certify IDAT validity.
                    self.image.write_bytes(rgb_png(*dimensions, sparse=True))
                else:
                    self.image.write_bytes(rgb_png(*dimensions))
                self.assertEqual(
                    inspector.require_ocr_png_envelope(self.image, budget),
                    dimensions,
                )

    def test_declared_huge_png_with_tiny_bytes_is_rejected(self):
        for dimensions in ((8193, 1), (100_000, 1), (1, 100_000),
                           (501, 502), (502, 501), (0, 500)):
            with self.subTest(dimensions=dimensions), self.assertRaises(
                inspector.ReviewRequired
            ):
                self.image.write_bytes(rgb_png(*dimensions, sparse=True))
                inspector.require_ocr_png_envelope(self.image, BOUND)

    def test_png_corruption_signature_ihdr_crc_iend_and_chunk_type_fail_closed(self):
        valid = rgb_png(2, 2)
        corruptions = [
            b"not PNG",
            valid[:20],
            b"X" + valid[1:],
            valid[:8] + b"\x00\x00\x00\x00" + valid[12:],
            valid[:12] + b"JHDR" + valid[16:],
            valid[:16] + b"\x00" * 8 + valid[24:],
            valid[:29] + b"\x00\x00\x00\x00" + valid[33:],
            valid[:24] + b"\x10" + valid[25:],  # 16 bits/sample
            valid[:25] + b"\x03" + valid[26:],  # indexed palette
            valid[:-12],
            valid[:-1] + b"x",
            valid + b"after-IEND",
        ]
        for candidate in corruptions:
            with self.subTest(hash=hashlib.sha256(candidate).hexdigest()[:8]):
                self.image.write_bytes(candidate)
                with self.assertRaises(inspector.ReviewRequired):
                    inspector.require_ocr_png_envelope(self.image, BOUND)

    def test_zero_invalid_and_oversized_budget_fail_closed(self):
        self.image.write_bytes(rgb_png(2, 2))
        for budget in ((0, 100), (-1, 100), (True, 100), (1.5, 2),
                       ("500", "500"), (10_000, 10_000), (1,), (), None):
            with self.subTest(budget=budget), self.assertRaises(
                inspector.ReviewRequired
            ):
                inspector.require_ocr_png_envelope(self.image, budget)

    def test_missing_symlink_hardlink_directory_and_oversized_file_are_rejected(self):
        with self.assertRaises(inspector.ReviewRequired):
            inspector.require_ocr_png_envelope(self.image, BOUND)
        self.image.symlink_to(self.root / "untrusted")
        with self.assertRaises(inspector.ReviewRequired):
            inspector.require_ocr_png_envelope(self.image, BOUND)
        self.image.unlink()
        self.image.mkdir()
        with self.assertRaises(inspector.ReviewRequired):
            inspector.require_ocr_png_envelope(self.image, BOUND)
        self.image.rmdir()
        self.image.write_bytes(rgb_png(2, 2))
        other = self.root / "other-link.png"
        os.link(self.image, other)
        with self.assertRaises(inspector.ReviewRequired):
            inspector.require_ocr_png_envelope(self.image, BOUND)
        other.unlink()
        self.image.write_bytes(rgb_png(2, 2))
        with self.image.open("r+b") as stream:
            stream.truncate(32 * 1024 * 1024 + 1)
        with self.assertRaises(inspector.ReviewRequired):
            inspector.require_ocr_png_envelope(self.image, BOUND)


class InspectorRasterPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.signatures = Path(self.temp.name)
        for name in ("daily.cld", "main.cvd", "bytecode.cvd"):
            (self.signatures / name).write_bytes(b"synthetic")
        self.called = []

    def tearDown(self):
        self.temp.cleanup()

    def engine(self, argv, cwd, png: bytes | None):
        self.called.append(tuple(argv))
        exe = argv[0]
        if exe == "clamscan":
            return "ClamAV 1.5.5" if "--version" in argv else ""
        if argv[:2] == ["qpdf", "--is-encrypted"]:
            return inspector.QPDF_UNENCRYPTED
        if argv[:2] == ["qpdf", "--json"]:
            if "--json-key=pages" in argv:
                return json.dumps({
                    "version": 2,
                    "pages": [{"object": "3 0 R", "pageposfrom1": 1}],
                })
            return json.dumps({
                "version": 2,
                "qpdf": [
                    {"jsonversion": 2},
                    {"obj:3 0 R": {"value": {"/Type": "/Page"}}},
                ],
            })
        if exe == "pdfdetach":
            return "0 embedded files"
        if exe == "pdfinfo":
            if "-box" in argv:
                return ("Pages: 1\nEncrypted: no\n"
                        "Page 1 size: 200 x 200 pts\n"
                        "Page 1 rot: 0\n"
                        "Page 1 MediaBox: 0 0 200 200\n"
                        "Page 1 CropBox: 0 0 200 200\n")
            return "Pages: 1\nEncrypted: no\n"
        if exe == "pdftotext":
            return ""
        if exe == "pdftoppm":
            if png is not None:
                (cwd / "ocr-page.png").write_bytes(png)
            return ""
        if exe == "tesseract":
            return "Texto reconstruido"
        return ""

    def test_pipeline_refuses_huge_png_before_tesseract_even_if_file_is_small(self):
        forged = rgb_png(100_000, 100_000, sparse=True)
        with self.assertRaises(inspector.ReviewRequired):
            inspector.inspect_pdf(
                PDF, "ver_png", SHA, signatures=self.signatures,
                run=lambda args, cwd: self.engine(args, cwd, forged),
            )
        self.assertIn("pdftoppm", [c[0] for c in self.called])
        self.assertNotIn("tesseract", [c[0] for c in self.called])

    def test_pipeline_rejects_missing_and_corrupt_rasters_before_tesseract(self):
        valid = rgb_png(500, 500)
        corrupt = valid[:29] + b"\x00\x00\x00\x00" + valid[33:]
        for png in (None, b"not PNG", corrupt,
                    rgb_png(501, 502, sparse=True)):
            with self.subTest(length=None if png is None else len(png)):
                self.called.clear()
                with self.assertRaises(inspector.ReviewRequired):
                    inspector.inspect_pdf(
                        PDF, "ver_png", SHA, signatures=self.signatures,
                        run=lambda args, cwd: self.engine(args, cwd, png),
                    )
                self.assertIn("pdftoppm", [c[0] for c in self.called])
                self.assertNotIn("tesseract", [c[0] for c in self.called])

    def test_valid_png_flows_to_tesseract_and_preserves_clean_manifest(self):
        result = inspector.inspect_pdf(
            PDF, "ver_png", SHA, signatures=self.signatures,
            run=lambda args, cwd: self.engine(args, cwd, rgb_png(500, 500)),
        )
        self.assertEqual(result["scanVerdict"], "clean")
        self.assertEqual(result["pages"], [{"page": 1, "text": "Texto reconstruido"}])
        self.assertLess(
            next(i for i, c in enumerate(self.called) if c[0] == "pdftoppm"),
            next(i for i, c in enumerate(self.called) if c[0] == "tesseract"),
        )


if __name__ == "__main__":
    unittest.main()
