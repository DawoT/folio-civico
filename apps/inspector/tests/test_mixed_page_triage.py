"""S05-02 / R1.50: synthetic mixed text+raster pages never pass as complete."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fixtures import native_pdf, scanned_pdf, mixed_pdf
from pdfimages_fixtures import EMPTY_REPORT as HEADER, SINGLE_IMAGE_ROW as ROW
from qpdf_visual_fixtures import visual_qpdf_report

SPEC = importlib.util.spec_from_file_location("folio_inspector_mixed", ROOT / "inspector.py")
assert SPEC is not None and SPEC.loader is not None
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)

class MixedRasterTriageTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.signatures = Path(self.scratch.name)
        for name in ("daily.cld", "main.cvd", "bytecode.cvd"):
            (self.signatures / name).write_bytes(b"synthetic")

    def engine(self, args, _cwd, *, images=HEADER, text="EXPEDIENTE OBRA 2026"):
        if args[0] == "clamscan" and "--version" in args:
            return "ClamAV 1.5.5"
        if args[:2] == ["qpdf", "--is-encrypted"]:
            return inspector.QPDF_UNENCRYPTED
        if args[:2] == ["qpdf", "--json"]:
            return visual_qpdf_report(args, count=1)
        if args[0] == "pdfdetach":
            return "0 embedded files"
        if args[0] == "pdfinfo":
            return "Pages: 1\nEncrypted: no\n"
        if args[0] == "pdftotext":
            return text
        if args[0] == "pdfimages":
            return images
        return ""

    def test_real_synthetic_fixture_has_both_text_and_image_objects(self):
        sample = mixed_pdf()
        self.assertTrue(sample.startswith(b"%PDF-1.4"))
        self.assertIn(b"EXPEDIENTE OBRA 2026", sample)
        self.assertIn(b"/Subtype /Image", sample)
        self.assertIn(b"/Im0 Do", sample)
        self.assertLess(len(sample), 8192)
        self.assertNotEqual(sample, native_pdf())
        self.assertNotEqual(sample, scanned_pdf())

    def test_mixed_text_and_image_requires_review_before_clean_manifest(self):
        calls = []
        def run(args, cwd):
            calls.append(tuple(args))
            return self.engine(args, cwd, images=HEADER + ROW)
        pdf = mixed_pdf()
        with self.assertRaises(inspector.ReviewRequired):
            inspector.inspect_pdf(
                pdf, "version_mixed", hashlib.sha256(pdf).hexdigest(),
                signatures=self.signatures, run=run,
            )
        self.assertTrue(any(args[0] == "pdfimages" for args in calls))
        self.assertFalse(any(args[0] in ("pdftoppm", "tesseract") for args in calls))

    def test_text_only_page_with_no_raster_remains_clean(self):
        calls = []
        def run(args, cwd):
            calls.append(tuple(args))
            return self.engine(args, cwd)
        pdf = native_pdf()
        result = inspector.inspect_pdf(
            pdf, "version_native", hashlib.sha256(pdf).hexdigest(),
            signatures=self.signatures, run=run,
        )
        self.assertEqual(result["scanVerdict"], "clean")
        self.assertEqual(len(result["pages"]), 1)
        self.assertTrue(any(args[0] == "pdfimages" for args in calls))
        self.assertFalse(any(args[0] in ("pdftoppm", "tesseract") for args in calls))

    def test_invalid_digital_text_is_rejected_before_a_second_poppler_parser(self):
        pdf = native_pdf()
        for text in ("X" * (inspector.MAX_PAGE_TEXT + 1), "Texto" + chr(0x202e)):
            calls = []
            def run(args, cwd):
                calls.append(tuple(args))
                return self.engine(args, cwd, text=text)
            with self.subTest(length=len(text)), self.assertRaises(inspector.ReviewRequired):
                inspector.inspect_pdf(
                    pdf, "version_invalid", hashlib.sha256(pdf).hexdigest(),
                    signatures=self.signatures, run=run,
                )
            self.assertNotIn("pdfimages", [args[0] for args in calls])

    def test_pdfimages_parser_fails_closed_on_malformed_or_wrong_page_report(self):
        cases = (
            "", HEADER.splitlines()[0], "garbage\n" + HEADER,
            HEADER.replace("object ID", "object XX"),
            HEADER + ROW.replace("   1     0 image", "   2     0 image"),
            HEADER + ROW.replace("   1     0 image", "   0     0 image"),
            HEADER + ROW + "unexpected garbage\n",
            HEADER + ROW.replace("640   120", "invalid   120"),
            HEADER + ROW.replace("0.5%", "secret=token"),
            HEADER + ROW + ROW,
            HEADER + ROW + "\u202e",
            HEADER + (" " * (inspector.MAX_PDFIMAGE_LIST_BYTES + 1)),
        )
        for bad in cases:
            with self.subTest(report=bad[:65]), self.assertRaises(inspector.ReviewRequired):
                inspector.has_pdf_page_raster(bad, page=1, count=2)

    def test_pdfimages_parser_accepts_empty_and_detects_real_poppler_row(self):
        self.assertFalse(inspector.has_pdf_page_raster(HEADER, page=1, count=1))
        self.assertTrue(inspector.has_pdf_page_raster(HEADER + ROW, page=1, count=1))
        with self.assertRaises(inspector.ReviewRequired):
            inspector.has_pdf_page_raster(HEADER + ROW, page=2, count=2)

    def test_missing_pdfimages_engine_does_not_fall_back_to_clean(self):
        pdf = native_pdf()
        def run(args, cwd):
            if args[0] == "pdfimages":
                raise inspector.ScannerUnavailable("synthetic engine missing")
            return self.engine(args, cwd)
        with self.assertRaises(inspector.ScannerUnavailable):
            inspector.inspect_pdf(
                pdf, "version_native", hashlib.sha256(pdf).hexdigest(),
                signatures=self.signatures, run=run,
            )


if __name__ == "__main__":
    unittest.main()
