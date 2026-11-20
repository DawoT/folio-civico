"""R1.35: pre-raster MediaBox admission, never Page size/CropBox as cost bound."""
from __future__ import annotations

import hashlib
import json
from decimal import Decimal
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("folio_inspector_ocr_geometry", ROOT / "inspector.py")
assert SPEC and SPEC.loader
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)

PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF"
SHA = hashlib.sha256(PDF).hexdigest()


def bounded_geometry(raw: str, *, page: int, count: int) -> tuple[int, int]:
    """Security contract: a caller MUST supply a resolved UserUnit."""
    return inspector.require_ocr_raster_geometry(
        raw, page=page, count=count, user_unit=Decimal(1),
    )


def box_report(
    page: int, *, pages: int = 2, media: str = "0 0 595 842",
    crop: str | None = None, size: str = "595 x 842", rot: str = "0",
) -> str:
    crop = media if crop is None else crop
    return (
        f"Pages:           {pages}\nEncrypted:       no\n"
        f"Page {page} size: {size} pts (A4)\n"
        f"Page {page} rot:   {rot}\n"
        f"Page {page} MediaBox: {media}\n"
        f"Page {page} CropBox: {crop}\n"
        f"Page {page} BleedBox: {crop}\n"
    )


class GeometryBudgetTests(unittest.TestCase):
    def test_media_box_cropped_size_does_not_understate_raster(self):
        result = bounded_geometry(
            box_report(2, media="0 0 200 200", crop="20 30 120 90",
                       size="100 x 60"),
            page=2, count=2,
        )
        self.assertEqual(result, (501, 501))

    def test_inherited_media_box_not_reduced_by_crop(self):
        result = bounded_geometry(
            box_report(2, media="0 0 500 300", crop="100 10 300 210",
                       size="200 x 200"),
            page=2, count=2,
        )
        self.assertEqual(result, (1251, 751))

    def test_cropbox_outside_media_is_clamped_by_poppler_without_underbudgeting(self):
        result = bounded_geometry(
            box_report(2, media="0 0 200 200", crop="0 0 400 400",
                       size="200 x 200"),
            page=2, count=2,
        )
        self.assertEqual(result, (501, 501))

    def test_rejects_pixel_budget_even_when_each_side_passes(self):
        with self.assertRaises(inspector.ReviewRequired):
            bounded_geometry(
                box_report(2, media="0 0 3000 3000", size="3000 x 3000"),
                page=2, count=2,
            )

    def test_legitimate_spanish_unicode_in_metadata_is_not_rejected(self):
        report = "Title: Expediente técnico de hidráulica\n" + box_report(2)
        self.assertEqual(
            bounded_geometry(report, page=2, count=2),
            (1488, 2106),
        )

    def test_negative_origin_is_allowed_only_for_bounded_extent(self):
        dims = bounded_geometry(
            box_report(2, media="-100 -100 100 100", size="200 x 200"),
            page=2, count=2,
        )
        self.assertEqual(dims, (501, 501))

    def test_asymmetric_rotation_swaps_dimensions(self):
        for rotation, expected in (
            ("0", (501, 1001)),
            ("90", (1001, 501)),
            ("180", (501, 1001)),
            ("270", (1001, 501)),
        ):
            with self.subTest(rotation=rotation):
                result = bounded_geometry(
                    box_report(2, media="0 0 200 400", rot=rotation,
                               size="200 x 400"),
                    page=2, count=2,
                )
                self.assertEqual(result, expected)

    def test_supports_valid_a1_and_a2_as_provisional_product_limit(self):
        for box in ("0 0 1684 2384", "0 0 1191 1684"):
            self.assertTrue(all(n > 0 for n in bounded_geometry(
                box_report(2, media=box, size="200 x 300"), page=2, count=2
            )))

    def test_a0_and_extreme_are_rejected_before_raster(self):
        for box, crop in (
            ("0 0 2384 3370", "0 0 200 200"),
            ("0 0 536870919 1", "0 0 100 1"),
            ("0 0 20000 1", "0 0 100 1"),
            ("0 0 10000 10000", "0 0 100 100"),
        ):
            with self.subTest(box=box), self.assertRaises(inspector.ReviewRequired):
                bounded_geometry(
                    box_report(2, media=box, crop=crop, size="100 x 1"),
                    page=2, count=2,
                )

    def test_rejects_missing_duplicate_unexpected_and_corrupt_records(self):
        report = box_report(2)
        invalid = (
            report.replace("Page 2 MediaBox: 0 0 595 842\n", ""),
            report.replace("Page 2 MediaBox: 0 0 595 842",
                           "Page 2 MediaBox: NaN 0 595 842"),
            report + "Page 2 MediaBox: 0 0 595 842\n",
            report + "Page 9 MediaBox: 0 0 10 10\n",
            report + "Page 2 rot: 0\n",
            report.replace("Page 2 rot:   0", "Page 2 rot: 45"),
            report.replace("Page 2 size: 595 x 842", "Page 2 size: arbitrary x 842"),
            report.replace("Encrypted:       no", "Encrypted:       yes"),
            report.replace("Pages:           2", "Pages:           3"),
            report.replace("Page 2 MediaBox:", "Page 1 MediaBox:"),
            report.replace("Page 2 CropBox:", "Page 1 CropBox:"),
            report.replace("Page 2 CropBox: 0 0 595 842", "Page 2 CropBox: 0 0 0 842"),
            report + "\nPage 2 MediaBox: 0 0 595 842 garbage",
            report + "\u202e",
        )
        for raw in invalid:
            with self.subTest(tail=raw[-80:]), self.assertRaises(inspector.ReviewRequired):
                bounded_geometry(raw, page=2, count=2)

    def test_rejects_invalid_rectangle_coordinate_and_scientific_overflow(self):
        for box in (
            "0 0 0 842",
            "0 0 -1 842",
            "0 0 595 -842",
            "100 0 99 842",
            "0 0 Inf 842",
            "0 0 1e+999 842",
            "0 0 1e+99 842",
            "0 0 -1e+99 842",
            "0 0 0.0000 842",
            "0 0 99999999999999999999999999 842",
        ):
            with self.subTest(box=box), self.assertRaises(inspector.ReviewRequired):
                bounded_geometry(
                    box_report(2, media=box), page=2, count=2
                )

    def test_rejects_oversized_output_and_incorrect_page_context(self):
        report = box_report(2)
        for text, page, count in (
            (report * 2000, 2, 2),
            (report, 3, 2),
            (report, 2, 1),
            (report, 1, 2),
            (report, 2, 101),
        ):
            with self.subTest(page=page, count=count), self.assertRaises(inspector.ReviewRequired):
                bounded_geometry(text, page=page, count=count)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.signatures = Path(self.temp.name)
        for name in ("daily.cld", "main.cvd", "bytecode.cvd"):
            (self.signatures / name).write_bytes(b"synthetic")
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def fake_engine(self, argv, cwd, *, no_text=True, box=None):
        self.calls.append(tuple(argv))
        op = argv[0]
        if op == "clamscan" and "--version" in argv:
            return "ClamAV 1.5.5/28187/2026-11-18"
        if op == "qpdf" and argv[1] == "--is-encrypted":
            return "not_encrypted"
        if op == "qpdf" and argv[1] == "--json":
            if "--json-key=pages" in argv:
                return json.dumps({
                    "version": 2, "pages": [
                        {"object": "3 0 R", "pageposfrom1": 1},
                        {"object": "4 0 R", "pageposfrom1": 2},
                    ],
                })
            number = int(next(
                arg.split("=", 1)[1].split(",")[0]
                for arg in argv if arg.startswith("--json-object=")
            ))
            return json.dumps({
                "version": 2,
                "qpdf": [
                    {"jsonversion": 2},
                    {f"obj:{number} 0 R": {"value": {"/Type": "/Page"}}},
                ],
            })
        if op == "pdfdetach":
            return "0 embedded files\n"
        if op == "pdfinfo":
            if "-box" in argv:
                p = int(argv[argv.index("-f") + 1])
                return box_report(p, media=box or "0 0 595 842")
            return "Pages: 2\nEncrypted: no\n"
        if op == "pdftotext":
            return "" if no_text else "Texto documental nativo"
        if op == "pdftoppm":
            (cwd / "ocr-page.png").write_bytes(b"synthetic raster")
        if op == "tesseract":
            return "OCR válido y limpio"
        return ""

    def test_extreme_media_is_rejected_after_qpdf_but_before_pdftoppm(self):
        def run(argv, cwd):
            return self.fake_engine(argv, cwd, box="0 0 536870919 1")
        with self.assertRaises(inspector.ReviewRequired):
            inspector.inspect_pdf(PDF, "ver_1", SHA,
                                  signatures=self.signatures, run=run)
        calls = self.calls
        gates = [args[:2] for args in calls]
        self.assertIn(("qpdf", "--check"), gates)
        self.assertIn(("qpdf", "--is-encrypted"), gates)
        self.assertFalse(any(a[0] in ("pdftoppm", "tesseract") for a in calls))
        self.assertTrue(any(a[0] == "pdfinfo" and "-box" in a for a in calls))
        self.assertLess(next(i for i,a in enumerate(calls) if a[0]=="pdftotext"),
                        next(i for i,a in enumerate(calls) if a[0]=="pdfinfo" and "-box" in a))

    def test_ocr_mixed_page_metadata_is_checked_per_page(self):
        def run(argv, cwd):
            if argv[0] == "pdftotext" and argv[argv.index("-f") + 1] == "1":
                self.calls.append(tuple(argv))
                return "Texto nativo"
            if argv[0] == "pdfinfo" and "-box" in argv:
                self.calls.append(tuple(argv))
                self.assertEqual(argv[argv.index("-f") + 1], "2")
                self.assertEqual(argv[argv.index("-l") + 1], "2")
                return box_report(2, media="0 0 200 200",
                                  crop="0 0 100 100", size="100 x 100")
            return self.fake_engine(argv, cwd)
        result = inspector.inspect_pdf(PDF, "ver_1", SHA,
                                       signatures=self.signatures, run=run)
        self.assertEqual(len(result["pages"]), 2)
        self.assertEqual(len([a for a in self.calls if a[0] == "pdftoppm"]), 1)
        self.assertEqual(len([a for a in self.calls if a[0] == "pdfinfo" and "-box" in a]), 1)

    def test_no_geometry_parser_cost_for_text_only_pdf(self):
        def run(argv, cwd):
            return self.fake_engine(argv, cwd, no_text=False)
        result = inspector.inspect_pdf(PDF, "ver_1", SHA,
                                       signatures=self.signatures, run=run)
        self.assertEqual(result["scanVerdict"], "clean")
        self.assertFalse(any("-box" in a for a in self.calls))

    def test_geometry_parser_failure_yields_no_clean_report(self):
        for faulty in (None, "", "Page 2 MediaBox: 0 0 595 842"):
            self.calls = []
            def run(argv, cwd):
                if argv[0] == "pdfinfo" and "-box" in argv:
                    self.calls.append(tuple(argv))
                    if faulty is None:
                        raise inspector.ScannerUnavailable("metadata unavailable")
                    return faulty
                return self.fake_engine(argv, cwd)
            with self.subTest(faulty=faulty), self.assertRaises(
                (inspector.ReviewRequired, inspector.ScannerUnavailable)
            ):
                inspector.inspect_pdf(PDF, "ver_1", SHA,
                                      signatures=self.signatures, run=run)
            self.assertFalse(any(a[0] == "pdftoppm" for a in self.calls))


if __name__ == "__main__":
    unittest.main()
