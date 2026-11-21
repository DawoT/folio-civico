"""R1.36: fail-closed QPDF page UserUnit admission before Poppler raster."""
from __future__ import annotations

from decimal import Decimal
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from png_fixtures import rgb_png
from qpdf_visual_fixtures import visual_qpdf_report

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("folio_ocr_unit", ROOT / "inspector.py")
assert SPEC and SPEC.loader
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)

PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF"
SHA = hashlib.sha256(PDF).hexdigest()


def inventory(count: int = 2) -> str:
    return json.dumps({
        "version": 2,
        "parameters": {"decodelevel": "generalized"},
        "pages": [
            {"object": f"{i + 3} 0 R", "pageposfrom1": i + 1,
             "contents": [], "images": [], "label": None, "outlines": []}
            for i in range(count)
        ],
    })


def page_json(number: int, unit: object | None = None) -> str:
    value = {
        "/Type": "/Page", "/Parent": "2 0 R",
        "/MediaBox": [0, 0, 200, 200],
    }
    if unit is not None:
        value["/UserUnit"] = unit
    return json.dumps({
        "version": 2,
        "parameters": {"decodelevel": "generalized"},
        "qpdf": [
            {"jsonversion": 2, "maxobjectid": 12, "pdfversion": "1.6"},
            {f"obj:{number} 0 R": {"value": value}},
        ],
    })


def page_info(count: int = 2, page: int = 1) -> str:
    return (
        f"Pages: {count}\nEncrypted: no\n"
        f"Page {page} size: 200 x 200 pts\n"
        f"Page {page} rot: 0\n"
        f"Page {page} MediaBox: 0 0 200 200\n"
        f"Page {page} CropBox: 0 0 200 200\n"
    )


class UserUnitEvidenceTests(unittest.TestCase):
    def test_qpdf_json_pages_must_match_original_inventory(self):
        self.assertEqual(
            inspector.parse_qpdf_page_inventory(inventory(), count=2),
            ((3, 0), (4, 0)),
        )
        bad = (
            inventory(1), inventory(3),
            inventory().replace('"version": 2', '"version": 3', 1),
            inventory().replace('"pageposfrom1": 2', '"pageposfrom1": 1', 1),
            inventory().replace('"pageposfrom1": 1', '"pageposfrom1": true', 1),
            inventory().replace('"4 0 R"', '"3 0 R"'),
            inventory().replace('"4 0 R"', '"foo"'),
            inventory().replace('"4 0 R"', '"999999999999 0 R"'),
            inventory() + "\u202e",
            inventory() * 10000,
            "",
        )
        for raw in bad:
            with self.subTest(head=raw[:90]), self.assertRaises(inspector.ReviewRequired):
                inspector.parse_qpdf_page_inventory(raw, count=2)

    def test_qpdf_pageobject_direct_numeric_userunit(self):
        self.assertEqual(
            inspector.parse_qpdf_user_unit(page_json(4), object_number=4, generation=0),
            Decimal(1),
        )
        self.assertEqual(
            inspector.parse_qpdf_user_unit(page_json(4, 5), object_number=4, generation=0),
            Decimal(5),
        )
        self.assertEqual(
            inspector.parse_qpdf_user_unit(page_json(4, 10000), object_number=4, generation=0),
            Decimal(10000),
        )

    def test_unknown_non_numeric_negative_and_indirect_unit_fail_closed(self):
        for candidate in (
            0, -1, 0.5, 75001, True, "12 0 R", "5", "NaN", [],
            {"reference": "5 0 R"},
        ):
            with self.subTest(value=candidate), self.assertRaises(inspector.ReviewRequired):
                inspector.parse_qpdf_user_unit(
                    page_json(4, candidate), object_number=4, generation=0,
                )

    def test_qpdf_pageobject_identity_and_structure_are_checked(self):
        good = page_json(4, 1)
        bad = (
            good.replace('"obj:4 0 R"', '"obj:5 0 R"'),
            good.replace('"/Type": "/Page"', '"/Type": "/Pages"'),
            good.replace('"version": 2', '"version": 3', 1),
            good.replace('"qpdf": [', '"qpdf": []'),
            good.replace('"version": 2', '"version": 2, "version": 2', 1),
            good + "\u202e",
            good * 10000,
            "",
        )
        for raw in bad:
            with self.subTest(s=raw[:100]), self.assertRaises(inspector.ReviewRequired):
                inspector.parse_qpdf_user_unit(raw, object_number=4, generation=0)

    def test_unit_scaling_is_conservative_even_if_poppler_ignores_userunit(self):
        with self.assertRaises(TypeError):
            inspector.require_ocr_raster_geometry(page_info(), page=1, count=2)
        without = inspector.require_ocr_raster_geometry(
            page_info(), page=1, count=2, user_unit=Decimal(1),
        )
        with5 = inspector.require_ocr_raster_geometry(
            page_info(), page=1, count=2, user_unit=Decimal(5),
        )
        self.assertEqual(without, (501, 501))
        self.assertEqual(with5, (2501, 2501))
        with self.assertRaises(inspector.ReviewRequired):
            inspector.require_ocr_raster_geometry(
                page_info(), page=1, count=2, user_unit=Decimal(10000),
            )


class UserUnitPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.signatures = Path(self.tmp.name)
        for name in ("daily.cld", "main.cvd", "bytecode.cvd"):
            (self.signatures / name).write_bytes(b"synthetic")
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def runner(self, args, cwd, *, unit=1, only_text=False):
        self.calls.append(tuple(args))
        if args[0] == "clamscan":
            return "ClamAV 1.5.5" if "--version" in args else ""
        if args[:2] == ["qpdf", "--is-encrypted"]:
            return inspector.QPDF_UNENCRYPTED
        if args[:2] == ["qpdf", "--json"]:
            return visual_qpdf_report(args, count=2, user_unit=unit)
        if args[0] == "pdfdetach":
            return "0 embedded files"
        if args[0] == "pdfinfo":
            if "-box" in args:
                return page_info()
            return "Pages: 2\nEncrypted: no\n"
        if args[0] == "pdfimages":
            from pdfimages_fixtures import EMPTY_REPORT
            return EMPTY_REPORT
        if args[0] == "pdftotext":
            page = int(args[args.index("-f") + 1])
            return "Native page text" if only_text or page == 2 else ""
        if args[0] == "pdftoppm":
            (cwd / "ocr-page.png").write_bytes(rgb_png(500, 500))
            return ""
        if args[0] == "tesseract":
            return "Texto recuperado en OCR"
        return ""

    def test_large_userunit_fails_before_pdftoppm(self):
        with self.assertRaises(inspector.ReviewRequired):
            inspector.inspect_pdf(
                PDF, "ver_1", SHA, signatures=self.signatures,
                run=lambda args, cwd: self.runner(args, cwd, unit=10000),
            )
        self.assertFalse(any(a[0] == "pdftoppm" for a in self.calls))
        order = [a[0] for a in self.calls]
        self.assertLess(order.index("qpdf"), order.index("pdfdetach"))
        self.assertIn(("qpdf", "--check"), [a[:2] for a in self.calls])
        self.assertTrue(any("--json-object=3,0" in a for a in self.calls))

    def test_userunit_five_allows_bounded_ocr(self):
        result = inspector.inspect_pdf(
            PDF, "ver_1", SHA, signatures=self.signatures,
            run=lambda args, cwd: self.runner(args, cwd, unit=5),
        )
        self.assertEqual(result["scanVerdict"], "clean")
        self.assertEqual(sum(a[0] == "pdftoppm" for a in self.calls), 1)
        self.assertEqual(sum("--json-key=pages" in a for a in self.calls), 1)

    def test_text_only_document_checks_scoped_visual_objects_without_ocr(self):
        result = inspector.inspect_pdf(
            PDF, "ver_1", SHA, signatures=self.signatures,
            run=lambda args, cwd: self.runner(args, cwd, only_text=True),
        )
        self.assertEqual(result["scanVerdict"], "clean")
        self.assertTrue(any("--json-key=pages" in a for a in self.calls))
        self.assertTrue(any("--json-stream-data=inline" in a for a in self.calls))
        self.assertFalse(any(a[0] in ("pdftoppm", "tesseract") for a in self.calls))

    def test_qpdf_userunit_json_failure_fails_closed(self):
        for bad in ("", "not json", page_json(3, "9 0 R")):
            self.calls.clear()
            def run(args, cwd):
                if args[:2] == ["qpdf", "--json"] and "--json-key=qpdf" in args:
                    self.calls.append(tuple(args))
                    return bad
                return self.runner(args, cwd)
            with self.subTest(bad=bad[:40]), self.assertRaises(
                inspector.ReviewRequired
            ):
                inspector.inspect_pdf(
                    PDF, "ver_1", SHA, signatures=self.signatures, run=run,
                )
            self.assertFalse(any(a[0] == "pdftoppm" for a in self.calls))


if __name__ == "__main__":
    unittest.main()
