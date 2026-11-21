"""R1.55 — RED regression: digital PDF text must not hide vector evidence.

All documents, rows and engine reports in these tests are synthetic; the
fixture represents only a single-page known PDF structure. Real-engine smoke
must be run separately in the isolated inspector image.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fixtures import native_pdf
from pdfimages_fixtures import EMPTY_REPORT
from probe_vector_evidence_r153 import DIGITAL_TEXT, VECTOR_VALUE, vector_evidence_pdf
from inspector import ReviewRequired, ScannerUnavailable, inspect_pdf, QPDF_UNENCRYPTED

TEXT_STREAM = ("BT\n/F1 24 Tf\n70 720 Td\n(" + DIGITAL_TEXT + ") Tj\nET\n").encode()
VECTOR_STREAM = TEXT_STREAM + b"80 540 8 8 re f\n"


def qpdf_response(**parts: object) -> str:
    return json.dumps({"version": 2, **parts}, separators=(",", ":"))


def qpdf_object(ref: str, payload: dict) -> str:
    return qpdf_response(qpdf=[
        {"jsonversion": 2}, {"obj:" + ref: payload},
    ])


class VectorAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.signatures = Path(self.tmp.name)
        for name in ("daily.cld", "main.cvd", "bytecode.cvd"):
            (self.signatures / name).write_bytes(b"synthetic")

    def runner(self, stream: bytes, *, font_subtype: str = "/Type1",
               fail_qpdf: bool = False):
        calls: list[tuple[str, ...]] = []

        def run(argv: list[str], _cwd: Path) -> str:
            calls.append(tuple(argv))
            name = argv[0]
            if name == "clamscan" and "--version" in argv:
                return "ClamAV 1.5.5"
            if name == "clamscan":
                return ""
            if argv[:2] == ["qpdf", "--is-encrypted"]:
                return QPDF_UNENCRYPTED
            if argv[:2] == ["qpdf", "--check"]:
                return ""
            if name == "qpdf":
                if fail_qpdf:
                    raise ScannerUnavailable("Synthetic QPDF not available")
                if "--json-key=pages" in argv:
                    return qpdf_response(pages=[{
                        "pageposfrom1": 1, "object": "3 0 R",
                        "contents": ["4 0 R"], "images": [],
                    }])
                if "--json-object=3,0" in argv:
                    return qpdf_object("3 0 R", {
                        "value": {
                            "/Type": "/Page", "/Contents": "4 0 R",
                            "/Resources": {"/Font": {"/F1": "5 0 R"}},
                        },
                    })
                if "--json-object=5,0" in argv:
                    return qpdf_object("5 0 R", {
                        "value": {
                            "/Type": "/Font", "/Subtype": font_subtype,
                            "/BaseFont": "/Helvetica",
                        },
                    })
                if "--json-object=4,0" in argv:
                    if "--json-stream-data=inline" not in argv or "--decode-level=all" not in argv:
                        raise AssertionError("Decoded stream is mandatory")
                    return qpdf_object("4 0 R", {
                        "stream": {"dict": {}, "data": base64.b64encode(stream).decode()},
                    })
                raise AssertionError("Unknown QPDF object request")
            if name == "pdfdetach":
                return "0 embedded files"
            if name == "pdfinfo":
                return "Pages: 1\nEncrypted: no\n"
            if name == "pdftotext":
                return DIGITAL_TEXT
            if name == "pdfimages":
                return EMPTY_REPORT
            raise AssertionError(f"Unexpected engine {name}")
        return run, calls

    def inspect(self, sample: bytes, run):
        return inspect_pdf(
            sample, "synthetic_vector_r155",
            hashlib.sha256(sample).hexdigest(),
            signatures=self.signatures, run=run,
        )

    def test_vector_content_with_digital_text_cannot_receive_clean(self):
        sample, shapes = vector_evidence_pdf()
        self.assertEqual(shapes, 67)
        self.assertNotIn(VECTOR_VALUE.encode(), sample)
        run, calls = self.runner(VECTOR_STREAM)
        with self.assertRaises(ReviewRequired):
            self.inspect(sample, run)
        self.assertTrue(any("--json-stream-data=inline" in argv for argv in calls))
        self.assertFalse(any(argv[0] in ("pdftoppm", "tesseract") for argv in calls))

    def test_native_digital_text_positive_control_remains_clean(self):
        run, calls = self.runner(TEXT_STREAM)
        result = self.inspect(native_pdf(), run)
        self.assertEqual(result["scanVerdict"], "clean")
        self.assertEqual(result["pages"], [{"page": 1, "text": DIGITAL_TEXT}])
        self.assertTrue(any("--json-stream-data=inline" in argv for argv in calls))

    def test_flate_decoded_paint_is_not_treated_as_text_only(self):
        run, calls = self.runner(VECTOR_STREAM)
        with self.assertRaises(ReviewRequired):
            self.inspect(vector_evidence_pdf()[0], run)
        self.assertTrue(any("--decode-level=all" in argv for argv in calls))

    def test_unknown_type3_font_cannot_claim_complete_text(self):
        run, _calls = self.runner(TEXT_STREAM, font_subtype="/Type3")
        with self.assertRaises(ReviewRequired):
            self.inspect(native_pdf(), run)

    def test_unavailable_qpdf_visual_probe_is_fail_closed(self):
        run, calls = self.runner(TEXT_STREAM, fail_qpdf=True)
        with self.assertRaises((ReviewRequired, ScannerUnavailable)):
            self.inspect(native_pdf(), run)
        self.assertTrue(any(argv[0] == "qpdf" and "--json" in argv for argv in calls))

    def test_tampered_page_contents_reference_is_not_clean(self):
        run, calls = self.runner(TEXT_STREAM)
        def changed(argv, cwd):
            report = run(argv, cwd)
            if "--json-object=3,0" in argv:
                return report.replace('"4 0 R"', '"999 0 R"')
            return report
        with self.assertRaises(ReviewRequired):
            self.inspect(native_pdf(), changed)
        self.assertFalse(any("--json-object=999,0" in argv for argv in calls))

    def test_bad_qpdf_stream_and_bad_font_identity_are_not_clean(self):
        for altered_object, old, replacement in (
            ("4,0", '"data":"', '"data":"???'),
            ("5,0", '"/Type":"/Font"', '"/Type":"/Page"'),
        ):
            run, _calls = self.runner(TEXT_STREAM)
            def changed(argv, cwd):
                report = run(argv, cwd)
                if "--json-object=" + altered_object in argv:
                    return report.replace(old, replacement)
                return report
            with self.subTest(corruption=altered_object), self.assertRaises(ReviewRequired):
                self.inspect(native_pdf(), changed)

    def test_page_probe_decodes_only_selected_stream_objects(self):
        run, calls = self.runner(TEXT_STREAM)
        self.inspect(native_pdf(), run)
        inline = [argv for argv in calls if "--json-stream-data=inline" in argv]
        self.assertEqual(len(inline), 1)
        self.assertIn("--json-object=4,0", inline[0])
        self.assertIn("--decode-level=all", inline[0])
        self.assertFalse(any(
            "--json-stream-data=inline" in argv and
            not any(option.startswith("--json-object=") for option in argv)
            for argv in calls
        ))

    def test_image_build_copies_exact_visual_gate_modules(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        copies = [line for line in dockerfile.splitlines()
                  if line.startswith("COPY --chown=65534:65534 inspector.py ")]
        self.assertEqual(len(copies), 1)
        self.assertIn("qpdf_paint_triage_r154.py", copies[0])
        self.assertIn("qpdf_scoped_gate_r155.py", copies[0])
        self.assertNotIn("probe_vector_evidence_r153.py", copies[0])


if __name__ == "__main__":
    unittest.main()
