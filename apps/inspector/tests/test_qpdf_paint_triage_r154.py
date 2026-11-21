"""R1.54: bounded PDF semantic paint-token RESEARCH only (no release gate)."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from inspector import ReviewRequired
from qpdf_paint_triage_r154 import has_uncovered_paint, qpdf_page_has_uncovered_paint

TEXT = b"BT\n/F1 24 Tf\n70 720 Td\n(EXPEDIENTE OBRA 2026) Tj\nET\n"
VECTOR = TEXT + b"80 540 8 8 re f\n"
REF = "4 0 R"


def document(data: bytes = TEXT) -> dict:
    return {
        "version": 2,
        "pages": [{
            "contents": [REF], "images": [],
            "pageposfrom1": 1, "object": "3 0 R",
        }],
        "qpdf": [
            {"jsonversion": 2, "maxobjectid": 5},
            {
                "obj:3 0 R": {
                    "value": {"/Type": "/Page", "/Resources": {
                        "/Font": {"/F1": "5 0 R"},
                    }}
                },
                "obj:4 0 R": {"stream": {
                    "data": base64.b64encode(data).decode("ascii"),
                    "dict": {},
                }},
                "obj:5 0 R": {"value": {
                    "/Type": "/Font", "/Subtype": "/Type1",
                    "/BaseFont": "/Helvetica",
                }},
            },
        ],
    }


class QpdfSemanticPaintResearchTests(unittest.TestCase):
    def test_accepts_known_text_only_operators_without_vector_paint(self):
        self.assertFalse(has_uncovered_paint(TEXT))
        self.assertFalse(qpdf_page_has_uncovered_paint(json.dumps(document()), page=1, count=1))

    def test_detects_vector_path_shading_form_and_inline_image_ops(self):
        for op in (b"re", b"m", b"l", b"S", b"f", b"f*", b"B", b"Do",
                   b"sh", b"BI", b"ID", b"EI", b"gs", b"BDC", b"BX",
                   b"EX", b"W", b"n"):
            with self.subTest(op=op):
                self.assertTrue(has_uncovered_paint(TEXT + b" 20 20 " + op + b"\n"))

    def test_text_strings_and_comments_cannot_spoof_graphic_operators(self):
        for data in (
            b"BT\n/F1 24 Tf (words re f Do sh) Tj ET\n",
            b"BT /F1 24 Tf ((re f) \\(BI\\) sh) Tj ET",
            b"BT /F1 24 Tf <7265206620446f> Tj ET",
            b"% re f Do BI sh\nBT /F1 24 Tf (good) Tj ET\n",
            b"q 1 0 0 1 0 0 cm BT /F1 24 Tf [(abc) -12 (de)] TJ ET Q",
        ):
            with self.subTest(content=data):
                self.assertFalse(has_uncovered_paint(data))

    def test_opaque_and_unbalanced_stream_syntax_fails_closed(self):
        for data in (
            b"", b"BT /F1 24 Tf (incomplete Tj",
            b"BT /F1 24 Tf (((((((((((((((((text))))))))))))))))) Tj ET",
            b"BT /F1 24 Tf << /ActualText (hidden) >> BDC (abc) Tj ET",
            b"BT /F1 24 Tf <nothex> Tj ET",
            b"BT /F1 24 Tf [(abc) Tj ET",
            b"BT /F1 24 Tf ] (abc) Tj ET",
            b"BT /F1 24 Tf (x) Tj ET Q",
            b"BT BT (x) Tj ET ET",
            b"ET",
            b"q BT /F1 24 Tf (x) Tj ET",
            b"BT /F1 24 Tf (x) Tj",
            b"BT /F1 24 Tf /Name\xff (x) Tj ET",
            b"A" * 129,
        ):
            with self.subTest(case=data[:50]), self.assertRaises(ReviewRequired):
                has_uncovered_paint(data)

    def test_known_nontext_operator_is_a_review_signal_not_parser_error(self):
        self.assertTrue(has_uncovered_paint(b"42 50 10 3 re"))
        self.assertTrue(has_uncovered_paint(b"BT /F1 24 Tf " + bytes([92])))

    def test_length_and_token_limits_are_bounded(self):
        with self.assertRaises(ReviewRequired):
            has_uncovered_paint(b"BT " + b" " * (128 * 1024))
        with self.assertRaises(ReviewRequired):
            has_uncovered_paint(b"BT " + b"1 " * 50010 + b"ET")

    def test_qpdf_base64_stream_reference_and_identity_are_strict(self):
        normal = document()
        tamper = []
        wrong = copy.deepcopy(normal);wrong["version"] = 3;tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["pages"][0]["pageposfrom1"] = 2;tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["pages"][0]["object"] = "x 0 R";tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["qpdf"][0]["jsonversion"] = 3;tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["pages"][0]["contents"] = ["100 0 R"];tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["pages"][0]["contents"] = [REF, REF];tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["qpdf"][1]["obj:4 0 R"]["stream"]["data"] = "??";tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["qpdf"][1]["obj:4 0 R"]["stream"]["dict"]["/Filter"]="/UnknownDecode";tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["qpdf"][1]["obj:4 0 R"]["stream"]["data"] = None;tamper.append(wrong)
        wrong = copy.deepcopy(normal);wrong["qpdf"][1]["obj:3 0 R"]["value"]["/Type"] = "/Pages";tamper.append(wrong)
        for bad in tamper:
            with self.subTest(bad=str(bad)[:160]), self.assertRaises(ReviewRequired):
                qpdf_page_has_uncovered_paint(json.dumps(bad), page=1, count=1)
        for page,count in ((0,1),(2,1),(1,2),(1,101),(True,1)):
            with self.subTest(page=page,count=count),self.assertRaises(ReviewRequired):
                qpdf_page_has_uncovered_paint(json.dumps(normal), page=page, count=count)

    def test_annotations_and_non_text_resources_block_visual_assumptions(self):
        for resource in ("/Pattern", "/Shading", "/XObject", "/ExtGState"):
            bad = document()
            bad["qpdf"][1]["obj:3 0 R"]["value"]["/Resources"][resource] = {}
            with self.subTest(resource=resource):
                self.assertTrue(qpdf_page_has_uncovered_paint(json.dumps(bad), page=1, count=1))
        bad = document()
        bad["qpdf"][1]["obj:3 0 R"]["value"]["/Annots"] = ["6 0 R"]
        self.assertTrue(qpdf_page_has_uncovered_paint(json.dumps(bad), page=1, count=1))

    def test_type3_fonts_and_unresolved_font_identity_require_review(self):
        for subtype in ("/Type3", "/Type0", "/CIDFontType2", "/Unknown"):
            bad = document()
            bad["qpdf"][1]["obj:5 0 R"]["value"]["/Subtype"] = subtype
            with self.subTest(subtype=subtype):
                self.assertTrue(qpdf_page_has_uncovered_paint(json.dumps(bad), page=1, count=1))
        for corruption in ("missing_font", "wrong_type", "bad_ref"):
            bad = document()
            if corruption == "missing_font":
                bad["qpdf"][1].pop("obj:5 0 R")
            elif corruption == "wrong_type":
                bad["qpdf"][1]["obj:5 0 R"]["value"]["/Type"] = "/XObject"
            else:
                bad["qpdf"][1]["obj:3 0 R"]["value"]["/Resources"]["/Font"]["/F1"] = "not-ref"
            with self.subTest(corruption=corruption), self.assertRaises(ReviewRequired):
                qpdf_page_has_uncovered_paint(json.dumps(bad), page=1, count=1)

    def test_qpdf_decoded_stream_draw_commands_are_evidentially_distinct(self):
        self.assertFalse(qpdf_page_has_uncovered_paint(json.dumps(document(TEXT)),page=1,count=1))
        self.assertTrue(qpdf_page_has_uncovered_paint(json.dumps(document(VECTOR)),page=1,count=1))

    def test_multiple_decoded_content_streams_cannot_hide_a_vector(self):
        content = document(TEXT)
        content["pages"][0]["contents"].append("6 0 R")
        content["qpdf"][1]["obj:6 0 R"] = {
            "stream": {
                "data": base64.b64encode(b"20 100 m 40 100 l S").decode("ascii"),
                "dict": {},
            },
        }
        self.assertTrue(qpdf_page_has_uncovered_paint(
            json.dumps(content), page=1, count=1
        ))
        content["pages"][0]["contents"][1] = {"malformed": "object"}
        with self.assertRaises(ReviewRequired):
            qpdf_page_has_uncovered_paint(json.dumps(content), page=1, count=1)

    def test_duplicate_json_fields_and_control_chars_fail_closed(self):
        raw=json.dumps(document())
        bad=raw.replace('"version": 2', '"version": 2, "version": 2',1)
        for source in (bad,raw+"\u202e",raw*1000):
            with self.subTest(n=len(source)), self.assertRaises(ReviewRequired):
                qpdf_page_has_uncovered_paint(source,page=1,count=1)


if __name__ == "__main__":
    unittest.main()
