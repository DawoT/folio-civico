"""R1.53: strict, offline vector evidence research contract (NOT a G4 waiver)."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import probe_vector_evidence_r153 as probe

COMMANDS = ["clamscan", "qpdf", "pdftotext", "pdfimages"]


def argument(**updates):
    fixed = {
        "digital_text": probe.DIGITAL_TEXT,
        "image_present": False,
        "ink": 3936,
        "drawn_rectangles": 67,
        "scanned_text": probe.DIGITAL_TEXT,
        "reviewed": False,
        "inspected_commands": COMMANDS.copy(),
    }
    fixed.update(updates)
    return fixed


class VectorEvidenceResearchTests(unittest.TestCase):
    def test_fixture_contains_unique_vector_evidence_not_raster(self):
        data, shapes = probe.vector_evidence_pdf()
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertIn(probe.DIGITAL_TEXT.encode("ascii"), data)
        self.assertNotIn(probe.VECTOR_VALUE.encode("ascii"), data)
        self.assertNotIn(b"/Subtype /Image", data)
        self.assertNotIn(b"/Im0 Do", data)
        self.assertGreaterEqual(shapes, 50)
        self.assertEqual(data.count(b" re f\n"), shapes)
        self.assertLess(len(data), 8192)

    def test_grayscale_probe_counts_only_expected_graphic_region(self):
        blank = bytes([255]) * (probe.WIDTH * probe.HEIGHT)
        source = b"P5\n612 792\n255\n"
        self.assertEqual(probe.count_vector_ink(source + blank), 0)
        changed = bytearray(blank)
        for y in range(200, 260):
            for x in range(90, 190):
                changed[y * probe.WIDTH + x] = 0
        self.assertEqual(probe.count_vector_ink(source + changed), 6000)

    def test_pgm_parser_never_accepts_malformed_or_unbounded_decodes(self):
        base = b"P5\n612 792\n255\n"
        pixels = b"\xff" * (probe.WIDTH * probe.HEIGHT)
        for bad in (b"", b"P6\n612 792\n255\n"+pixels,
                    b"P5\n612 793\n255\n"+pixels,
                    b"P5\n612 792\n127\n"+pixels,
                    base + pixels[:-1], base + pixels + b"x" * 1024,
                    b"something confidential"):
            with self.subTest(sample=bad[:30]), self.assertRaises(ValueError):
                probe.count_vector_ink(bad)

    def test_live_clean_result_with_missing_graphic_never_approves_g4(self):
        result = probe.classify_result(**argument())
        self.assertEqual(result["status"], "vector_evidence_gap_reproduced_release_blocked")
        self.assertTrue(result["visual_value_omitted_from_manifest"])
        self.assertIs(result["release_authorized"], False)
        self.assertEqual(result["g4_gate"], "blocked")
        self.assertNotIn("EXPEDIENTE", json.dumps(result))

    def test_future_review_result_is_also_not_release_approval(self):
        result = probe.classify_result(
            **argument(scanned_text=None, reviewed=True)
        )
        self.assertEqual(result["status"], "vector_evidence_review_required_release_blocked")
        self.assertIsNone(result["visual_value_omitted_from_manifest"])
        self.assertIs(result["release_authorized"], False)

    def test_cli_returns_blocked_exit_two_only_for_valid_observations(self):
        for evidence in (
            probe.classify_result(**argument()),
            probe.classify_result(**argument(scanned_text=None, reviewed=True)),
        ):
            output = io.StringIO()
            with patch.object(probe, "probe", return_value=evidence), contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(), 2)
            actual = json.loads(output.getvalue())
            self.assertEqual(actual, evidence)
            self.assertIs(actual["release_authorized"], False)
            self.assertEqual(actual["g4_gate"], "blocked")

    def test_cli_rejects_unavailable_scanner_without_exposing_details(self):
        output = io.StringIO()
        with patch.object(probe, "probe", side_effect=ValueError("private /tmp/synthetic.pdf")), contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(), 3)
        self.assertEqual(json.loads(output.getvalue()), {
            "status": "vector_evidence_probe_incomplete",
            "release_authorized": False, "g4_gate": "blocked",
        })
        self.assertNotIn("private", output.getvalue())

    def test_ambiguous_or_untrustworthy_evidence_fails_closed(self):
        modifications = (
            {"digital_text": ""}, {"digital_text": "6002"},
            {"image_present": True}, {"ink": 0}, {"ink": 999},
            {"drawn_rectangles": 0}, {"drawn_rectangles": 101},
            {"inspected_commands": ["clamscan", "pdftotext", "pdfimages"]},
            {"scanned_text": "6002"}, {"scanned_text": ""},
            {"scanned_text": None, "reviewed": False},
            {"scanned_text": probe.DIGITAL_TEXT, "reviewed": True},
        )
        for change in modifications:
            with self.subTest(change=change), self.assertRaises(ValueError):
                probe.classify_result(**argument(**change))


if __name__ == "__main__":
    unittest.main()
