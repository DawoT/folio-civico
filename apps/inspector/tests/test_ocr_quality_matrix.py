"""Pure policy tests for the no-network, real-engine synthetic OCR quality matrix."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ocr_quality_matrix as quality


def report(errors=0):
    return {
        "source":quality.SOURCE,
        "cases":[
            {
                "case":name,
                "fixture_sha256":hashlib.sha256(name.encode()).hexdigest(),
                "text_sha256":hashlib.sha256(expected.encode()).hexdigest(),
                "expected_sha256":hashlib.sha256(quality.canonical(expected).encode()).hexdigest(),
                "errors":errors,
                "reference_characters":len(quality.canonical(expected)),
            }
            for name,expected in quality.CORPUS
        ],
    }


class OcrMatrixTests(unittest.TestCase):
    def test_ocr_metric_counts_insertions_deletions_and_substitutions(self):
        self.assertEqual(quality.edit_distance("OBRA", "OBRA"),0)
        self.assertEqual(quality.edit_distance("OBRA", "OBAR"),2)
        self.assertEqual(quality.edit_distance("OBRA", "OBR"),1)
        self.assertEqual(quality.edit_distance("OBRA", "OBRAX"),1)
        self.assertEqual(quality.canonical(" revisión  pública\n2026 "), "REVISIÓN PÚBLICA 2026")

    def test_original_synthetic_pdf_can_encode_spanish_accents(self):
        pdf=quality.synthetic_text_pdf("REVISIÓN PÚBLICA 2026")
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"/WinAnsiEncoding",pdf)
        self.assertNotIn(b"/Subtype /Image",pdf)
        for bad in ("", "x"*71, "invalid\nline", "unmapped ☂"):
            with self.subTest(bad=bad), self.assertRaises((ValueError,UnicodeEncodeError)):
                quality.synthetic_text_pdf(bad)

    def test_incomplete_or_changed_baseline_fails_closed(self):
        base=report()
        candidate=copy.deepcopy(base)
        self.assertEqual(quality.compare_reports(base,candidate)["status"],"no_regression")
        changed=copy.deepcopy(candidate)
        changed["cases"][2]["fixture_sha256"]="f"*64
        with self.assertRaises(ValueError):
            quality.compare_reports(base,changed)
        changed=copy.deepcopy(candidate)
        changed["cases"].pop()
        with self.assertRaises(ValueError):
            quality.compare_reports(base,changed)
        changed=copy.deepcopy(candidate)
        changed["source"]="unknown"
        with self.assertRaises(ValueError):
            quality.compare_reports(base,changed)

    def test_error_increase_blocks_even_if_text_hashes_match(self):
        base=report()
        candidate=copy.deepcopy(base)
        candidate["cases"][1]["errors"]=1
        summary=quality.compare_reports(base,candidate)
        self.assertEqual(summary["status"],"regression")
        self.assertEqual(summary["regressed_cases"],["spanish-identifier"])
        self.assertEqual(summary["candidate_char_errors"],1)
        self.assertTrue(summary["synthetic_only"])

    def test_matrix_requires_real_inspector_and_discloses_only_hashes(self):
        def inspect(_pdf,version,_sha256,*,signatures):
            expected=dict(
                (name.replace("-","_"),text) for name,text in quality.CORPUS
            )[version]
            self.assertEqual(signatures,Path("/opt/clamdb"))
            return {"pages":[{"page":1,"text":expected}]}
        with patch.object(quality,"synthetic_scan",return_value=b"mocked_for_unit_only"), \
             patch.object(quality,"inspect_pdf",side_effect=inspect):
            payload=quality.matrix_report()
        self.assertEqual(len(payload["cases"]),4)
        self.assertTrue(all(x["errors"]==0 for x in payload["cases"]))
        self.assertNotIn("REVISIÓN PÚBLICA",repr(payload))


if __name__=="__main__":
    unittest.main()
