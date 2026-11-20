"""R1.16 defensive source experiment: bounded PDF corpus and honest outcomes."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_adversarial_corpus import (
    _segment, corpus_sha256, jbig2_custom_huffman_pdf,
    jbig2_oversized_page_pdf, splash_far_clipped_pdf,
    synthetic_differential_pdfs,
)
from poppler_adversarial_differential import (
    CASES, SANITIZER_CLASSIFICATIONS, SCRIPT, VARIANTS,
    inspect_source_differential, main, read_instrumented_results,
    validate_differential_observation, verify_expected_parser_differentials,
)


def fixture_report():
    return {
        "status": "source_differential_research_only",
        "cases": {
            case: {
                variant: {
                    "exit_code": 0,
                    "sanitizer": "none",
                    "raster_sha256": hashlib.sha256(case.encode()).hexdigest(),
                    "diagnostic_prefix": "",
                }
                for variant in VARIANTS
            }
            for case in CASES
        },
        "all_selected_cve_fixes_verified": False,
        "cve_remediation_claimed": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "release_authorized": False,
    }


class PopplerAdversarialDifferentialTests(unittest.TestCase):
    def test_corpus_is_reproducible_bounded_and_wholly_synthetic(self):
        first = synthetic_differential_pdfs()
        second = synthetic_differential_pdfs()
        self.assertEqual(first, second)
        self.assertEqual(set(first), CASES)
        self.assertEqual(len(first), 6)
        self.assertEqual(
            corpus_sha256(),
            {k: hashlib.sha256(v).hexdigest() for k, v in first.items()},
        )
        for payload in first.values():
            self.assertTrue(payload.startswith(b"%PDF-"))
            self.assertLess(len(payload), 8192)
            self.assertNotIn(b"Documento Nacional", payload)

    def test_jbig2_int_min_and_control_segment_are_deterministically_encoded(self):
        low = jbig2_custom_huffman_pdf(-(1 << 31))
        control = jbig2_custom_huffman_pdf(0)
        self.assertNotEqual(low, control)
        self.assertIn(struct.pack(">ii", -(1 << 31), -(1 << 31)), low)
        self.assertIn(b"/JBIG2Decode", low)
        self.assertIn(b"/Subtype /Image", low)
        self.assertIn(b"/JBIG2Decode", jbig2_oversized_page_pdf())
        with self.assertRaises(ValueError):
            jbig2_custom_huffman_pdf(42)
        with self.assertRaises(ValueError):
            _segment(0, 53, 0, b"")
        with self.assertRaises(ValueError):
            _segment(1, 53, 1, b"X" * 257)

    def test_splash_far_case_is_bounded_and_clipping_is_explicit(self):
        pdf = splash_far_clipped_pdf()
        self.assertIn(b"600000000 cm", pdf)
        self.assertIn(b"W n", pdf)
        self.assertLess(len(pdf), 4096)

    def test_validator_rejects_claimed_cve_fixes_and_incomplete_cases(self):
        report = fixture_report()
        self.assertEqual(validate_differential_observation(report), report)
        bad = fixture_report()
        bad["release_authorized"] = True
        with self.assertRaises(ValueError):
            validate_differential_observation(bad)
        bad = fixture_report()
        bad["cases"].pop("jbig2_intmin")
        with self.assertRaises(ValueError):
            validate_differential_observation(bad)
        bad = fixture_report()
        bad["cases"]["sampled32"].pop("patched")
        with self.assertRaises(ValueError):
            validate_differential_observation(bad)

    def test_validator_rejects_false_results_invalid_hashes_and_diagnostics(self):
        for mutation in ("invalid_exit", "invalid_hash", "untrusted_marker",
                         "long_diagnostic", "unrecognized_field"):
            report = fixture_report()
            field = report["cases"]["sampled32"]["original"]
            if mutation == "invalid_exit":
                field["exit_code"] = False
            if mutation == "invalid_hash":
                field["raster_sha256"] = "bad"
            if mutation == "untrusted_marker":
                field["sanitizer"] = "CVE_fixed"
            if mutation == "long_diagnostic":
                field["diagnostic_prefix"] = "x" * 401
            if mutation == "unrecognized_field":
                field["cve_fixes_verified"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_differential_observation(report)
        self.assertIn("ubsan_signed_integer_overflow", SANITIZER_CLASSIFICATIONS)

    def test_scripts_are_offline_source_scoped_and_do_not_modify_runtime(self):
        root = Path(__file__).resolve().parents[1] / "research_patches"
        build = (root / "run_adversarial_differential.sh").read_text()
        runtime = (root / "run_adversarial_cases.sh").read_text()
        self.assertIn("sha256sum --check /fixtures/baseline.sha256", build)
        self.assertIn("sha256sum --check /fixtures/patched.sha256", build)
        self.assertIn("cmake --build", build)
        self.assertIn("--target pdftoppm", build)
        self.assertIn("timeout --signal=TERM --kill-after=2s 8s", runtime)
        self.assertIn("sha256sum --check /fixtures/differential-corpus.sha256", runtime)
        self.assertIn("bash /prototypes/run_adversarial_cases.sh", build)
        self.assertNotIn("docker push", build)
        self.assertNotIn("--network host", build)
        self.assertEqual(SCRIPT, "/prototypes/run_adversarial_differential.sh")

    def test_two_real_parser_differentials_and_four_controls_are_required(self):
        report = fixture_report()
        for case, sanitizer in (
            ("sampled32", "ubsan_shift_exponent_32"),
            ("jbig2_intmin", "ubsan_signed_integer_overflow"),
        ):
            report["cases"][case]["original"]["sanitizer"] = sanitizer
            report["cases"][case]["original"]["exit_code"] = 1
        report["cases"]["jbig2_intmin"]["patched"]["diagnostic_prefix"] = (
            "Syntax Error (500): 1 extraneous byte after segment"
        )
        result = verify_expected_parser_differentials(report)
        self.assertTrue(result["two_numeric_ub_differentials_observed"])
        self.assertTrue(result["four_control_rasters_identical"])
        self.assertTrue(result["jbig2_intmin_syntax_warning_remains"])
        self.assertFalse(result["selected_cve_fixes_verified"])
        invalid = fixture_report()
        with self.assertRaises(ValueError):
            verify_expected_parser_differentials(invalid)
        invalid = json.loads(json.dumps(report))
        invalid["cases"]["splash_far"]["patched"]["raster_sha256"] = (
            hashlib.sha256(b"unexpected image").hexdigest()
        )
        with self.assertRaises(ValueError):
            verify_expected_parser_differentials(invalid)
        invalid = json.loads(json.dumps(report))
        invalid["cases"]["jbig2_intmin"]["patched"]["sanitizer"] = "sanitizer_other"
        with self.assertRaises(ValueError):
            verify_expected_parser_differentials(invalid)

    def test_main_fails_closed_without_official_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(sys, "argv", [
                "poppler_adversarial_differential.py",
                "--source-directory", temp,
                "--fix-directory", temp,
                "--builder-image-id", "sha256:" + "0" * 64,
            ]), patch("builtins.print") as emitted:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(emitted.call_args.args[0]), {
                    "status": "error",
                    "reason": "poppler_adversarial_differential_evidence_incomplete",
                    "release_authorized": False,
                })

    def test_read_real_outputs_rejects_missing_tampered_or_forged_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                read_instrumented_results(root)
            for case in CASES:
                for variant in VARIANTS:
                    prefix = root / (variant + "-" + case)
                    Path(str(prefix) + ".exit").write_text("0\n")
                    Path(str(prefix) + ".stderr").write_text("")
                    Path(str(prefix) + ".stdout").write_text("")
            observed = read_instrumented_results(root)
            self.assertFalse(observed["release_authorized"])
            self.assertEqual(set(observed["cases"]), CASES)
            Path(str(root / "original-sampled32") + ".exit").write_text("CVE_fixed")
            with self.assertRaises(ValueError):
                read_instrumented_results(root)
            Path(str(root / "original-sampled32") + ".exit").write_text("0")
            Path(str(root / "patched-jbig2_intmin") + ".stderr").write_bytes(
                b"x" * (128 * 1024 + 1)
            )
            with self.assertRaises(ValueError):
                read_instrumented_results(root)

    def test_validator_preserves_real_sanitizer_findings_without_clearance(self):
        report = fixture_report()
        report["cases"]["sampled32"]["original"]["sanitizer"] = (
            "ubsan_shift_exponent_32"
        )
        report["cases"]["jbig2_intmin"]["original"]["sanitizer"] = (
            "ubsan_signed_integer_overflow"
        )
        self.assertEqual(validate_differential_observation(report), report)
        self.assertFalse(report["cve_remediation_claimed"])
        self.assertFalse(report["release_authorized"])


if __name__ == "__main__":
    unittest.main()
