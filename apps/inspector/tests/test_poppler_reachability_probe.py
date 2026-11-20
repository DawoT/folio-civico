"""R1.17 actual-source method/real-PDF reachability with fail-closed evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_reachability_corpus import (
    FONT_CASE_NAME, PAGE_DIMENSION_CASES, SYNTHETIC_TTF_SHA256,
    additional_corpus_sha256, additional_reachability_pdfs,
    invalid_jbig2_page_pdfs, minimal_type42_pdf, read_synthetic_font,
)
from poppler_reachability_probe import (
    EXPECTED_CONTAINER_DONE, SCRIPT, SPLASH_CASES,
    inspect_reachability, main, read_process_output,
    verify_jbig2_early_rejection, verify_splash_method_cases,
    verify_synthetic_true_type,
)


def process(root: Path, stem: str, code: int, *, stdout="", stderr="") -> None:
    for suffix, body in (
        (".exit", str(code) + "\n"),
        (".stdout", stdout),
        (".stderr", stderr),
    ):
        (root / (stem + suffix)).write_text(body)


def splash_fixture(root: Path) -> None:
    for variant in ("original", "patched"):
        process(root, variant + "-splash_normal", 0,
                stdout="normal_path_accepted\n")
        process(root, variant + "-splash_ymin_overflow",
                0 if variant == "patched" else 1,
                stdout="splash_ymin_checked_rejected\n"
                if variant == "patched" else "",
                stderr="" if variant == "patched" else (
                    "/work/original/splash/SplashClip.cc:212:28: runtime error: "
                    "signed integer overflow: 536870919 * 4 cannot "
                    "be represented in type 'int'\n"
                ))
        process(root, variant + "-splash_ymax_residual", 1, stderr=(
            "/work/" + variant + "/splash/SplashClip.cc:213:34: "
            "runtime error: signed integer overflow: 536870919 * 4 "
            "cannot be represented in type 'int'\n"
        ))


def jbig2_fixture(root: Path) -> None:
    for variant in ("original", "patched"):
        for case in PAGE_DIMENSION_CASES:
            prefix = variant + "-" + case
            process(root, prefix, 0,
                    stderr="Syntax Error: invalid width/height\n")
            (root / (prefix + ".pgm")).write_bytes(
                b"P5\n3 2\n255\n" + b"\xff" * 6
            )


def type42_fixture(root: Path) -> None:
    for variant in ("original", "patched"):
        prefix = variant + "-" + FONT_CASE_NAME
        process(root, prefix, 0)
        (root / (prefix + ".ps")).write_bytes(
            b"%!PS-Adobe-3.0\n/FontType 42 def\n/sfnts [\n"
            b"FolioSynthetic-Regular\n"
        )


class PopplerReachabilityProbeTests(unittest.TestCase):
    def test_exact_font_is_original_small_and_sha_pinned(self):
        blob = read_synthetic_font()
        self.assertEqual(len(blob), 956)
        self.assertEqual(hashlib.sha256(blob).hexdigest(), SYNTHETIC_TTF_SHA256)
        pdf = minimal_type42_pdf()
        self.assertEqual(pdf, minimal_type42_pdf())
        self.assertLess(len(pdf), 4096)
        self.assertIn(b"/FontFile2 7 0 R", pdf)
        self.assertIn(blob, pdf)
        with self.assertRaises(ValueError):
            minimal_type42_pdf(blob[:-1])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "fake.b64"
            p.write_text("not base64!!!")
            with self.assertRaises(ValueError):
                read_synthetic_font(p)

    def test_new_jbig2_cases_exercise_three_bounded_invalid_dimensions(self):
        pdfs = invalid_jbig2_page_pdfs()
        self.assertEqual(set(pdfs), set(PAGE_DIMENSION_CASES))
        self.assertEqual(len(additional_reachability_pdfs()), 4)
        self.assertEqual(set(additional_corpus_sha256()), {
            *PAGE_DIMENSION_CASES, FONT_CASE_NAME,
        })
        for name, blob in pdfs.items():
            self.assertTrue(blob.startswith(b"%PDF-"))
            self.assertIn(b"/JBIG2Decode", blob)
            self.assertLess(len(blob), 1024)
        self.assertEqual(
            additional_corpus_sha256(),
            additional_corpus_sha256(),
        )

    def test_actual_splash_method_requires_true_original_ub_and_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            splash_fixture(root)
            report = verify_splash_method_cases(root)
            self.assertEqual(set(report["cases"]), set(SPLASH_CASES))
            self.assertTrue(report["actual_splash_method_ymin_guard_observed"])
            self.assertTrue(report["actual_splash_method_ymax_residual_ub_observed_both"])
            self.assertFalse(report["reached_through_pdf_parser"])
            self.assertFalse(report["splash_cve_fully_verified"])

    def test_method_path_fails_closed_on_fake_guard_or_missing_residual_ub(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            splash_fixture(root)
            process(root, "patched-splash_ymin_overflow", 0,
                    stdout="normal_path_accepted\n")
            with self.assertRaises(ValueError):
                verify_splash_method_cases(root)
            splash_fixture(root)
            process(root, "patched-splash_ymax_residual", 0)
            with self.assertRaises(ValueError):
                verify_splash_method_cases(root)
            splash_fixture(root)
            process(root, "original-splash_ymin_overflow", 1,
                    stderr="AddressSanitizer: generic fault\n")
            with self.assertRaises(ValueError):
                verify_splash_method_cases(root)

    def test_jbig2_invalid_cases_require_actual_rejection_and_raster_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jbig2_fixture(root)
            result = verify_jbig2_early_rejection(root)
            self.assertEqual(result["invalid_page_cases_rejected_equally"], 3)
            self.assertFalse(result["null_bitmap_arithmetic_reproduced"])
            (root / "patched-jbig2_zero_width.pgm").write_bytes(
                b"P5\n3 2\n255\n" + b"\x00" * 6
            )
            with self.assertRaises(ValueError):
                verify_jbig2_early_rejection(root)
            jbig2_fixture(root)
            process(root, "original-jbig2_zero_height", 0,
                    stderr="runtime error: signed integer overflow\n")
            with self.assertRaises(ValueError):
                verify_jbig2_early_rejection(root)

    def test_true_type_requires_ps_type42_and_exact_byte_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            type42_fixture(root)
            verified = verify_synthetic_true_type(root)
            self.assertTrue(
                verified["type42_postscript_baseline_equal_to_prototype"]
            )
            self.assertFalse(verified["truetype_glyph_length_overflow_reproduced"])
            other = root / "patched-type42_synthetic.ps"
            other.write_bytes(other.read_bytes() + b"changed")
            with self.assertRaises(ValueError):
                verify_synthetic_true_type(root)
            type42_fixture(root)
            other.write_bytes(b"%!PS but no Type42")
            with self.assertRaises(ValueError):
                verify_synthetic_true_type(root)

    def test_missing_or_symlinked_evidence_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            splash_fixture(root)
            path = root / "original-splash_normal.exit"
            path.unlink()
            with self.assertRaises(ValueError):
                read_process_output(root, "original-splash_normal")
            path.symlink_to(root / "patched-splash_normal.exit")
            with self.assertRaises(ValueError):
                read_process_output(root, "original-splash_normal")
            path.unlink()
            path.write_text("CVE_FIXED")
            with self.assertRaises(ValueError):
                read_process_output(root, "original-splash_normal")

    def test_shell_reuses_strict_r116_build_not_release(self):
        paths = Path(__file__).resolve().parents[1] / "research_patches"
        run = (paths / "run_reachability_differential.sh").read_text()
        cases = (paths / "run_reachability_cases.sh").read_text()
        harness = (paths / "splash_clip_method_probe.cc").read_text()
        self.assertIn("bash /prototypes/run_adversarial_differential.sh", run)
        self.assertIn("sha256sum --check /fixtures/r117-corpus.sha256", run)
        self.assertIn("--target pdftops", run)
        self.assertIn("splash/SplashClip.cc", run)
        self.assertIn("-fsanitize=address,undefined", run)
        self.assertIn("timeout --signal=TERM --kill-after=2s 5s", cases)
        self.assertIn("timeout --signal=TERM --kill-after=2s 8s", cases)
        self.assertIn("SplashClip::clipToPath", harness)
        self.assertNotIn("docker push", run)
        self.assertNotIn("wrangler deploy", run)
        self.assertEqual(SCRIPT, "/prototypes/run_reachability_differential.sh")

    def test_fake_container_success_without_outputs_never_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("fixes").mkdir()
            root.joinpath("patches").mkdir()
            fake = {
                "base_source_version": "25.03.0-5+deb13u4",
                "baseline_sha256": {
                    "poppler/Function.cc": hashlib.sha256(b"a").hexdigest(),
                },
                "prototype_source_sha256": {
                    "poppler/Function.cc": hashlib.sha256(b"b").hexdigest(),
                },
                "research_patch_sha256": {},
            }
            report = subprocess.CompletedProcess(
                [], 0, stdout=EXPECTED_CONTAINER_DONE + "\n", stderr="",
            )
            with patch("poppler_reachability_probe.inspect_semantic_prototypes",
                       return_value=fake):
                with self.assertRaises(ValueError):
                    inspect_reachability(
                        {}, {}, {},
                        builder_id="sha256:" + "c" * 64,
                        fix_directory=root / "fixes",
                        prototype_directory=root / "patches",
                        runner=lambda *a, **kw: report,
                    )

    def test_cli_fails_closed_without_official_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sys, "argv", [
                "poppler_reachability_probe.py",
                "--source-directory", tmp,
                "--fix-directory", tmp,
                "--builder-image-id", "sha256:" + "0" * 64,
            ]), patch("builtins.print") as printer:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(printer.call_args.args[0]), {
                    "status": "error",
                    "reason": "poppler_r117_source_reachability_evidence_incomplete",
                    "release_authorized": False,
                })


if __name__ == "__main__":
    unittest.main()
