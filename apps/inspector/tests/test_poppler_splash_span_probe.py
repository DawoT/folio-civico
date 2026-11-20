"""R1.24: fail-closed actual SplashClip::testSpan differential contract."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_splash_span_probe import (
    CONDITIONS, DONE, OVERFLOW, SCRIPT, STDOUT, VARIANTS,
    inspect_span, main, verify_span_results,
)


def fill(root: Path) -> None:
    for variant in VARIANTS:
        for condition in CONDITIONS:
            stem = root / (variant + "-span_" + condition)
            is_overflow = condition == "span_x_aa_overflow"
            code = 1 if is_overflow else 0
            stdout = "" if is_overflow else STDOUT[condition]
            stderr = (
                f"/work/{variant}/splash/SplashClip.cc:264:74: "
                f"{OVERFLOW} cannot be represented in type 'int'\n"
            ) if is_overflow else ""
            for ext, value in (
                (".exit", f"{code}\n"), (".stdout", stdout),
                (".stderr", stderr),
            ):
                Path(str(stem) + ext).write_text(value)


class SplashSpanProbeTests(unittest.TestCase):
    def test_three_sources_four_cases_expected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill(root)
            report = verify_span_results(root)
            self.assertEqual(set(report["cases"]), set(CONDITIONS))
            self.assertTrue(report["all_three_variants_prove_residual_ub"])
            self.assertTrue(report["no_path_extreme_short_circuits"])
            self.assertTrue(report["outside_rect_extreme_short_circuits"])
            self.assertFalse(report["pdf_parser_reachability_verified"])
            self.assertFalse(report["additional_cve_remediation_verified"])
            for variant in VARIANTS:
                self.assertEqual(
                    report["cases"]["span_x_aa_overflow"][variant]["exit_code"], 1,
                )

    def test_fake_success_on_overflow_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill(root)
            (root / "extended-span_span_x_aa_overflow.exit").write_text("0\n")
            with self.assertRaises(ValueError):
                verify_span_results(root)
            fill(root)
            (root / "extended-span_span_x_aa_overflow.stderr").write_text("")
            with self.assertRaises(ValueError):
                verify_span_results(root)

    def test_wrong_ub_site_or_value_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill(root)
            (root / "patched-span_span_x_aa_overflow.stderr").write_text(
                "/other/Source.cc:20:2: " + OVERFLOW + "\n"
            )
            with self.assertRaises(ValueError):
                verify_span_results(root)
            fill(root)
            (root / "patched-span_span_x_aa_overflow.stderr").write_text(
                "/work/patched/splash/SplashClip.cc:264:74: "
                "runtime error: signed integer overflow: 900000000 * 2\n"
            )
            with self.assertRaises(ValueError):
                verify_span_results(root)

    def test_other_sanitizer_or_crash_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill(root)
            path = root / "original-span_span_x_aa_overflow.stderr"
            path.write_text(path.read_text() + "AddressSanitizer: unrelated issue\n")
            with self.assertRaises(ValueError):
                verify_span_results(root)
            fill(root)
            (root / "original-span_span_x_aa_overflow.exit").write_text("139\n")
            with self.assertRaises(ValueError):
                verify_span_results(root)

    def test_normal_path_and_short_circuit_must_be_real(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill(root)
            (root / "patched-span_no_path_extreme.stdout").write_text(
                "normal_span_inside\n"
            )
            with self.assertRaises(ValueError):
                verify_span_results(root)
            fill(root)
            (root / "extended-span_outside_guard.stderr").write_text(
                "unexpected warning\n"
            )
            with self.assertRaises(ValueError):
                verify_span_results(root)

    def test_missing_symlink_and_timeout_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill(root)
            path = root / "original-span_normal.exit"
            path.unlink()
            path.symlink_to(root / "patched-span_normal.exit")
            with self.assertRaises(ValueError):
                verify_span_results(root)
            path.unlink()
            fill(root)
            path.write_text("124\n")
            with self.assertRaises(ValueError):
                verify_span_results(root)
            path.unlink()
            with self.assertRaises(ValueError):
                verify_span_results(root)

    def test_script_reuses_prior_15_checks_and_real_cpp(self):
        root = Path(__file__).resolve().parents[1] / "research_patches"
        script = (root / "run_splash_span_probe.sh").read_text()
        cpp = (root / "splash_span_method_probe.cc").read_text()
        self.assertEqual(SCRIPT, "/prototypes/run_splash_span_probe.sh")
        self.assertIn("bash /prototypes/run_splash_public_test.sh", script)
        self.assertIn("for variant in original patched extended", script)
        self.assertIn("-fsanitize=address,undefined", script)
        self.assertIn("timeout --signal=TERM --kill-after=2s 6s", script)
        self.assertIn("clip.testSpan(INT_MAX / 4 + 8, INT_MAX / 4 + 8, 1)", cpp)
        self.assertIn("clip.clipToPath(", cpp)
        self.assertIn("clip.getNumPaths() != 1", cpp)
        self.assertIn("SplashClip clip(0, 0, 600000000, 10, true)", cpp)
        self.assertNotIn("docker push", script)
        self.assertNotIn("docker tag", script)
        self.assertNotIn("wrangler deploy", script)

    def test_fake_container_complete_without_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixes, research = root / "fixes", root / "research"
            fixes.mkdir()
            research.mkdir()
            pinned = Path(__file__).resolve().parents[1] / "research_patches"
            (research / "SplashClip-ymax-checked-research-overlay.patch").write_bytes(
                (pinned / "SplashClip-ymax-checked-research-overlay.patch").read_bytes()
            )
            attestation = {
                "base_source_version": "25.03.0-5+deb13u4",
                "baseline_sha256": {"splash/SplashClip.cc": "a" * 64},
                "prototype_source_sha256": {"splash/SplashClip.cc": "b" * 64},
            }
            success_without_evidence = subprocess.CompletedProcess(
                [], 0, stdout=DONE + "\n", stderr="",
            )
            with patch(
                "poppler_splash_span_probe.inspect_semantic_prototypes",
                return_value=attestation,
            ), self.assertRaises(ValueError):
                inspect_span(
                    {}, {}, {}, builder_id="sha256:" + "f" * 64,
                    fix_directory=fixes, prototype_directory=research,
                    runner=lambda *a, **k: success_without_evidence,
                )

    def test_cli_missing_debian_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sys, "argv", [
                "poppler_splash_span_probe.py",
                "--source-directory", tmp,
                "--fix-directory", tmp,
                "--builder-image-id", "sha256:" + "0" * 64,
            ]), patch("builtins.print") as captured:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(captured.call_args.args[0]), {
                    "status": "error",
                    "reason": "splash_span_method_source_evidence_incomplete",
                    "release_authorized": False,
                })


if __name__ == "__main__":
    unittest.main()
