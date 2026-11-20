"""R1.21: fail-closed proof of actual Splash public method residual UB."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_splash_public_test_probe import (
    CONDITIONS, DONE, SCRIPT, UBSAN_OVERFLOW, VARIANTS, inspect_public_test,
    main, verify_public_test_results,
)


def fill_evidence(directory: Path) -> None:
    for variant in VARIANTS:
        for condition in CONDITIONS:
            stem = directory / (variant + "-publictest_" + condition)
            exit_code = 0 if condition == "normal" else 1
            stdout = "normal_public_test_passed\n" if exit_code == 0 else ""
            stderr = "" if exit_code == 0 else (
                f"/work/{variant}/splash/SplashClip.cc:357:11: "
                + UBSAN_OVERFLOW
                + " cannot be represented in type 'int'\n"
            )
            for ext, content in (
                (".exit", f"{exit_code}\n"),
                (".stdout", stdout),
                (".stderr", stderr),
            ):
                Path(str(stem) + ext).write_text(content)


class SplashPublicTestProbeTests(unittest.TestCase):
    def test_normal_and_edge_in_three_real_source_variants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill_evidence(root)
            r = verify_public_test_results(root)
            self.assertEqual(set(r["cases"]), set(CONDITIONS))
            self.assertTrue(r["original_and_five_and_six_prototype_ub_reproduced"])
            self.assertTrue(r["normal_public_method_behavior_retained"])
            self.assertFalse(r["pdf_parser_reproducer_verified"])
            self.assertFalse(r["cve_remediation_claimed"])
            for variant in VARIANTS:
                self.assertEqual(
                    r["cases"]["x_aa_overflow"][variant]["exit_code"], 1
                )

    def test_success_report_must_not_substitute_for_actual_ub(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill_evidence(root)
            (root / "extended-publictest_x_aa_overflow.exit").write_text("0\n")
            with self.assertRaises(ValueError):
                verify_public_test_results(root)
            fill_evidence(root)
            (root / "extended-publictest_x_aa_overflow.stderr").write_text("")
            with self.assertRaises(ValueError):
                verify_public_test_results(root)

    def test_unrelated_crash_or_sanitizer_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill_evidence(root)
            (root / "patched-publictest_x_aa_overflow.stderr").write_text(
                "AddressSanitizer: heap-buffer-overflow\n"
            )
            with self.assertRaises(ValueError):
                verify_public_test_results(root)
            fill_evidence(root)
            (root / "patched-publictest_x_aa_overflow.stderr").write_text(
                "/work/patched/splash/SplashClip.cc:1:1: runtime error: "
                "signed integer overflow: 536870919 * 4\n"
                "AddressSanitizer: heap-buffer-overflow\n"
            )
            with self.assertRaises(ValueError):
                verify_public_test_results(root)

    def test_wrong_source_file_path_and_wrong_overflow_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill_evidence(root)
            (root / "original-publictest_x_aa_overflow.stderr").write_text(
                "/other/file.cc:19:2: " + UBSAN_OVERFLOW + "\n"
            )
            with self.assertRaises(ValueError):
                verify_public_test_results(root)
            fill_evidence(root)
            (root / "extended-publictest_x_aa_overflow.stderr").write_text(
                "/work/extended/splash/SplashClip.cc:357:11: "
                "runtime error: signed integer overflow: 200000000 * 4\n"
            )
            with self.assertRaises(ValueError):
                verify_public_test_results(root)

    def test_symlink_and_truncated_or_timeout_results_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fill_evidence(root)
            path = root / "original-publictest_normal.exit"
            path.unlink()
            path.symlink_to(root / "patched-publictest_normal.exit")
            with self.assertRaises(ValueError):
                verify_public_test_results(root)
            path.unlink()
            fill_evidence(root)
            path.write_text("124\n")
            with self.assertRaises(ValueError):
                verify_public_test_results(root)
            fill_evidence(root)
            (root / "original-publictest_normal.stderr").write_text("!" * 18000)
            with self.assertRaises(ValueError):
                verify_public_test_results(root)

    def test_script_reuses_pinned_r119_preparation_and_no_runtime(self):
        src = Path(__file__).resolve().parents[1] / "research_patches"
        build = (src / "run_splash_public_test.sh").read_text()
        harness = (src / "splash_public_test_probe.cc").read_text()
        self.assertEqual(SCRIPT, "/prototypes/run_splash_public_test.sh")
        self.assertIn("bash /prototypes/run_splash_ymax_overlay.sh", build)
        self.assertIn("-fsanitize=address,undefined", build)
        self.assertIn("for variant in original patched extended", build)
        self.assertIn("splash/SplashClip.cc", build)
        self.assertIn("timeout --signal=TERM --kill-after=2s 6s", build)
        self.assertIn("SplashClip clip(0, 0, 600000000, 10, true)", harness)
        self.assertIn("clip.test(INT_MAX / 4 + 8, 1)", harness)
        self.assertIn("clip.test(3, 3)", harness)
        for forbidden in ("docker push", "docker tag", "wrangler deploy", "vex --approve"):
            self.assertNotIn(forbidden, build)

    def test_false_container_success_without_outputs_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixes, research = root / "fixes", root / "research"
            fixes.mkdir()
            research.mkdir()
            original = Path(__file__).resolve().parents[1] / "research_patches"
            (research / "SplashClip-ymax-checked-research-overlay.patch").write_bytes(
                (original / "SplashClip-ymax-checked-research-overlay.patch").read_bytes()
            )
            attestation = {
                "base_source_version": "25.03.0-5+deb13u4",
                "baseline_sha256": {"splash/SplashClip.cc": "a" * 64},
                "prototype_source_sha256": {"splash/SplashClip.cc": "b" * 64},
            }
            fake = subprocess.CompletedProcess(
                [], 0, stdout=DONE + "\n", stderr="",
            )
            with patch(
                "poppler_splash_public_test_probe.inspect_semantic_prototypes",
                return_value=attestation,
            ), self.assertRaises(ValueError):
                inspect_public_test(
                    {}, {}, {}, builder_id="sha256:" + "c" * 64,
                    fix_directory=fixes, prototype_directory=research,
                    runner=lambda *a, **k: fake,
                )

    def test_fake_marker_or_nonzero_container_exit_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixes, research = root / "fixes", root / "research"
            fixes.mkdir()
            research.mkdir()
            original = Path(__file__).resolve().parents[1] / "research_patches"
            (research / "SplashClip-ymax-checked-research-overlay.patch").write_bytes(
                (original / "SplashClip-ymax-checked-research-overlay.patch").read_bytes()
            )
            attestation = {
                "base_source_version": "25.03.0-5+deb13u4",
                "baseline_sha256": {"splash/SplashClip.cc": "a" * 64},
                "prototype_source_sha256": {"splash/SplashClip.cc": "b" * 64},
            }
            for exit_code, marker in ((0, "other-complete\n"), (3, DONE + "\n")):
                fake = subprocess.CompletedProcess([], exit_code, stdout=marker)
                with self.subTest(exit_code=exit_code), patch(
                    "poppler_splash_public_test_probe.inspect_semantic_prototypes",
                    return_value=attestation,
                ), self.assertRaises(ValueError):
                    inspect_public_test(
                        {}, {}, {}, builder_id="sha256:" + "c" * 64,
                        fix_directory=fixes, prototype_directory=research,
                        runner=lambda *a, **k: fake,
                    )

    def test_cli_rejects_missing_official_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sys, "argv", [
                "poppler_splash_public_test_probe.py",
                "--source-directory", tmp,
                "--fix-directory", tmp,
                "--builder-image-id", "sha256:" + "0" * 64,
            ]), patch("builtins.print") as capture:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(capture.call_args.args[0]), {
                    "status": "error",
                    "reason": "splash_public_method_real_source_evidence_incomplete",
                    "release_authorized": False,
                })


if __name__ == "__main__":
    unittest.main()
