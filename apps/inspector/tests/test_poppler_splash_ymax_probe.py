"""R1.19: strict source-only SplashClip guard overlay and adversarial evidence."""
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
from poppler_splash_ymax_probe import (
    CONDITIONS, DONE_MARKER, OVERLAY_FILENAME, OVERLAY_SHA256, SCRIPT,
    SOURCE_YMAX_SHA256, VARIANTS, inspect_ymax_overlay, main,
    validate_overlay_patch, verify_actual_splash_results,
)


def evidence(root: Path) -> None:
    for condition in CONDITIONS:
        for variant in VARIANTS:
            prefix = root / (variant + "-" + condition)
            if condition == "normal":
                status, stdout, stderr = 0, "normal_path_accepted\n", ""
            elif condition == "ymin_overflow" and variant != "original":
                status, stdout, stderr = 0, "splash_ymin_checked_rejected\n", ""
            elif condition == "ymax_overflow" and variant == "extended":
                status, stdout, stderr = 0, "splash_ymax_checked_rejected\n", ""
            else:
                status, stdout = 1, ""
                stderr = (
                    "/work/" + variant + "/splash/SplashClip.cc:213:34: "
                    "runtime error: signed integer overflow: 536870919 * 4 "
                    "cannot be represented in type 'int'\n"
                )
            prefix.with_suffix(".exit").write_text(str(status) + "\n")
            prefix.with_suffix(".stdout").write_text(stdout)
            prefix.with_suffix(".stderr").write_text(stderr)


class SplashYmaxOverlayTests(unittest.TestCase):
    def test_overlay_pinned_and_isolated_from_original_three_prototypes(self):
        root = Path(__file__).resolve().parents[1]
        patches = root / "research_patches"
        raw = validate_overlay_patch(patches)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), OVERLAY_SHA256)
        self.assertEqual(len(SOURCE_YMAX_SHA256), 64)
        self.assertIn(b"checkedMultiply(yMaxIPlusOne", raw)
        self.assertIn(b"checkedSubtraction(yMaxAAPadded", raw)
        originals = list(patches.glob("*-trixie-prototype.patch"))
        self.assertEqual(len(originals), 3)
        self.assertNotIn(OVERLAY_FILENAME, [p.name for p in originals])

    def test_changed_or_linked_overlay_refused(self):
        root = Path(__file__).resolve().parents[1] / "research_patches"
        actual = (root / OVERLAY_FILENAME).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / OVERLAY_FILENAME
            source.write_bytes(actual + b" ")
            with self.assertRaises(ValueError):
                validate_overlay_patch(Path(tmp))
            source.unlink()
            source.symlink_to(root / OVERLAY_FILENAME)
            with self.assertRaises(ValueError):
                validate_overlay_patch(Path(tmp))
            source.unlink()
            source.write_bytes(b"")
            with self.assertRaises(ValueError):
                validate_overlay_patch(Path(tmp))

    def test_expected_nine_real_method_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            outcome = verify_actual_splash_results(root)
            self.assertEqual(set(outcome["cases"]), set(CONDITIONS))
            self.assertTrue(outcome["sixth_overlay_ymax_rejected_without_ub"])
            self.assertTrue(outcome["original_and_five_prototypes_ymax_overflow_reproduced"])
            self.assertTrue(outcome["existing_ymin_guard_retained"])
            self.assertFalse(outcome["reached_by_pdf_parser"])
            self.assertFalse(outcome["cve_2026_102621_complete_fix_verified"])
            self.assertEqual(
                outcome["cases"]["ymax_overflow"]["extended"]["exit_code"], 0
            )

    def test_fake_overlay_ymax_guard_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            path = root / "extended-ymax_overflow.stdout"
            path.write_text("normal_path_accepted\n")
            with self.assertRaises(ValueError):
                verify_actual_splash_results(root)
            evidence(root)
            (root / "extended-ymax_overflow.stderr").write_text(
                "runtime error: signed integer overflow\n"
            )
            with self.assertRaises(ValueError):
                verify_actual_splash_results(root)

    def test_missing_original_overflow_or_bad_baseline_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            (root / "original-ymax_overflow.stderr").write_text(
                "AddressSanitizer: unrelated heap error\n"
            )
            with self.assertRaises(ValueError):
                verify_actual_splash_results(root)
            evidence(root)
            (root / "patched-ymax_overflow.exit").write_text("0\n")
            with self.assertRaises(ValueError):
                verify_actual_splash_results(root)

    def test_symlinks_timeout_and_oversized_diagnostics_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            p = root / "original-normal.exit"
            p.unlink()
            p.symlink_to(root / "patched-normal.exit")
            with self.assertRaises(ValueError):
                verify_actual_splash_results(root)
            p.unlink()
            evidence(root)
            p.write_text("124\n")
            with self.assertRaises(ValueError):
                verify_actual_splash_results(root)
            evidence(root)
            (root / "patched-normal.stderr").write_text("A" * 17000)
            with self.assertRaises(ValueError):
                verify_actual_splash_results(root)

    def test_shell_can_only_execute_isolated_method_not_runtime(self):
        directory = Path(__file__).resolve().parents[1] / "research_patches"
        shell = (directory / "run_splash_ymax_overlay.sh").read_text()
        self.assertIn("sha256sum --check /fixtures/patched.sha256", shell)
        self.assertIn("sha256sum --check /fixtures/extended.sha256", shell)
        self.assertIn("sha256sum --check /fixtures/overlay.sha256", shell)
        self.assertIn("patch --batch --forward --fuzz=0", shell)
        self.assertIn("for variant in original patched extended", shell)
        self.assertIn("-fsanitize=address,undefined", shell)
        self.assertIn("timeout --signal=TERM --kill-after=2s 6s", shell)
        self.assertNotIn("docker push", shell)
        self.assertNotIn("wrangler deploy", shell)
        self.assertNotIn("cmake --build", shell)
        self.assertEqual(SCRIPT, "/prototypes/run_splash_ymax_overlay.sh")

    def test_fake_container_completion_never_proves_runtime_or_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixed = root / "fixes"
            patches = root / "patches"
            fixed.mkdir()
            patches.mkdir()
            (patches / OVERLAY_FILENAME).write_bytes(
                (Path(__file__).resolve().parents[1]
                 / "research_patches" / OVERLAY_FILENAME).read_bytes()
            )
            attestation = {
                "base_source_version": "25.03.0-5+deb13u4",
                "baseline_sha256": {
                    "splash/SplashClip.cc": "a" * 64,
                },
                "prototype_source_sha256": {
                    "splash/SplashClip.cc": "b" * 64,
                },
            }
            result = subprocess.CompletedProcess(
                [], 0, stdout=DONE_MARKER + "\n", stderr="",
            )
            with patch("poppler_splash_ymax_probe.inspect_semantic_prototypes",
                       return_value=attestation):
                with self.assertRaises(ValueError):
                    inspect_ymax_overlay(
                        {}, {}, {}, builder_id="sha256:" + "a" * 64,
                        fix_directory=fixed, prototype_directory=patches,
                        runner=lambda *args, **kwargs: result,
                    )

    def test_cli_refuses_missing_official_source_and_fixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sys, "argv", [
                "poppler_splash_ymax_probe.py",
                "--source-directory", tmp,
                "--fix-directory", tmp,
                "--builder-image-id", "sha256:" + "0" * 64,
            ]), patch("builtins.print") as capture:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(capture.call_args.args[0]), {
                    "status": "error",
                    "reason": "splash_ymax_guard_research_evidence_incomplete",
                    "release_authorized": False,
                })


if __name__ == "__main__":
    unittest.main()
