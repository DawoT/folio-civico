"""R1.26: real tiny SplashBitmap + SplashClip::clipAALine evidence checks."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_splash_clipa_line_probe import (
    CONDITIONS, DONE, EXPECTED_NORMAL, HELPER_LIBRARY_SHA256,
    HELPER_LIBRARY_BYTES, OVERFLOW_OPERANDS, SCRIPT, VARIANTS,
    inspect_clipa_line, main, validate_helper_library,
    verify_clipaaline_results,
)


def make_evidence(root: Path) -> None:
    for variant in VARIANTS:
        for case in CONDITIONS:
            stem = root / f"{variant}-clippaaline_{case}"
            if case in EXPECTED_NORMAL:
                code, stdout, stderr = 0, EXPECTED_NORMAL[case], ""
            else:
                code, stdout = 1, ""
                stderr = (
                    f"/work/{variant}/splash/SplashClip.cc:284:9: "
                    "runtime error: signed integer overflow: "
                    f"{OVERFLOW_OPERANDS[case]} * 4 cannot be represented "
                    "in type 'int'\n"
                )
            for ext, value in (
                (".exit", f"{code}\n"),
                (".stdout", stdout),
                (".stderr", stderr),
            ):
                Path(str(stem) + ext).write_text(value)


class SplashClipAALineTests(unittest.TestCase):
    def test_twelve_cases_require_actual_real_bitmap_and_ubsan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_evidence(root)
            result = verify_clipaaline_results(root)
            self.assertEqual(set(result["cases"]), set(CONDITIONS))
            self.assertEqual(result["real_bitmap_dimensions"], [64, 4])
            self.assertTrue(result["normal_bitmap_bound_inputs_succeeded"])
            self.assertTrue(
                result["outside_bitmap_x0_and_x1_ub_reproduced_in_all_variants"]
            )
            self.assertTrue(
                result["out_of_bounds_arguments_are_not_validated_renderer_inputs"]
            )
            self.assertFalse(result["renderer_reachability_verified"])
            self.assertFalse(result["pdf_parser_reachability_verified"])
            self.assertFalse(result["cve_remediation_claimed"])

    def test_fake_safe_overflow_result_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_evidence(root)
            (root / "extended-clippaaline_invalid_x0.exit").write_text("0\n")
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)
            make_evidence(root)
            (root / "patched-clippaaline_invalid_x1.stderr").write_text("")
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)

    def test_wrong_site_or_wrong_multiplier_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_evidence(root)
            (root / "original-clippaaline_invalid_x0.stderr").write_text(
                "/irrelevant/source.cc:1:1: runtime error: signed "
                "integer overflow: 536870919 * 4 cannot be represented "
                "in type 'int'\n"
            )
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)
            make_evidence(root)
            (root / "extended-clippaaline_invalid_x1.stderr").write_text(
                "/work/extended/splash/SplashClip.cc:308:9: runtime error: "
                "signed integer overflow: 536870919 * 4 cannot be "
                "represented in type 'int'\n"
            )
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)

    def test_other_sanitizer_or_crash_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_evidence(root)
            (root / "original-clippaaline_invalid_x1.stderr").write_text(
                "AddressSanitizer: heap-buffer-overflow\n"
            )
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)
            make_evidence(root)
            (root / "original-clippaaline_invalid_x1.exit").write_text("139\n")
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)

    def test_valid_bounded_bitmap_cases_must_remain_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_evidence(root)
            (root / "patched-clippaaline_normal_in_bounds.stderr").write_text(
                "UBSan: unexpected warning\n"
            )
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)
            make_evidence(root)
            (root / "patched-clippaaline_normal_origin.stdout").write_text(
                "unverified normal\n"
            )
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)

    def test_symlink_missing_and_timeout_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_evidence(root)
            p = root / "original-clippaaline_normal_origin.exit"
            p.unlink()
            p.symlink_to(root / "patched-clippaaline_normal_origin.exit")
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)
            p.unlink()
            make_evidence(root)
            p.write_text("124\n")
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)
            p.unlink()
            with self.assertRaises(ValueError):
                verify_clipaaline_results(root)

    def test_reject_missing_and_symlinked_or_nonpinned_helper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            invalid = root / "wrong.so"
            invalid.write_bytes(b"not a trusted Poppler ELF")
            self.assertEqual(len(HELPER_LIBRARY_SHA256), 64)
            self.assertGreater(HELPER_LIBRARY_BYTES, 32 * 1024 * 1024)
            with self.assertRaises(ValueError):
                validate_helper_library(invalid)
            target = root / "helper-link.so"
            target.symlink_to(invalid)
            with self.assertRaises(ValueError):
                validate_helper_library(target)
            with self.assertRaises(ValueError):
                validate_helper_library(root / "missing.so")

    def test_source_only_runner_never_uses_runtime_image(self):
        patches = Path(__file__).resolve().parents[1] / "research_patches"
        shell = (patches / "run_splash_clipa_line_probe.sh").read_text()
        cpp = (patches / "splash_clipa_line_method_probe.cc").read_text()
        self.assertEqual(SCRIPT, "/prototypes/run_splash_clipa_line_probe.sh")
        self.assertIn("bash /prototypes/run_splash_span_probe.sh", shell)
        self.assertIn("sha256sum --check /fixtures/helper-lib.sha256", shell)
        self.assertIn("for variant in original patched extended", shell)
        self.assertIn("-fsanitize=address,undefined", shell)
        self.assertIn("-L/libhelper", shell)
        self.assertIn("-l:libpoppler.so.147", shell)
        self.assertIn("test -f /libhelper/libpoppler.so.147", shell)
        self.assertIn("splash/SplashClip.cc", shell)
        self.assertIn("timeout --signal=TERM --kill-after=2s 6s", shell)
        self.assertIn("SplashBitmap aaBuf(64, 4, 1, splashModeMono1, false)", cpp)
        self.assertIn("clip.clipAALine(&aaBuf, &x0, &x1, 1)", cpp)
        self.assertIn("x1 = INT_MAX / 4 + 8", cpp)
        for forbidden in ("docker push", "docker tag", "wrangler deploy"):
            self.assertNotIn(forbidden, shell)

    def test_pinned_helper_soname_and_bind_mount_agree(self):
        from poppler_splash_clipa_line_probe import inspect_clipa_line
        script = (Path(__file__).resolve().parents[1]
                  / "research_patches" / "run_splash_clipa_line_probe.sh").read_text()
        module = Path(sys.modules[inspect_clipa_line.__module__].__file__).read_text()
        self.assertIn('"libpoppler.so.147": HELPER_LIBRARY_SHA256', module)
        self.assertIn("target=/libhelper/libpoppler.so.147,readonly", module)
        self.assertIn("-l:libpoppler.so.147", script)
        self.assertNotIn("-lpoppler -o", script)

    def test_fake_builder_success_without_outputs_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixes, research = root / "fixes", root / "research"
            fixes.mkdir()
            research.mkdir()
            helper = root / "fake-helper.so"
            helper.write_bytes(b"not a real helper")
            previous = (Path(__file__).resolve().parents[1]
                        / "research_patches"
                        / "SplashClip-ymax-checked-research-overlay.patch")
            (research / previous.name).write_bytes(previous.read_bytes())
            attestation = {
                "base_source_version": "25.03.0-5+deb13u4",
                "baseline_sha256": {"splash/SplashClip.cc": "a" * 64},
                "prototype_source_sha256": {"splash/SplashClip.cc": "b" * 64},
            }
            fake = subprocess.CompletedProcess(
                [], 0, stdout=DONE + "\n", stderr="",
            )
            with patch(
                "poppler_splash_clipa_line_probe.inspect_semantic_prototypes",
                return_value=attestation,
            ), patch(
                "poppler_splash_clipa_line_probe.validate_helper_library",
                return_value=helper,
            ), self.assertRaises(ValueError):
                inspect_clipa_line(
                    {}, {}, {}, builder_id="sha256:" + "a" * 64,
                    fix_directory=fixes, prototype_directory=research,
                    helper_library_path=helper,
                    runner=lambda *a, **k: fake,
                )

    def test_cli_missing_sources_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sys, "argv", [
                "poppler_splash_clipa_line_probe.py",
                "--source-directory", tmp,
                "--fix-directory", tmp,
                "--builder-image-id", "sha256:" + "0" * 64,
                "--helper-library-path", str(Path(tmp) / "missing.so"),
            ]), patch("builtins.print") as captured:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(captured.call_args.args[0]), {
                    "status": "error",
                    "reason": "clipaaline_real_bitmap_source_evidence_incomplete",
                    "release_authorized": False,
                })


if __name__ == "__main__":
    unittest.main()
