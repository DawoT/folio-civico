"""R1.27: fail-closed proof of actual Debian Poppler Splash constructors."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_splash_aa_constructor_probe import (
    CONSTRUCTORS, DONE, EXPECTED, OVERFLOW, PROBE_FILENAME, PROBE_SHA256,
    SCENARIOS, SCRIPT, SCRIPT_SHA256, SOURCE_SHA256, build_args, check_prototypes,
    inspect_constructor, main, verify_results,
)


def evidence(root: Path) -> None:
    for constructor in CONSTRUCTORS:
        for scenario in SCENARIOS:
            name = root / (constructor + "-" + scenario)
            if scenario == "wide_aa":
                code, stdout = 1, ""
                line = 1454 if constructor == "params" else 1476
                stderr = (
                    f"/src/poppler-25.03.0/splash/Splash.cc:{line}:49: "
                    f"{OVERFLOW}\n"
                )
            else:
                code, stdout, stderr = 0, EXPECTED[scenario], ""
            for ext, content in (
                (".exit", f"{code}\n"),
                (".stdout", stdout),
                (".stderr", stderr),
            ):
                Path(str(name) + ext).write_text(content)


class RealSplashConstructorProbeTests(unittest.TestCase):
    def test_eight_real_method_results_and_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            report = verify_results(root)
            self.assertEqual(set(report["cases"]), set(CONSTRUCTORS))
            self.assertTrue(report["actual_source_constructor_overflow_in_both_overloads"])
            self.assertTrue(report["allocated_wide_bitmap_required_before_constructor"])
            self.assertFalse(report["renderer_reachability_verified"])
            self.assertFalse(report["pdf_parser_reachability_verified"])
            for name in CONSTRUCTORS:
                self.assertEqual(
                    report["cases"][name]["wide_aa"]["exit_code"], 1,
                )

    def test_fake_success_on_wide_aa_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            (root / "screen-wide_aa.exit").write_text("0\n")
            with self.assertRaises(ValueError):
                verify_results(root)
            evidence(root)
            (root / "params-wide_aa.stderr").write_text("")
            with self.assertRaises(ValueError):
                verify_results(root)

    def test_wrong_actual_source_line_and_overflow_operand_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            (root / "screen-wide_aa.stderr").write_text(
                "/other/source.cc:1:1: " + OVERFLOW + "\n"
            )
            with self.assertRaises(ValueError):
                verify_results(root)
            evidence(root)
            (root / "params-wide_aa.stderr").write_text(
                "/src/poppler-25.03.0/splash/Splash.cc:1454:49: "
                "runtime error: signed integer overflow: 400000000 * 4\n"
            )
            with self.assertRaises(ValueError):
                verify_results(root)

    def test_other_sanitizer_or_crash_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            (root / "params-wide_aa.stderr").write_text(
                "AddressSanitizer: heap-buffer-overflow\n"
            )
            with self.assertRaises(ValueError):
                verify_results(root)
            evidence(root)
            (root / "params-wide_aa.exit").write_text("139\n")
            with self.assertRaises(ValueError):
                verify_results(root)

    def test_non_aa_and_small_normal_cases_must_be_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            (root / "screen-wide_noaa.stderr").write_text(
                "runtime error: signed integer overflow\n"
            )
            with self.assertRaises(ValueError):
                verify_results(root)
            evidence(root)
            (root / "params-normal_aa.stdout").write_text("fake\n")
            with self.assertRaises(ValueError):
                verify_results(root)

    def test_missing_symlink_and_timeout_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root)
            path = root / "params-normal_noaa.exit"
            path.unlink()
            path.symlink_to(root / "screen-normal_noaa.exit")
            with self.assertRaises(ValueError):
                verify_results(root)
            path.unlink()
            evidence(root)
            path.write_text("124\n")
            with self.assertRaises(ValueError):
                verify_results(root)
            path.unlink()
            with self.assertRaises(ValueError):
                verify_results(root)

    def test_pinned_original_source_script_uses_full_static_library(self):
        root = Path(__file__).resolve().parents[1] / "research_patches"
        check_prototypes(root)
        script = (root / Path(SCRIPT).name).read_text()
        probe = (root / PROBE_FILENAME).read_text()
        self.assertEqual(SCRIPT, "/prototypes/run_splash_aa_width_constructor.sh")
        self.assertEqual(len(SOURCE_SHA256), 64)
        self.assertEqual(len(PROBE_SHA256), 64)
        self.assertEqual(len(SCRIPT_SHA256), 64)
        self.assertEqual(
            hashlib.sha256((root / Path(SCRIPT).name).read_bytes()).hexdigest(),
            SCRIPT_SHA256,
        )
        self.assertIn("-DBUILD_SHARED_LIBS=OFF", script)
        self.assertIn("libpoppler.a", script)
        self.assertIn("-fsanitize=address,undefined", script)
        self.assertIn("-fno-sanitize=vptr", script)
        self.assertIn("splashAASize", script)
        self.assertIn("SplashBitmap bitmap(width, 1, 1, splashModeMono1, false)", probe)
        self.assertIn("bitmap.getDataPtr() == nullptr", probe)
        self.assertIn("Splash splash(&bitmap, aa", probe)
        self.assertIn("SplashScreen screen(static_cast<const SplashScreenParams *>(nullptr))", probe)
        for forbidden in ("docker push", "docker tag", "wrangler deploy"):
            self.assertNotIn(forbidden, script)

    def test_altered_prototype_or_untrusted_script_rejected(self):
        original = Path(__file__).resolve().parents[1] / "research_patches"
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in (PROBE_FILENAME, Path(SCRIPT).name):
                shutil.copy2(original / name, directory / name)
            check_prototypes(directory)
            code = directory / PROBE_FILENAME
            code.write_bytes(code.read_bytes() + b"// altered\n")
            with self.assertRaises(ValueError):
                check_prototypes(directory)
            shutil.copy2(original / PROBE_FILENAME, code)
            runner = directory / Path(SCRIPT).name
            runner.write_text(runner.read_text().replace(
                "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_SHARED_LIBS=ON",
            ))
            with self.assertRaises(ValueError):
                check_prototypes(directory)

    def test_runner_tampering_preserving_all_markers_must_fail_closed(self):
        # The previous text-only guard accepted an altered executable shell
        # script if its expected markers were left intact. No CI/release
        # evidence may be accepted from that unpinned runner.
        original = Path(__file__).resolve().parents[1] / "research_patches"
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in (PROBE_FILENAME, Path(SCRIPT).name):
                shutil.copy2(original / name, directory / name)
            check_prototypes(directory)
            runner = directory / Path(SCRIPT).name
            runner.write_text(runner.read_text() + "\n: 'synthetic extra shell command'\n")
            with self.assertRaises(ValueError):
                check_prototypes(directory)

    def test_container_mounts_require_image_digest_and_rootless(self):
        original = Path(__file__).resolve().parents[1] / "research_patches"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / "fixtures", root / "results"
            first.mkdir()
            second.mkdir()
            args = build_args("sha256:" + "b" * 64, original, first, second)
            command = " ".join(args)
            for required in (
                "--pull never", "--network none", "--read-only",
                "--user 65534:65534", "--cap-drop ALL",
                "no-new-privileges", "--memory 6g", "--cpus 2",
                "/prototypes,readonly", "/fixtures,readonly",
                "/results", SCRIPT,
            ):
                self.assertIn(required, command)
            self.assertNotIn("docker push", command)
            with self.assertRaises(ValueError):
                build_args("untrusted:latest", original, first, second)
            link = root / "linked"
            link.symlink_to(first, target_is_directory=True)
            with self.assertRaises(ValueError):
                build_args("sha256:" + "b" * 64, original, link, second)

    def test_success_marker_without_real_process_records_fails_closed(self):
        root = Path(__file__).resolve().parents[1] / "research_patches"
        fake = subprocess.CompletedProcess([], 0, stdout=DONE + "\n", stderr="")
        with self.assertRaises(ValueError):
            inspect_constructor(
                builder_id="sha256:" + "b" * 64,
                prototype_directory=root,
                runner=lambda *a, **k: fake,
            )

    def test_nonzero_builder_even_with_marker_fails(self):
        root = Path(__file__).resolve().parents[1] / "research_patches"
        fake = subprocess.CompletedProcess([], 7, stdout=DONE + "\n", stderr="")
        with self.assertRaises(ValueError):
            inspect_constructor(
                builder_id="sha256:" + "b" * 64,
                prototype_directory=root,
                runner=lambda *a, **k: fake,
            )

    def test_cli_invalid_builder_fails_without_docker(self):
        with patch.object(sys, "argv", [
            "poppler_splash_aa_constructor_probe.py",
            "--builder-image-id", "poppler:untrusted",
        ]), patch("builtins.print") as output:
            self.assertEqual(main(), 3)
            self.assertEqual(json.loads(output.call_args.args[0]), {
                "status": "error",
                "reason": "splash_aa_constructor_source_evidence_incomplete",
                "release_authorized": False,
            })


if __name__ == "__main__":
    unittest.main()
