"""R1.31: bounded PDF-to-Splash renderer research, not release evidence."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_splash_pdf_width_corpus import (
    EXTREME_WIDTH, EXPECTED_PDF_SHA256, pdf_corpus,
)
from poppler_splash_pdf_width_probe import (
    DONE, OVERFLOW, RUNNER_SHA256, build_args, check_runner,
    inspect_pdf_width, verify_results,
)


def record(root: Path, name: str, code: int, *, stdout: str = "", stderr: str = "") -> None:
    for suffix, payload in ((".exit", str(code) + "\n"),
                            (".stdout", stdout), (".stderr", stderr)):
        (root / (name + suffix)).write_text(payload)


def evidence(root: Path, *, overflow: bool) -> None:
    record(root, "normal_aa", 0)
    record(root, "normal_noaa", 0)
    record(root, "scaled_wide_aa", 0)
    (root / "normal_aa.pbm").write_bytes(b"P4\n8 1\n\x00")
    (root / "normal_noaa.pbm").write_bytes(b"P4\n8 1\n\x00")
    (root / "scaled_wide_aa.pbm").write_bytes(b"P4\n32 1\n\x00" * 4)
    record(root, "wide_noaa", 0)
    record(root, "wide_aa", 0)  # Mono1 explicitly disables vector AA.
    record(root, "wide_gray_aa", 1 if overflow else 0,
           stderr=("/src/poppler-25.03.0/splash/Splash.cc:1454:103: "
                   + OVERFLOW + "\n") if overflow else "")
    record(root, "wide_metadata", 0, stdout=(
        "Pages:           1\n"
        f"Page size:       {EXTREME_WIDTH} x 1 pts\n"
    ))


class SplashPdfWidthProbeTests(unittest.TestCase):
    def test_exact_synthetic_pdf_corpus_is_bounded_and_pinned(self):
        corpus = pdf_corpus()
        self.assertEqual(set(corpus), {"normal", "wide"})
        for name, blob in corpus.items():
            self.assertLess(len(blob), 2048)
            self.assertTrue(blob.startswith(b"%PDF-1.4"))
            self.assertEqual(hashlib.sha256(blob).hexdigest(), EXPECTED_PDF_SHA256[name])
        self.assertIn(f"/MediaBox [0 0 {EXTREME_WIDTH} 1]".encode(),
                      corpus["wide"])

    def test_runner_integrity_rejects_added_commands(self):
        original = Path(__file__).resolve().parents[1] / "research_patches" / "run_splash_pdf_width_probe.sh"
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), RUNNER_SHA256)
        check_runner(original)
        with tempfile.TemporaryDirectory() as tmp:
            runner = Path(tmp) / original.name
            shutil.copy2(original, runner)
            runner.write_bytes(runner.read_bytes() + b"\n: 'synthetic mutation'\n")
            with self.assertRaises(ValueError):
                check_runner(runner)

    def test_docker_arguments_enforce_offline_rootless_and_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dirs = [root / x for x in ("prototypes", "fixtures", "results")]
            for directory in dirs:
                directory.mkdir()
            argv = build_args("sha256:" + "a" * 64, *dirs)
            for value in ("none", "--read-only", "65534:65534", "ALL",
                          "--pull", "never", "--memory", "--tmpfs"):
                self.assertIn(value, argv)
            self.assertTrue(argv[-1].endswith("run_splash_pdf_width_probe.sh"))
            with self.assertRaises(ValueError):
                build_args("unsafe-tag", *dirs)

    def test_real_pdf_ubsan_requires_exact_source_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root, overflow=True)
            report = verify_results(root)
            self.assertTrue(report["pdf_parser_to_splash_constructor_ubsan_observed"])
            self.assertTrue(report["renderer_reachability_verified"])
            self.assertFalse(report["source_binary_equivalence_to_runtime_verified"])
            self.assertFalse(report["release_authorized"])

    def test_without_ubsan_result_is_inconclusive_not_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root, overflow=False)
            report = verify_results(root)
            self.assertFalse(report["renderer_reachability_verified"])
            self.assertFalse(report["pdf_parser_to_splash_constructor_ubsan_observed"])

    def test_generic_sanitizer_or_forged_overflow_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root, overflow=True)
            record(root, "wide_gray_aa", 1, stderr="AddressSanitizer: heap-buffer-overflow\n")
            with self.assertRaises(ValueError):
                verify_results(root)
            evidence(root, overflow=True)
            record(root, "wide_gray_aa", 1, stderr="/tmp/fake.cc:4: " + OVERFLOW + "\n")
            with self.assertRaises(ValueError):
                verify_results(root)

    def test_mono1_vector_aa_cannot_be_passed_off_as_reached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root, overflow=False)
            report = verify_results(root)
            self.assertTrue(report["mono1_vector_antialias_disabled_by_outputdev"])
            record(root, "wide_aa", 1, stderr=(
                "/src/poppler-25.03.0/splash/Splash.cc:1454:103: "
                + OVERFLOW + "\\n"
            ))
            with self.assertRaises(ValueError):
                verify_results(root)

    def test_missing_metadata_output_or_control_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence(root, overflow=True)
            (root / "normal_aa.pbm").unlink()
            with self.assertRaises(ValueError):
                verify_results(root)
            evidence(root, overflow=True)
            record(root, "wide_metadata", 0, stdout="Pages: 1\n")
            with self.assertRaises(ValueError):
                verify_results(root)

    def test_inspect_rejects_runner_error_before_observed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                inspect_pdf_width(
                    builder_id="sha256:" + "0" * 64,
                    prototype_directory=Path(tmp),
                    runner=lambda *a, **kw: subprocess.CompletedProcess([], 0, DONE + "\n", ""),
                )


if __name__ == "__main__":
    unittest.main()
