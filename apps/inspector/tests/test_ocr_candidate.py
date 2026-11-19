"""Candidate OCR supply-chain and fail-closed validation contracts.

This experiment cannot be promoted to production. A custom compiled OCR
binary is not necessarily present in Trivy's package inventory.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class MinimalOcrCandidateTests(unittest.TestCase):
    def test_source_version_and_digest_are_pinned(self):
        docker = (ROOT / "apps/inspector/Dockerfile.ocr-candidate").read_text()
        self.assertIn("tesseract_5.5.4.orig.tar.gz", docker)
        self.assertIn(
            "a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4",
            docker,
        )
        self.assertIn("sha256sum --check", docker)
        self.assertNotIn("tesseract_5.5.0.orig.tar.gz", docker)

    def test_unsupported_ocr_modules_and_vulnerable_libraries_are_removed(self):
        docker = (ROOT / "apps/inspector/Dockerfile.ocr-candidate").read_text()
        for expected in (
            "-DDISABLE_ARCHIVE=ON", "-DDISABLE_CURL=ON",
            "-DDISABLED_LEGACY_ENGINE=ON", "-DBUILD_TRAINING_TOOLS=OFF",
            "apt-get purge -y tesseract-ocr libtesseract5 libarchive13t64 libxml2",
            "test ! -e /usr/lib/x86_64-linux-gnu/libxml2.so.2",
            "TESSDATA_PREFIX",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, docker)
        self.assertNotIn("apt-get autoremove", docker)

    def test_candidate_validation_is_offline_fail_closed_and_never_pushes(self):
        shell = (ROOT / "apps/inspector/validate_ocr_candidate.sh").read_text()
        for expected in (
            "set -euo pipefail",
            "apps/inspector/preflight.py --mode build",
            "folio-civico-inspector:ocr-candidate",
            "--network none", "--read-only", "--cap-drop ALL",
            "--security-opt no-new-privileges", "--memory 4g",
            "smoke_real_engines.py", "smoke_http_real.py",
            "--format json", "--format cyclonedx",
            "audit_image.py",
            "ocr_not_tracked_in_sbom",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, shell)
        for forbidden in ("docker push", "docker system prune", "--ignore-unfixed",
                          "--skip-db-update", "--ignorefile", "--exit-code 0"):
            self.assertNotIn(forbidden, shell)


if __name__ == "__main__":
    unittest.main()
