import hashlib
import importlib.util
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

INSPECTOR_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(INSPECTOR_DIR))
from fixtures import native_pdf, scanned_pdf, malformed_pdf, _image_bitmap
from preflight import (
    evaluate_requirements, GIB, MIN_BUILD_FREE_BYTES,
    MIN_SMOKE_FREE_BYTES, ENGINE_TOOLS,
)
from smoke_real_engines import (scanner_test_sample, main as smoke_main,
                                exercise_real_engines)
from inspector import ReviewRequired
import preflight


def verify_xref(pdf: bytes) -> None:
    """Check deterministic PDF offsets independently, without a PDF engine."""
    offset = int(pdf.rsplit(b"startxref\n", 1)[1].split(b"\n", 1)[0])
    assert pdf[offset:offset + 5] == b"xref\n"
    table = pdf[offset:].split(b"trailer\n", 1)[0].splitlines()
    count = int(table[1].split()[1])
    assert pdf.count(b" 0 obj\n") == count - 1
    for index in range(1, count):
        location = int(table[index + 2][:10])
        assert pdf[location:].startswith(f"{index} 0 obj\n".encode())


class SyntheticFixtureTests(unittest.TestCase):
    def test_native_pdf_is_minimal_self_contained_and_not_an_uploaded_document(self):
        pdf = native_pdf()
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"EXPEDIENTE OBRA 2026", pdf)
        self.assertIn(b"/Helvetica", pdf)
        self.assertLess(len(pdf), 8192)
        verify_xref(pdf)

    def test_scanned_fixture_contains_only_pixels_and_has_valid_pdf_xref(self):
        pdf = scanned_pdf()
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"/Subtype /Image", pdf)
        self.assertIn(b"/DeviceGray", pdf)
        self.assertNotIn(b"/Helvetica", pdf)
        self.assertNotIn(b" Tj", pdf)
        self.assertNotIn(b"OBRA 2026", pdf)
        self.assertLess(len(pdf), 8192)
        verify_xref(pdf)
        width, height, bitmap = _image_bitmap("OBRA 2026")
        self.assertEqual((width, height), (640, 120))
        self.assertIn(0, bitmap)
        self.assertIn(255, bitmap)

    def test_invalid_glyphs_and_damaged_fixture_are_rejected(self):
        with self.assertRaises(ValueError):
            _image_bitmap("EXTERNAL MESSAGE")
        sample = malformed_pdf()
        self.assertTrue(sample.startswith(b"%PDF-"))
        self.assertNotIn(b"%%EOF", sample)
        self.assertNotEqual(hashlib.sha256(sample).digest(),
                            hashlib.sha256(native_pdf()).digest())

    def test_eicar_test_pattern_is_only_generated_in_memory(self):
        self.assertEqual(len(scanner_test_sample()), 68)
        self.assertTrue(scanner_test_sample().startswith(b"X5O!"))
        self.assertNotIn(b"\n", scanner_test_sample())


class PreflightPolicyTests(unittest.TestCase):
    def test_shared_host_with_less_than_eight_gib_must_block_build(self):
        self.assertIn(
            "insufficient_disk:need_8_GiB_free",
            evaluate_requirements("build", int(4.2 * GIB), {"docker": True})
        )
        self.assertFalse(evaluate_requirements(
            "build", MIN_BUILD_FREE_BYTES, {"docker": True}
        ))

    def test_real_engine_smoke_never_substitutes_mocks_when_tools_are_missing(self):
        available = {name: True for name in ENGINE_TOOLS}
        available["clamscan"] = False
        issues = evaluate_requirements("smoke", MIN_SMOKE_FREE_BYTES, available, True)
        self.assertIn("missing_engine:clamscan", issues)
        available["clamscan"] = True
        self.assertEqual(
            evaluate_requirements("smoke", MIN_SMOKE_FREE_BYTES, available, False),
            ["missing_or_stale_clamav_signatures"]
        )

    def test_host_ram_and_remote_docker_daemon_are_hard_build_gates(self):
        self.assertIn(
            "insufficient_memory:need_4_GiB_available",
            evaluate_requirements(
                "build", MIN_BUILD_FREE_BYTES, {"docker": True},
                available_ram_bytes=2 * GIB
            )
        )
        with patch.dict(os.environ, {"DOCKER_HOST": "ssh://shared-host.example.invalid"}):
            with patch("preflight.subprocess.run") as runtime:
                self.assertIsNone(preflight._docker_root_free())
                runtime.assert_not_called()

    def test_real_smoke_refuses_antivirus_that_does_not_detect_eicar(self):
        def simulated_inspector(pdf, version, expected_hash, *, signatures):
            if version == "synthetic_bad":
                raise ReviewRequired("synthetic malformed PDF")
            return {"pages": [
                {"page": 1, "text": ("EXPEDIENTE OBRA 2026"
                                     if version == "synthetic_native"
                                     else "OBRA 2026")}
            ]}
        with tempfile.TemporaryDirectory() as scratch:
            with patch("smoke_real_engines.inspect_pdf", side_effect=simulated_inspector), \
                 patch("smoke_real_engines.subprocess.run",
                       return_value=subprocess.CompletedProcess(
                           args=["clamscan"], returncode=0)):
                with self.assertRaisesRegex(AssertionError, "did not identify"):
                    exercise_real_engines(Path(scratch))

    def test_smoke_orchestration_returns_aggregate_success_with_stubbed_engines(self):
        """Unit-only verification of orchestration, NOT real AV/OCR."""
        def simulated_inspector(pdf, version, expected_hash, *, signatures):
            if version == "synthetic_bad":
                raise ReviewRequired("synthetic malformed PDF")
            return {"pages": [
                {"page": 1, "text": ("EXPEDIENTE OBRA 2026"
                                     if version == "synthetic_native"
                                     else "OBRA 2026")}
            ]}
        with tempfile.TemporaryDirectory() as scratch:
            with patch("smoke_real_engines.inspect_pdf", side_effect=simulated_inspector), \
                 patch("smoke_real_engines.subprocess.run",
                       return_value=subprocess.CompletedProcess(
                           args=["clamscan"], returncode=1)):
                self.assertEqual(exercise_real_engines(Path(scratch)), {
                    "native": "passed", "ocr": "passed", "malformed": "rejected",
                    "antivirus_test": "detected"
                })

    def test_manual_smoke_returns_nonzero_when_preflight_fails(self):
        from smoke_real_engines import inspect_host
        with patch("smoke_real_engines.inspect_host", return_value={
            "ready": False, "problems": ["missing_engine:clamscan"]
        }), patch.object(sys, "argv", ["smoke_real_engines.py"]), patch("builtins.print") as output:
            self.assertEqual(smoke_main(), 2)
            payload = json.loads(output.call_args.args[0])
            self.assertEqual(payload["ready"], False)


if __name__ == "__main__":
    unittest.main()
