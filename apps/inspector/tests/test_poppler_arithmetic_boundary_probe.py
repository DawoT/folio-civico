"""R1.16: numeric analogue provenance and fail-closed boundaries."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import poppler_arithmetic_boundary_probe as probe


class PopplerArithmeticBoundaryTests(unittest.TestCase):
    def test_complete_selected_source_and_residual_inventory(self):
        self.assertEqual(len(probe.EXPECTED_SOURCE_SHA256), 5)
        self.assertEqual(len(probe.FIXED_OPERATIONS), 4)
        self.assertEqual(len(probe.RESIDUAL_OPERATIONS), 2)
        self.assertIn("splash_ymax_residual", probe.RESIDUAL_OPERATIONS)
        self.assertIn("truetype_alignment_residual", probe.RESIDUAL_OPERATIONS)
        self.assertEqual(
            set(probe.SOURCE_MARKERS),
            set(probe.EXPECTED_SOURCE_SHA256) - {"goo/GooCheckedOps.h"},
        )

    def test_source_snapshot_rejects_missing_tampered_or_symlinked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = {"goo/GooCheckedOps.h": b"// checked operators\n"}
            content.update({
                path: "\n".join(markers).encode() + b"\n"
                for path, markers in probe.SOURCE_MARKERS.items()
            })
            hashes = {
                path: hashlib.sha256(data).hexdigest()
                for path, data in content.items()
            }
            for name, data in content.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            with patch.dict(probe.EXPECTED_SOURCE_SHA256, hashes, clear=True):
                self.assertEqual(probe.verify_source_snapshot(root), hashes)
                modified = root / "poppler/Function.cc"
                modified.write_bytes(modified.read_bytes() + b"// tampered")
                with self.assertRaises(ValueError):
                    probe.verify_source_snapshot(root)
                modified.write_bytes(content["poppler/Function.cc"])
                modified.unlink()
                modified.symlink_to(root / "splash/SplashClip.cc")
                with self.assertRaises(ValueError):
                    probe.verify_source_snapshot(root)

    def test_compiler_failure_must_not_claim_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(probe, "verify_source_snapshot",
                              return_value={"pinned": "hash"}):
                result = subprocess.CompletedProcess(
                    [], 1, stdout="", stderr="no compiler",
                )
                with self.assertRaises(ValueError):
                    probe.evaluate_boundary_analogues(
                        Path(tmp), runner=lambda *a, **kw: result,
                    )

    def test_cli_without_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sys, "argv", [
                "poppler_arithmetic_boundary_probe.py",
                "--pinned-source-tree", tmp,
            ]), patch("builtins.print") as printer:
                self.assertEqual(probe.main(), 3)
                self.assertEqual(json.loads(printer.call_args.args[0]), {
                    "status": "error",
                    "reason": "arithmetic_analogue_evidence_incomplete",
                    "release_authorized": False,
                })

    def test_arithmetic_analogues_do_not_execute_poppler_parser(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "research_patches/differential_arithmetic_boundaries.cc"
        ).read_text()
        self.assertIn("checkedMultiply", source)
        self.assertIn("checkedSubtraction", source)
        self.assertIn("checkedAdd", source)
        self.assertIn("truetype_alignment_residual", source)
        self.assertIn("splash_ymax_residual", source)
        self.assertIn("NOT prove a CVE fix", source)


if __name__ == "__main__":
    unittest.main()
