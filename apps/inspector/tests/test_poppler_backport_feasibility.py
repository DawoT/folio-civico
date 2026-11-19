"""Offline security tests: patch feasibility never clears CVE or release gates."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_source_patch_probe import CVE_SOURCE_PATHS
from poppler_backport_feasibility import (
    FIX_PATCH_SHA256, FIX_UNASSESSED, _validate_patches,
    inspect_backport_feasibility, main,
)
from test_poppler_source_patch_probe import fake_package, fake_dpkg_source


def fake_fixes():
    patches = {}
    for cve in FIX_PATCH_SHA256:
        target = CVE_SOURCE_PATHS[cve]
        patches[cve] = (
            f"From: synthetic research fixture\n"
            f"diff --git a/{target} b/{target}\n"
            f"--- a/{target}\n"
            f"+++ b/{target}\n"
            "@@ -1 +1 @@\n-old\n+new\n"
        ).encode("utf-8")
    hashes = {name: hashlib.sha256(data).hexdigest()
              for name, data in patches.items()}
    return patches, hashes


class PopplerBackportFeasibilityTests(unittest.TestCase):
    def _inspect(self, patch_runner, *, patches=None, hashes=None):
        sources, source_hashes = fake_package()
        if patches is None:
            patches, hashes = fake_fixes()
        return inspect_backport_feasibility(
            sources, patches, expected_source_hashes=source_hashes,
            expected_patch_hashes=hashes, extract_runner=fake_dpkg_source,
            patch_runner=patch_runner,
        )

    def test_compatible_and_failed_hunks_are_only_research_results(self):
        seen = []
        def runner(args, **kwargs):
            self.assertIn("--dry-run", args)
            self.assertIn("--fuzz=0", args)
            self.assertIn("--forward", args)
            seen.append(args)
            cve = Path(args[-1]).stem
            return subprocess.CompletedProcess(
                args, 0 if cve in ("CVE-2026-102620", "CVE-2026-93311") else 1,
                stdout=(f"checking file {CVE_SOURCE_PATHS[cve]}\n" + ("" if cve in ("CVE-2026-102620", "CVE-2026-93311") else "Hunk #1 FAILED at 20.\n")), stderr="",
            )
        report = self._inspect(runner)
        self.assertEqual(len(seen), 7)
        self.assertEqual(report["patches_checked"], 7)
        self.assertEqual(report["textually_applicable_count"], 2)
        self.assertEqual(report["requires_manual_review_count"], 5)
        self.assertEqual(set(FIX_UNASSESSED), {
            "CVE-2026-93653", "CVE-2019-9545", "CVE-2019-9543",
        })
        self.assertEqual(len(report["selected_without_fix_patch"]), 3)
        self.assertTrue(all(not value["fix_verified"]
                            for value in report["patches"].values()))
        for flag in ("binary_equivalence_verified", "selected_cve_fixes_verified",
                     "backport_approved", "complete_source_advisory_coverage",
                     "release_authorized"):
            self.assertFalse(report[flag])

    def test_patch_digests_missing_entries_and_path_traversal_fail_closed(self):
        patches, hashes = fake_fixes()
        self.assertEqual(len(_validate_patches(patches, hashes)), 7)
        broken = dict(patches)
        name = sorted(broken)[0]
        broken[name] = broken[name] + b"!"
        with self.assertRaises(ValueError):
            _validate_patches(broken, hashes)
        broken = dict(patches)
        broken.pop(name)
        with self.assertRaises(ValueError):
            _validate_patches(broken, hashes)
        broken = dict(patches)
        broken[name] = broken[name].replace(
            CVE_SOURCE_PATHS[name].encode(), b"../../etc/passwd"
        )
        new_hashes = dict(hashes)
        new_hashes[name] = hashlib.sha256(broken[name]).hexdigest()
        with self.assertRaises(ValueError):
            _validate_patches(broken, new_hashes)
        broken = dict(patches)
        broken[name] = b"\xff"
        new_hashes[name] = hashlib.sha256(broken[name]).hexdigest()
        with self.assertRaises(UnicodeError):
            _validate_patches(broken, new_hashes)

    def test_debian_backport_without_optional_git_diff_header(self):
        patches, hashes = fake_fixes()
        cve = "CVE-2026-102620"
        target = CVE_SOURCE_PATHS[cve]
        patches[cve] = patches[cve].replace(
            f"diff --git a/{target} b/{target}\n".encode(), b""
        )
        hashes[cve] = hashlib.sha256(patches[cve]).hexdigest()
        self.assertEqual(_validate_patches(patches, hashes)[cve], hashes[cve])

    def test_ambiguous_success_and_tool_failure_are_not_accepted(self):
        args = ["patch"]
        with self.assertRaises(ValueError):
            self._inspect(lambda *a, **k: subprocess.CompletedProcess(
                args, 0, stdout="Hunk FAILED", stderr=""
            ))
        with self.assertRaises(ValueError):
            self._inspect(lambda *a, **k: subprocess.CompletedProcess(
                args, 2, stdout="fatal error", stderr=""
            ))
        with self.assertRaises(ValueError):
            self._inspect(lambda *a, **k: (_ for _ in ()).throw(
                subprocess.TimeoutExpired("patch", 30)
            ))

    def test_any_source_mutation_invalidates_claim(self):
        def mutating_runner(args, **kwargs):
            source = Path(kwargs["cwd"])
            target = source / CVE_SOURCE_PATHS["CVE-2026-93311"]
            target.write_bytes(target.read_bytes() + b"\nnew-data")
            return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")
        with self.assertRaises(ValueError):
            self._inspect(mutating_runner)

    def test_cli_missing_inputs_exit_3_with_no_release_statement(self):
        with tempfile.TemporaryDirectory() as empty:
            with (patch.object(sys, "argv", [
                "poppler_backport_feasibility.py",
                "--source-directory", empty, "--fix-directory", empty,
            ]), patch("builtins.print") as printer):
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(printer.call_args.args[0]), {
                    "reason": "poppler_backport_evidence_incomplete",
                    "status": "error",
                })


if __name__ == "__main__":
    unittest.main()
