"""R1.40: snapshot real scan bytes of pinned local image, never issue a release."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))

from snapshot_candidate_image import (
    IMAGE, FILES, INCOMPLETE, capture_snapshot, summarize_cve_findings,
    validate_output, verify_snapshot,
)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(
            prefix="folio-r140-test-", dir="/tmp"
        ))
        self.directory.rmdir()
        self.addCleanup(self._cleanup)
        self.image_id = "sha256:" + "e" * 64
        self.calls = []
        self.ids = [self.image_id] * 6
        self.audit = {
            "status": "blocked", "high": 2, "critical": 0, "unknown": 1,
            "source_components_unassessed": 1
        }
        self.advisory = {
            "status": "blocked", "selected_blocking": 2,
            "native_selected_cve_count": 14,
            "source_built_coverage_verified": False,
        }

    def _cleanup(self):
        if self.directory.exists():
            shutil.rmtree(self.directory)

    def _run(self, argv, timeout=180):
        self.calls.append(argv)
        if argv[:3] == ["docker", "context", "inspect"]:
            return "unix:///var/run/docker.sock\n"
        if argv[:3] == ["docker", "image", "inspect"]:
            return self.ids.pop(0) + "\n"
        if argv[0] == "trivy":
            path = Path(argv[argv.index("--output") + 1])
            if argv[argv.index("--format") + 1] == "json":
                payload = {
                    "ArtifactName": IMAGE, "ArtifactType": "container_image",
                    "Results": [{
                        "Target": "debian:13.7", "Type": "debian",
                        "Vulnerabilities": [
                            {"VulnerabilityID": "CVE-2026-78409",
                             "PkgName": "libmount1",
                             "InstalledVersion": "2.41.5-0+deb13u1",
                             "Severity": "HIGH"},
                        ],
                    }],
                }
            else:
                payload = {"bomFormat": "CycloneDX",
                           "metadata": {"component": {"name": IMAGE}},
                           "components": [{"name": "libmount1"}]}
            path.write_text(json.dumps(payload))
            return ""
        if argv[:2] == ["docker", "run"]:
            return json.dumps({
                "source": "folio-local-elf-provenance-v1",
                "mode": "candidate",
                "source_cve_coverage": "unassessed",
                "components": [{"name": "tesseract"}],
            }) + "\n"
        raise AssertionError(f"Unexpected command: {argv[:4]}")

    def _capture(self, **custom):
        with patch("snapshot_candidate_image.os.geteuid", return_value=1000), \
             patch("snapshot_candidate_image._run", side_effect=self._run), \
             patch("snapshot_candidate_image.evaluate_image_audit",
                   return_value=custom.get("audit", self.audit)), \
             patch("snapshot_candidate_image.targeted_advisories",
                   return_value=custom.get("advisory", self.advisory)):
            return capture_snapshot(self.directory)

    def test_real_evidence_bytes_retained_and_gate_remains_blocked(self):
        report = self._capture()
        self.assertEqual(report["immutable_local_image_id"], self.image_id)
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["security_gate"], "blocked")
        self.assertEqual(report["audit_gate"]["high"], 2)
        self.assertEqual(len(report["evidence_sha256"]), 4)
        self.assertFalse((self.directory / INCOMPLETE).exists())
        self.assertEqual(os.stat(self.directory).st_mode & 0o777, 0o700)
        for name in FILES:
            p = self.directory / name
            self.assertTrue(p.is_file())
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            if name != FILES[-1]:
                self.assertEqual(
                    hashlib.sha256(p.read_bytes()).hexdigest(),
                    report["evidence_sha256"][name],
                )
        self.assertEqual(
            report["four_util_linux_cves"]["scanner_findings"][
                "CVE-2026-78409"][0]["installed_version"],
            "2.41.5-0+deb13u1",
        )
        self.assertTrue(any(c[:2] == ["docker", "run"] for c in self.calls))
        runner = next(c for c in self.calls if c[:2] == ["docker", "run"])
        joined = " ".join(runner)
        for needed in ("--network none", "--read-only", "--cap-drop ALL",
                       "--security-opt no-new-privileges", self.image_id,
                       "-I -c"):
            self.assertIn(needed, joined)
        self.assertNotIn("dst=", joined)
        self.assertFalse(any("push" in c or "deploy" in c for c in self.calls))

    def _verify(self):
        with patch("snapshot_candidate_image.evaluate_image_audit",
                   return_value=self.audit), \
             patch("snapshot_candidate_image.targeted_advisories",
                   return_value=self.advisory):
            return verify_snapshot(self.directory)

    def test_independent_verification_recomputes_raw_evidence(self):
        self._capture()
        result = self._verify()
        self.assertEqual(result["image_id"], self.image_id)
        self.assertEqual(result["blocking_count"], 3)
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["security_gate"], "blocked")

    def test_snapshot_raw_sbom_tampering_rejected(self):
        self._capture()
        sbom = self.directory / FILES[1]
        sbom.write_text(sbom.read_text() + "{}")
        with self.assertRaisesRegex(ValueError, "hashes"):
            self._verify()

    def test_release_claim_or_manifest_tampering_rejected(self):
        self._capture()
        target = self.directory / FILES[-1]
        document = json.loads(target.read_text())
        document["release_authorized"] = True
        target.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "release state"):
            self._verify()

    def test_unexpected_snapshot_file_and_permissions_rejected(self):
        self._capture()
        extra = self.directory / "exfiltrated.json"
        extra.write_text("{}")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self._verify()
        extra.unlink()
        target = self.directory / FILES[0]
        target.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "safe immutable"):
            self._verify()

    def test_tag_change_marks_snapshot_unverified_and_no_final_manifest(self):
        self.ids[3] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "tag moved"):
            self._capture()
        self.assertTrue((self.directory / INCOMPLETE).exists())
        self.assertFalse((self.directory / FILES[-1]).exists())

    def test_audit_advisory_disagreement_blocks_final_manifest(self):
        with self.assertRaisesRegex(ValueError, "gates disagree"):
            self._capture(advisory={**self.advisory, "status": "passed"})
        self.assertTrue((self.directory / INCOMPLETE).exists())

    def test_passing_vuln_scan_never_authorizes_release(self):
        report = self._capture(
            audit={**self.audit, "status": "passed", "high": 0,
                   "unknown": 0, "source_components_unassessed": 0},
            advisory={**self.advisory, "status": "passed"},
        )
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["security_gate"], "blocked")
        self.assertEqual(report["audit_gate"]["status"], "passed")

    def test_private_new_tmp_destination_only(self):
        with self.assertRaises(ValueError):
            validate_output(Path("relative/folio-r140-lab123"))
        with self.assertRaises(ValueError):
            validate_output(Path("/etc/folio-r140-invalid"))
        with self.assertRaises(ValueError):
            validate_output(Path("/tmp/external-name"))
        self.directory.mkdir()
        with self.assertRaises(ValueError):
            validate_output(self.directory)

    def test_malformed_cve_findings_are_rejected(self):
        with self.assertRaises(ValueError):
            summarize_cve_findings({
                "Results": [{
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2026-76642",
                         "PkgName": "util-linux", "Severity": 10},
                    ],
                }],
            })

    def test_empty_cve_findings_are_not_a_vex(self):
        result = summarize_cve_findings({"Results": []})
        self.assertFalse(result["cve_remediated"])
        self.assertTrue(result["scanner_absence_does_not_mean_not_affected"])
        self.assertEqual(len(result["scanner_findings"]), 4)
        self.assertEqual(result["vex"], "not_issued")

    def test_host_root_is_forbidden(self):
        with patch("snapshot_candidate_image.os.geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "Host-root"):
                capture_snapshot(self.directory)
        self.assertFalse(self.directory.exists())


if __name__ == "__main__":
    unittest.main()
