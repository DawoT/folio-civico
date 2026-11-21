"""R1.43 differential scanner guard; a passing test never grants a release."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps" / "inspector"))
sys.path.insert(0, str(ROOT / "apps" / "inspector" / "tests"))
from expat_delta_r143 import SOURCE, TARGET, SOURCE_ID, verify_delta  # noqa: E402
from test_expat_evidence import fixtures as native_fixtures  # noqa: E402

NEW_ID = "sha256:" + "b" * 64
OLD_VERSION = "2.9.0-1~deb13u1"
NEW_VERSION = "2.10.0-1+folio1"


def fixture():
    _scan, _sbom, native, expat = native_fixtures()

    def scan(name, expat_version, expat_cves):
        vulnerabilities = [
            {"PkgName": "clamav", "InstalledVersion": "1.5.5-1",
             "VulnerabilityID": "CVE-2026-20213", "Severity": "HIGH"},
            {"PkgName": "qpdf", "InstalledVersion": "12.2.0-1",
             "VulnerabilityID": "CVE-2025-00001", "Severity": "UNKNOWN"},
        ]
        vulnerabilities.extend({
            "PkgName": "libexpat1", "InstalledVersion": expat_version,
            "VulnerabilityID": cve, "Severity": sev,
        } for cve, sev in expat_cves)
        return {
            "ArtifactName": name, "ArtifactType": "container_image",
            "Results": [{"Target": "debian 13.7", "Type": "debian",
                         "Vulnerabilities": vulnerabilities}],
        }

    def sbom(name, image_id, version):
        return {
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "metadata": {"component": {
                "name": name, "type": "container",
                "properties": [{"name": "aquasecurity:trivy:ImageID",
                                "value": image_id}],
            }},
            "components": [
                {"name": pkg, "type": "library", "version": ver,
                 "purl": f"pkg:deb/debian/{pkg}@{ver.replace('+', '%2B')}?arch=amd64"}
                for pkg, ver in (
                    ("libexpat1", version), ("clamav", "1.5.5-1"),
                    ("qpdf", "12.2.0-1"),
                )
            ] + [{"name": "debian", "type": "operating-system",
                  "version": "13.7"}],
        }

    old_cves = [
        ("CVE-2026-113351", "HIGH"), ("CVE-2026-124317", "UNKNOWN"),
        ("CVE-2026-128241", "UNKNOWN"),
    ]
    new_cves = [
        ("CVE-2026-124317", "UNKNOWN"), ("CVE-2026-128241", "UNKNOWN"),
    ]
    return [
        scan(SOURCE, OLD_VERSION, old_cves),
        scan(TARGET, NEW_VERSION, new_cves),
        sbom(SOURCE, SOURCE_ID, OLD_VERSION),
        sbom(TARGET, NEW_ID, NEW_VERSION),
        copy.deepcopy(native), copy.deepcopy(native), copy.deepcopy(expat),
        SOURCE_ID, NEW_ID,
    ]


class ExpatDeltaTests(unittest.TestCase):
    def test_expected_version_change_never_authorizes_release(self):
        report = verify_delta(*fixture())
        self.assertEqual(report["expat_package_after"], NEW_VERSION)
        self.assertEqual(report["before_blocking"], 5)
        self.assertEqual(report["after_blocking"], 4)
        self.assertEqual(report["expat_advisory_pairs_absent_from_new_scanner"],
                         [("CVE-2026-113351", "HIGH")])
        self.assertEqual(report["expat_advisory_pairs_new_in_scanner"], [])
        self.assertTrue(report["native_poppler_tesseract_hashes_unchanged"])
        self.assertFalse(report["advisory_remediation_claimed"])
        self.assertFalse(report["release_authorized"])

    def test_fail_closed_on_unrelated_drift_or_provenance_loss(self):
        changes = [
            lambda x: x[0].update(ArtifactName="other"),
            lambda x: x[1]["Results"].clear(),
            lambda x: x[2]["metadata"]["component"]["properties"][0].update(value=NEW_ID),
            lambda x: x[3]["components"].pop(),
            lambda x: x[3]["components"][1].update(version="1.5.4-1"),
            lambda x: x[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda x: x[1]["Results"][0]["Vulnerabilities"].append({
                "PkgName": "libpng16-16t64", "InstalledVersion": "1",
                "VulnerabilityID": "CVE-2026-1234", "Severity": "HIGH"}),
            lambda x: x[4]["components"][0].update(library_sha256="f"*64),
            lambda x: x[6].update(native_cve_coverage="assessed"),
            lambda x: x[6].update(patch_sha256="f"*64),
            lambda x: x[6].update(xmlwf_present=True),
            lambda x: x.__setitem__(7, NEW_ID),
            lambda x: x.__setitem__(8, SOURCE_ID),
        ]
        for i, mutate in enumerate(changes):
            with self.subTest(case=i):
                values = copy.deepcopy(fixture())
                mutate(values)
                with self.assertRaises((ValueError, TypeError)):
                    verify_delta(*values)

    def test_new_expat_advisory_does_not_disappear_and_stays_blocked(self):
        values = fixture()
        values[1]["Results"][0]["Vulnerabilities"].append({
            "PkgName": "libexpat1", "InstalledVersion": NEW_VERSION,
            "VulnerabilityID": "CVE-2026-200000", "Severity": "HIGH",
        })
        result = verify_delta(*values)
        self.assertIn(("CVE-2026-200000", "HIGH"),
                      result["expat_advisory_pairs_new_in_scanner"])
        self.assertGreater(result["after_blocking"], 4)
        self.assertFalse(result["release_authorized"])

    def test_offline_scripts_keep_immutable_scope_and_blocking(self):
        build = (ROOT / "apps/inspector/build_expat_experiment.sh").read_text()
        scan = (ROOT / "apps/inspector/scan_expat_delta_r143.sh").read_text()
        quality = (ROOT / "apps/inspector/compare_expat_ocr_r143.sh").read_text()
        dockerfile = (ROOT / "apps/inspector/Dockerfile.expat-experiment").read_text()
        self.assertIn("ARG EXPAT_BASE_IMAGE=scratch", dockerfile)
        self.assertIn("FROM ${EXPAT_BASE_IMAGE}", dockerfile)
        self.assertNotIn("FROM folio-civico-inspector:poppler-experiment", dockerfile)
        self.assertIn("expat-source-${BEFORE#sha256:}", build)
        self.assertIn('--build-arg "EXPAT_BASE_IMAGE=$BASE_PIN"', build)
        self.assertIn("invalid_experimental_base_image_id", build)
        self.assertIn("experiment_image_changed_during_smoke", build)
        self.assertEqual(build.count("docker run --rm --pull never"), 2)
        for source in (build, scan, quality):
            self.assertIn("sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f", source)
            self.assertIn("--network none", source)
            self.assertIn("--pull never", source)
            self.assertIn("--user 65534:65534", source)
            for forbidden in ("docker push", "wrangler deploy", "--ignore-unfixed", "--ignorefile"):
                self.assertNotIn(forbidden, source)
        self.assertIn("--skip-db-update", scan)
        self.assertIn("--download-db-only", scan)
        self.assertIn("expat_cve_regression.py", scan)
        self.assertIn("CVE-2026-118370", scan)
        self.assertIn("expat_delta_r143.py", scan)
        for command in (
            "build_expat_experiment.sh", "scan_expat_delta_r143.sh",
            "compare_expat_ocr_r143.sh",
        ):
            proc = subprocess.run(
                ["bash", f"apps/inspector/{command}", "--invalid"],
                cwd=ROOT, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(proc.returncode, 3)

    def test_cli_valid_delta_exit_two_corrupt_evidence_exit_three(self):
        keys = ("old-scan", "new-scan", "old-sbom", "new-sbom",
                "old-native", "new-native", "expat-native")
        with tempfile.TemporaryDirectory() as folder:
            paths = []
            cmd = ["python3", "apps/inspector/expat_delta_r143.py"]
            for key, value in zip(keys, fixture()[:7]):
                path = Path(folder) / (key + ".json")
                path.write_text(json.dumps(value), encoding="utf-8")
                cmd.extend(("--" + key, str(path)))
                paths.append(path)
            cmd.extend(("--old-id", SOURCE_ID, "--new-id", NEW_ID))
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True,
                               text=True, timeout=10, check=False)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertFalse(json.loads(r.stdout)["release_authorized"])
            paths[5].write_text("{}", encoding="utf-8")
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True,
                               text=True, timeout=10, check=False)
            self.assertEqual(r.returncode, 3)
            self.assertEqual(json.loads(r.stdout)["status"], "error")

if __name__ == "__main__":
    unittest.main()
