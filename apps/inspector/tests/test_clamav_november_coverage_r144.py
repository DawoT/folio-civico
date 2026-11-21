"""R1.44: November 2026 vendor advisories must not vanish from the review ledger.

All fixtures are synthetic. Production evidence uses real Trivy, detached GPG
signature, exact ELF hashes, dpkg verification and the image's immutable ID.
"""
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
from test_clamav_signed_vendor import fixtures  # noqa: E402
from clamav_november_coverage_r144 import (  # noqa: E402
    IMAGE, IMAGE_ID, NOVEMBER_CVES, JULY_CVES, review_clamav_coverage,
)

def evidence():
    scan, sbom, vendor, installed, _ = copy.deepcopy(fixtures())
    scan["ArtifactName"] = IMAGE
    sbom["metadata"]["component"]["name"] = IMAGE
    sbom["metadata"]["component"]["properties"][0]["value"] = IMAGE_ID
    sbom["components"].append({"type": "operating-system", "name": "debian",
                                "version": "13.7"})
    return [scan, sbom, vendor, installed, IMAGE_ID]


class ClamAVNovemberCoverageTests(unittest.TestCase):
    def test_expected_all_vendor_cves_retained_without_release_permission(self):
        result = review_clamav_coverage(*evidence())
        self.assertEqual(len(NOVEMBER_CVES), 10)
        self.assertEqual(len(JULY_CVES), 7)
        self.assertEqual(result["november_vendor_cve_total"], 10)
        self.assertEqual(result["november_not_reported_by_trivy"], sorted(NOVEMBER_CVES))
        self.assertEqual(result["july_still_reported_high"], sorted(JULY_CVES))
        self.assertEqual(result["november_reported_by_trivy"], [])
        self.assertEqual(result["clamav_package_version"], "1.5.5-1")
        self.assertEqual(result["scanner_critical"], 0)
        self.assertEqual(result["scanner_high"], 7)
        self.assertEqual(result["scanner_unknown"], 1)
        self.assertEqual(result["vendor_signed_file_hashes_match"], True)
        self.assertEqual(result["release_authorized"], False)
        self.assertEqual(result["vex_issued"], False)
        self.assertEqual(result["november_cve_binary_patch_proven"], False)
        self.assertEqual(result["vendor_release_claim_fixed_in"], "1.5.5")

    def test_new_november_advisory_reported_by_trivy_stays_visible(self):
        src = evidence()
        src[0]["Results"][0]["Vulnerabilities"].append({
            "PkgName": "clamav", "InstalledVersion": "1.5.5-1",
            "VulnerabilityID": NOVEMBER_CVES[0], "Severity": "HIGH",
        })
        report = review_clamav_coverage(*src)
        self.assertEqual(report["november_reported_by_trivy"], [
            {"id": NOVEMBER_CVES[0], "severity": "HIGH"}
        ])
        self.assertEqual(len(report["november_not_reported_by_trivy"]), 9)
        self.assertEqual(report["scanner_high"], 8)
        self.assertFalse(report["release_authorized"])

    def test_fail_closed_for_tampered_scanner_sbom_vendor_runtime_or_id(self):
        mutations = [
            lambda x: x[0]["Results"].clear(),
            lambda x: x[0].update(ArtifactName="other"),
            lambda x: x[0].update(ArtifactType="filesystem"),
            lambda x: x[0]["Results"][0]["Vulnerabilities"].pop(0),
            lambda x: x[0]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda x: x[0]["Results"][0]["Vulnerabilities"][0].update(InstalledVersion="1.5.4-1"),
            lambda x: x[0]["Results"][0]["Vulnerabilities"].append(
                copy.deepcopy(x[0]["Results"][0]["Vulnerabilities"][0])),
            lambda x: x[1]["metadata"]["component"]["properties"][0].update(value="sha256:"+"b"*64),
            lambda x: x[1]["components"][0].update(version="1.5.4-1"),
            lambda x: x[2].update(signature_verified=False),
            lambda x: x[2].update(signer_fingerprint="0"*40),
            lambda x: x[2].update(signed_deb_sha256="invalid"),
            lambda x: x[2]["files"][0].update(sha256="a"*64),
            lambda x: x[3]["files"][1].update(sha256="0"*64),
            lambda x: x[3].update(dpkg_verify_clean=False),
            lambda x: x[3].update(clamscan_version="ClamAV 1.5.4"),
            lambda x: x[3].update(shared_library_linked=False),
            lambda x: x.__setitem__(4, "sha256:"+"f"*64),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                rows = copy.deepcopy(evidence())
                mutate(rows)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    review_clamav_coverage(*rows)

    def test_cli_valid_evidence_exit_two_invalid_exit_three(self):
        with tempfile.TemporaryDirectory(prefix="r144-clamav-unit-") as root:
            keys = ("scan", "sbom", "vendor", "runtime")
            paths = []
            argv = [sys.executable, "apps/inspector/clamav_november_coverage_r144.py"]
            for key, value in zip(keys, evidence()[:4]):
                p = Path(root) / (key + ".json")
                p.write_text(json.dumps(value), encoding="utf-8")
                argv.extend(("--" + key, str(p)))
                paths.append(p)
            argv.extend(("--image-id", IMAGE_ID))
            ok = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True,
                                timeout=10, check=False)
            self.assertEqual(ok.returncode, 2, ok.stderr)
            self.assertFalse(json.loads(ok.stdout)["release_authorized"])
            paths[2].write_text("{}", encoding="utf-8")
            bad = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True,
                                 timeout=10, check=False)
            self.assertEqual(bad.returncode, 3)
            self.assertEqual(json.loads(bad.stdout)["status"], "error")

    def test_research_runner_has_no_release_escapes(self):
        shell = (ROOT / "apps/inspector/scan_clamav_november_coverage_r144.sh").read_text()
        self.assertIn("sha256:3447fed5e20f4c7f31110403738ffba08ab6b203141cea1b2158f60ef3ed5731", shell)
        self.assertIn("clamav_vendor_evidence.py --vendor", shell)
        self.assertIn("clamav_runtime_inventory.py", shell)
        self.assertIn("trivy image --download-db-only", shell)
        self.assertEqual(shell.count("--skip-db-update"), 2)
        self.assertIn("--pull never --network none --read-only", shell)
        self.assertIn("--user 65534:65534", shell)
        self.assertIn("clamav_november_coverage_r144.py", shell)
        for forbidden in ("docker push", "wrangler deploy", "--ignorefile", "--ignore-unfixed", "release_authorized=true"):
            self.assertNotIn(forbidden, shell)
        proc = subprocess.run(
            ["bash", "apps/inspector/scan_clamav_november_coverage_r144.sh", "--bad"],
            cwd=ROOT, capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(json.loads(proc.stdout)["status"], "error")


if __name__ == "__main__":
    unittest.main()
