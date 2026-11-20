"""R1.41 strict scanner-visible differential, never a release override."""
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
from kerberos_poppler_comparison import (  # noqa: E402
    BASE, EXPERIMENT, REMOVED_PACKAGES, KERBEROS_PACKAGES,
    compare_poppler_cve_surface,
)

BASE_ID = "sha256:" + "a" * 64
EXP_ID = "sha256:" + "b" * 64


def evidence():
    def record(name: str, number: int, severity="HIGH"):
        return {
            "PkgName": name, "InstalledVersion": "1.0",
            "VulnerabilityID": f"CVE-2026-{number}",
            "Severity": severity,
        }
    removed = []
    for index, name in enumerate(sorted(KERBEROS_PACKAGES)):
        removed.extend(record(name, 11000 + index * 100 + n) for n in range(14))
    removed.extend(record("libcurl3t64-gnutls", 17000 + n) for n in range(2))
    residual = [record("clamav", 21000), record("libexpat1", 21001, "UNKNOWN")]
    before = {
        "ArtifactName": BASE, "ArtifactType": "container_image",
        "Results": [{"Type": "debian", "Target": "debian 13.7",
                     "Vulnerabilities": removed + residual}],
    }
    after = copy.deepcopy(before)
    after["ArtifactName"] = EXPERIMENT
    after["Results"][0]["Vulnerabilities"] = copy.deepcopy(residual)

    def sbom(name, digest, packages):
        return {
            "bomFormat": "CycloneDX",
            "metadata": {"component": {"name": name, "type": "container",
                           "properties": [{
                               "name": "aquasecurity:trivy:ImageID",
                               "value": digest,
                           }]}},
            "components": [
                {"type": "library", "name": package, "version": "1.0",
                 "purl": f"pkg:deb/debian/{package}@1.0?arch=amd64"}
                for package in sorted(packages)
            ] + [{"type": "operating-system", "name": "debian",
                  "version": "13.7"}],
        }
    retained = {"clamav", "libexpat1"}
    return [
        before, after,
        sbom(BASE, BASE_ID, REMOVED_PACKAGES | retained),
        sbom(EXPERIMENT, EXP_ID, retained),
        BASE_ID, EXP_ID,
    ]


class KerberosPopplerDiffTests(unittest.TestCase):
    def test_exact_seven_packages_and_58_highs_but_release_stays_blocked(self):
        report = compare_poppler_cve_surface(*evidence())
        self.assertEqual(len(report["removed_debian_packages"]), 7)
        self.assertEqual(report["removed_high_total"], 58)
        self.assertEqual(report["removed_high_kerberos"], 56)
        self.assertEqual(report["candidate_blocking"], 60)
        self.assertEqual(report["experiment_blocking"], 2)
        self.assertEqual(report["experiment_unknown"], 1)
        self.assertEqual(report["new_scanner_findings"], 0)
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["cve_remediation_claimed"])
        self.assertFalse(report["poppler_native_cve_coverage_verified"])

    def test_fails_closed_on_unexpected_trivy_or_sbom_differences(self):
        def new_finding(xs):
            xs[1]["Results"][0]["Vulnerabilities"].append({
                "PkgName": "clamav", "InstalledVersion": "1.0",
                "VulnerabilityID": "CVE-2026-30399", "Severity": "HIGH",
            })

        mutations = [
            new_finding,
            lambda xs: xs[1]["Results"][0]["Vulnerabilities"].clear(),
            lambda xs: xs[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda xs: xs[1].update(ArtifactName="other"),
            lambda xs: xs[1]["Results"].clear(),
            lambda xs: xs[3]["components"].insert(0, {
                "type": "library", "name": "libkrb5-3",
                "version": "1.0", "purl": "pkg:deb/debian/libkrb5-3@1.0?arch=amd64",
            }),
            lambda xs: xs[3]["components"].pop(0),
            lambda xs: xs[3]["metadata"]["component"]["properties"][0].update(value=BASE_ID),
            lambda xs: xs[2]["metadata"]["component"].update(name="other"),
            lambda xs: xs.__setitem__(5, BASE_ID),
        ]
        for i, mutate in enumerate(mutations):
            with self.subTest(index=i):
                sources = copy.deepcopy(evidence())
                mutate(sources)
                with self.assertRaises((ValueError, TypeError)):
                    compare_poppler_cve_surface(*sources)

    def test_reduced_scan_without_residual_findings_is_not_release_evidence(self):
        rows = evidence()
        rows[1]["Results"][0]["Vulnerabilities"] = []
        rows[0]["Results"][0]["Vulnerabilities"] = [
            x for x in rows[0]["Results"][0]["Vulnerabilities"]
            if x["PkgName"] in REMOVED_PACKAGES
        ]
        with self.assertRaises(ValueError):
            compare_poppler_cve_surface(*rows)

    def test_cli_keeps_exit_two_on_valid_reduction_and_three_on_corruption(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            inputs = evidence()
            paths = [root / f"{i}.json" for i in range(4)]
            for path, data in zip(paths, inputs):
                path.write_text(json.dumps(data), encoding="utf-8")
            argv = ["python3", "apps/inspector/kerberos_poppler_comparison.py"]
            for key, path in zip(
                ("base-scan", "experiment-scan", "base-sbom", "experiment-sbom"),
                paths,
            ):
                argv.extend(("--" + key, str(path)))
            argv.extend(("--base-id", BASE_ID, "--experiment-id", EXP_ID))
            success = subprocess.run(argv, cwd=ROOT, capture_output=True,
                                     text=True, timeout=10, check=False)
            self.assertEqual(success.returncode, 2)
            self.assertFalse(json.loads(success.stdout)["release_authorized"])
            paths[3].write_text("{}", encoding="utf-8")
            failure = subprocess.run(argv, cwd=ROOT, capture_output=True,
                                     text=True, timeout=10, check=False)
            self.assertEqual(failure.returncode, 3)
            self.assertEqual(json.loads(failure.stdout)["status"], "error")


if __name__ == "__main__":
    unittest.main()
