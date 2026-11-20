"""TDD: remove only headless-unused X11 packages; fail closed on any other delta."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
from headless_prune_comparison import compare_headless, REMOVED_PACKAGES

BASE = "folio-civico-inspector:runtime-pruned-experiment"
NEW = "folio-civico-inspector:headless-pruned-experiment"
REMOVED = ("libcairo2", "libxext6", "libxrender1", "libx11-6", "libx11-data")
BEFORE_ID = "sha256:" + "a" * 64
AFTER_ID = "sha256:" + "b" * 64


def fixtures():
    before = {"ArtifactName": BASE, "ArtifactType": "container_image",
              "Results": [{"Type": "debian", "Target": "debian 13.7",
                           "Vulnerabilities": [
                               {"PkgName": name, "InstalledVersion": "1.0",
                                "VulnerabilityID": "CVE-2026-88806" if name.startswith("libx11")
                                else "CVE-2026-88807", "Severity": "HIGH"}
                               for name in REMOVED if name in
                               ("libx11-6", "libx11-data", "libxrender1")
                           ] + [
                               {"PkgName": "libcairo2", "InstalledVersion": "1.0",
                                "VulnerabilityID": "CVE-2017-7475", "Severity": "LOW"},
                               {"PkgName": "libx11-6", "InstalledVersion": "1.0",
                                "VulnerabilityID": "CVE-2026-94283", "Severity": "MEDIUM"},
                               {"PkgName": "clamav", "InstalledVersion": "1.5.5-1",
                                "VulnerabilityID": "CVE-2026-20213", "Severity": "HIGH"},
                               {"PkgName": "libexpat1", "InstalledVersion": "2.10.0-1+folio1",
                                "VulnerabilityID": "CVE-2026-124317", "Severity": "UNKNOWN"},
                           ]}]}
    after = copy.deepcopy(before)
    after["ArtifactName"] = NEW
    after["Results"][0]["Vulnerabilities"] = [
        record for record in after["Results"][0]["Vulnerabilities"]
        if record["PkgName"] not in REMOVED
    ]
    def sbom(name, identity, packages):
        return {
            "bomFormat": "CycloneDX", "specVersion": "1.7",
            "metadata": {"component": {"name": name, "type": "container",
                         "properties": [{"name": "aquasecurity:trivy:ImageID",
                                         "value": identity}]}},
            "components": [
                {"type": "library", "name": x, "version": "1.0",
                 "purl": f"pkg:deb/debian/{x}@1.0?arch=amd64"}
                for x in [*packages, "clamav", "libexpat1", "ncurses-bin",
                          "libtiff6", "libleptonica6", "qpdf"]
            ] + [{"type": "operating-system", "name": "debian", "version": "13.7"}],
        }
    return (before, after, sbom(BASE, BEFORE_ID, REMOVED),
            sbom(NEW, AFTER_ID, ()), BEFORE_ID, AFTER_ID)


class HeadlessPruneTests(unittest.TestCase):
    def test_diff_accepts_only_exact_x11_five_packages_and_three_high_records(self):
        self.assertEqual(set(REMOVED_PACKAGES), set(REMOVED))
        report = compare_headless(*fixtures())
        self.assertEqual(report["status"], "surface_reduced_release_blocked")
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["removed_high"], 3)
        self.assertEqual(report["removed_medium"], 1)
        self.assertEqual(report["removed_low"], 1)
        self.assertEqual(report["high_before"], 4)
        self.assertEqual(report["high_after"], 1)
        self.assertEqual(report["unknown_after"], 1)
        self.assertEqual(report["removed_packages"], sorted(REMOVED))
        self.assertEqual(report["scanner_gate"], "blocked")

    def test_fails_closed_on_tampering_without_cve_waivers(self):
        changes = [
            lambda p: p[1]["Results"][0]["Vulnerabilities"].clear(),
            lambda p: p[1]["Results"][0]["Vulnerabilities"].append({
                "PkgName": "ncurses-bin", "InstalledVersion": "1.0",
                "VulnerabilityID": "CVE-2025-69720", "Severity": "HIGH"}),
            lambda p: p[3]["components"].pop(),
            lambda p: p[3]["components"].append({
                "type": "library", "name": "libx11-6", "version": "1.0",
                "purl": "pkg:deb/debian/libx11-6@1.0?arch=amd64"}),
            lambda p: p[2]["metadata"]["component"].update(name="incorrect"),
            lambda p: p[3]["metadata"]["component"]["properties"][0].update(value="bad"),
            lambda p: p[3]["components"][-1].update(version="13.8"),
            lambda p: p[1].update(Results=[]),
            lambda p: p[0]["Results"][0]["Vulnerabilities"].append({
                "PkgName": "libx11-6", "InstalledVersion": "1.0",
                "VulnerabilityID": "CVE-2026-OTHER", "Severity": "HIGH"}),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                docs = list(copy.deepcopy(fixtures()))
                change(docs)
                with self.assertRaises((ValueError, TypeError)):
                    compare_headless(*docs)

    def test_cli_returns_error_not_a_release_for_tampered_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            files = {}
            docs = fixtures()
            for name, obj in zip(("before-scan", "after-scan", "before-sbom", "after-sbom"), docs):
                path = Path(directory) / f"{name}.json"
                path.write_text(json.dumps(obj), encoding="utf-8")
                files[name] = path
            cmd = ["python3", "apps/inspector/headless_prune_comparison.py"]
            for name, path in files.items():
                cmd.extend([f"--{name}", str(path)])
            cmd.extend(["--before-id", docs[4], "--after-id", docs[5]])
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 2)
            self.assertFalse(json.loads(p.stdout)["release_authorized"])
            files["after-sbom"].write_text("{}")
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 3)

    def test_builder_protects_essential_packages_and_runs_real_engines(self):
        dockerfile = (ROOT / "apps/inspector/Dockerfile.headless-pruned-experiment").read_text()
        builder = (ROOT / "apps/inspector/build_headless_pruned_experiment.sh").read_text()
        scanner = (ROOT / "apps/inspector/scan_headless_pruned_experiment.sh").read_text()
        self.assertIn("FROM folio-civico-inspector:runtime-pruned-experiment", dockerfile)
        self.assertIn("apt-get -s purge", dockerfile)
        self.assertIn("apt-get purge -y", dockerfile)
        self.assertIn("len(removed)==5", dockerfile)
        for item in REMOVED:
            self.assertIn(item, dockerfile)
        for essential in ("ncurses-bin", "libtiff6", "libleptonica6", "qpdf", "ClamAV 1.5.5"):
            self.assertIn(essential, dockerfile)
        for forbidden in ("--allow-remove-essential", "apt-get autoremove",
                          "dpkg --force", "util-linux", "bsdutils", "libmount1"):
            self.assertNotIn(forbidden, dockerfile)
        for expected in ("set -euo pipefail", "--network none", "--read-only",
                         "--cap-drop ALL", "smoke_real_engines.py", "smoke_http_real.py",
                         "runtime-pruned-experiment", "headless-pruned-experiment"):
            self.assertIn(expected, builder)
        for expected in ("--format json", "--format cyclonedx",
                         "headless_prune_comparison.py", "docker image inspect"):
            self.assertIn(expected, scanner)
        for file in (builder, scanner):
            for forbidden in ("--skip-db-update", "--ignore-unfixed", "--ignorefile",
                              "docker push", "wrangler deploy", "docker system prune"):
                self.assertNotIn(forbidden, file)
        for script in ("build_headless_pruned_experiment.sh",
                       "scan_headless_pruned_experiment.sh"):
            p = subprocess.run(["bash", "apps/inspector/" + script, "--bad"],
                               cwd=ROOT, capture_output=True, text=True, timeout=5)
            self.assertEqual(p.returncode, 3)


if __name__ == "__main__":
    unittest.main()
