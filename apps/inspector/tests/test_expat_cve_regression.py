"""TDD R1.25: bounded Expat CVE probes never override the release gate."""
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
from expat_cve_regression import verify_probe_evidence, EXPECTED_CVES, PROBE_STATES

IMAGE = "folio-civico-inspector:nonprivileged-experiment"
ID = "sha256:" + "a" * 64
VERSION = "2.10.0-1+folio1"


def fixture():
    scan = {"ArtifactName": IMAGE, "ArtifactType": "container_image",
            "Results": [
                {"Type": "debian", "Target": "debian 13.7",
                 "Vulnerabilities": [
                     {"Severity": severity, "PkgName": "libexpat1",
                      "InstalledVersion": VERSION, "VulnerabilityID": cve}
                     for cve, severity in EXPECTED_CVES.items()
                 ] + [
                     {"Severity": "MEDIUM", "PkgName": "libexpat1",
                      "InstalledVersion": VERSION, "VulnerabilityID": "CVE-2025-66382"},
                     {"Severity": "HIGH", "PkgName": "clamav",
                     "InstalledVersion": "1.5.5-1", "VulnerabilityID": "CVE-2026-20213",
                 }]}
            ]}
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.7",
            "metadata": {"component": {"type": "container", "name": IMAGE,
                         "properties": [{"name": "aquasecurity:trivy:ImageID",
                                         "value": ID}]}},
            "components": [
                {"type": "library", "name": "libexpat1", "version": VERSION,
                 "purl": "pkg:deb/debian/libexpat1@2.10.0-1%2Bfolio1?arch=amd64"},
                {"type": "library", "name": "clamav", "version": "1.5.5-1",
                 "purl": "pkg:deb/debian/clamav@1.5.5-1?arch=amd64"},
            ]}
    native = {
        "source": "folio-expat-local-provenance-v1", "package": "libexpat1",
        "package_version": VERSION, "runtime_version": "expat_2.10.0",
        "library_sha256": "b" * 64, "provenance_sha256": "c" * 64,
        "source_sha256": "b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f",
        "patch_sha256": "0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3",
        "linked_poppler_tools": ["pdfinfo","pdftotext","pdftoppm","pdfdetach","pdfattach"],
        "xmlwf_present": False, "native_cve_coverage": "unassessed",
    }
    probes = {
        "status": "bounded_probes_passed_not_release",
        "engine_version": "expat_2.10.0",
        "package_version": VERSION,
        "libexpat_sha256": "b"*64,
        "cve_probes": dict(PROBE_STATES),
        "max_input_bytes": 100_000,
        "max_milliseconds": 15_000,
        "release_authorized": False,
        "vex": "not_issued",
    }
    return (scan, sbom, native, probes, ID)


class ExpatRegressionTDD(unittest.TestCase):
    def test_fixes_reported_but_all_six_cves_still_block(self):
        d = verify_probe_evidence(*fixture())
        self.assertFalse(d["release_authorized"])
        self.assertEqual(d["scanner_gate"], "blocked")
        self.assertEqual(d["expat_high_still_reported"], 4)
        self.assertEqual(d["expat_unknown_still_reported"], 2)
        self.assertEqual(d["expat_medium_still_reported"], 1)
        self.assertEqual(d["bounded_runtime_probes_passed"], 3)
        self.assertEqual(d["unexercised_large_attribute_overflow"], True)
        self.assertEqual(d["native_cve_coverage"], "unassessed")

    def test_missing_cv_es_bad_probes_mismatched_binary_or_incomplete_sbom_rejected(self):
        changes = [
            lambda d: d[0]["Results"][0]["Vulnerabilities"].pop(0),
            lambda d: d[0]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda d: d[0]["Results"].clear(),
            lambda d: d[0].update(ArtifactName="wrong"),
            lambda d: d[1]["metadata"]["component"]["properties"][0].update(value="bad"),
            lambda d: d[1]["components"].pop(0),
            lambda d: d[1]["components"][0].update(version="2.9.0"),
            lambda d: d[2].update(library_sha256="0"*64),
            lambda d: d[2].update(native_cve_coverage="not_affected"),
            lambda d: d[3]["cve_probes"].update({"CVE-2026-118370":"passed"}),
            lambda d: d[3]["cve_probes"].update({"CVE-2026-115506":"amplification_permitted"}),
            lambda d: d[3].update(release_authorized=True),
            lambda d: d[3].update(max_input_bytes=5_000_000_000),
            lambda d: d[3].update(libexpat_sha256="0"*64),
            lambda d: d[3].update(engine_version="expat_2.9.0"),
            lambda d: d[4] + "wrong",
        ]
        for index, change in enumerate(changes[:-1]):
            with self.subTest(index=index):
                d=list(copy.deepcopy(fixture()))
                change(d)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    verify_probe_evidence(*d)

    def test_cli_exits_blocked_for_valid_evidence_and_fail_closed_if_modified(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            names=("scan","sbom","native","probes")
            f=fixture()
            cmd=["python3","apps/inspector/expat_cve_regression.py","--verify"]
            for name,data in zip(names,f[:4]):
                path=root/(name+".json")
                path.write_text(json.dumps(data),encoding="utf-8")
                cmd.extend(["--"+name,str(path)])
            cmd.extend(["--image-id",ID])
            good=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(good.returncode,2)
            self.assertFalse(json.loads(good.stdout)["release_authorized"])
            (root/"probes.json").write_text("{}")
            bad=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(bad.returncode,3)

    def test_probe_is_bounded_and_no_runtime_cve_waiver_is_created(self):
        source=(ROOT/"apps/inspector/expat_cve_regression.py").read_text()
        scan=(ROOT/"apps/inspector/scan_expat_cve_regression.sh").read_text()
        for token in ("XML_ParserReset","XML_ExternalEntityParserCreate",
                      "XML_SetBillionLaughsAttackProtectionActivationThreshold",
                      "XML_SetBillionLaughsAttackProtectionMaximumAmplification",
                      "XML_ERROR_AMPLIFICATION_LIMIT_BREACH", "release_authorized"):
            self.assertIn(token, source)
        for token in ("--network none","--read-only","--cap-drop ALL",
                      "--memory 4g","--cpus 1","timeout 60s",
                      "--format json","--format cyclonedx",
                      "expat_runtime_inventory.py","expat_cve_regression.py",
                      "docker image inspect"):
            self.assertIn(token,scan)
        for token in ("--ignore-unfixed","--ignorefile","--skip-db-update",
                      "docker push","wrangler deploy", "vex", "curl"):
            self.assertNotIn(token,scan)
        p=subprocess.run(["bash","apps/inspector/scan_expat_cve_regression.sh","--bad"],
                         cwd=ROOT,capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode,3)


if __name__=="__main__":
    unittest.main()
