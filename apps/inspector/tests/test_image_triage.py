"""TDD for additive CVE triage: it must never downgrade the blocking gate."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from triage_image import prioritize_findings, main, REQUIRED_ENGINES

IMAGE = "folio-civico-inspector:validation"


def finding(name: str, severity: str, vid: str, fixed: str = "") -> dict:
    return {
        "PkgName": name, "Severity": severity, "VulnerabilityID": vid,
        "InstalledVersion": "synthetic", "FixedVersion": fixed,
    }


def scan(*findings: dict) -> dict:
    return {
        "ArtifactName": IMAGE, "ArtifactType": "container_image",
        "Results": [
            {"Type": "debian", "Target": "debian:13", "Vulnerabilities": list(findings)},
            {"Type": "python-pkg", "Target": "python", "Vulnerabilities": []},
        ],
    }


def sbom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": IMAGE}},
        "components": [{"type": "library", "name": "libxml2", "version": "synthetic"}],
    }


def inventory(*, unmapped: int = 0) -> dict:
    engines = {name: ["libc6"] for name in REQUIRED_ENGINES}
    engines["tesseract"] = ["libc6", "libxml2", "libtesseract5"]
    engines["pdftotext"] = ["libc6", "libkrb5-3"]
    return {
        "source": "ldd-dpkg-query",
        "engines": engines,
        "unmapped_libraries": {"clamscan": unmapped},
    }


def source_inventory():
    return {
        "source":"folio-local-elf-provenance-v1",
        "mode":"validation",
        "components":[],
        "source_cve_coverage":"not_applicable",
    }


class TriageTests(unittest.TestCase):
    def test_real_link_is_prioritized_but_never_classifies_as_non_affected(self):
        report = prioritize_findings(
            scan(
                finding("libxml2", "CRITICAL", "CVE-2026-6653"),
                finding("libxml2", "HIGH", "CVE-2026-70000"),
                finding("libkrb5-3", "HIGH", "CVE-2026-70001"),
                finding("some-runtime-package", "HIGH", "CVE-2026-70002"),
                finding("libc6", "UNKNOWN", "CVE-2026-70003"),
                finding("libtesseract5", "LOW", "CVE-2026-70004"),
            ), sbom(), inventory(), IMAGE, source_inventory(),
        )
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["total_blocking_findings"], 5)
        self.assertEqual(report["observed_linked_blocking"], 4)
        self.assertEqual(report["not_observed_blocking"], 1)
        self.assertTrue(report["dynamic_linkage_only"])
        self.assertFalse(report["declares_not_affected"])
        self.assertEqual(report["priorities"][0]["package"], "libxml2")
        self.assertEqual(report["priorities"][0]["linked_engines"], ["tesseract"])
        self.assertEqual(report["priorities"][0]["critical"], 1)
        self.assertTrue(any(entry["package"] == "some-runtime-package"
                            and entry["linkage"] == "not_observed_in_ldd"
                            for entry in report["priorities"]))
        self.assertNotIn("synthetic", json.dumps(report))

    def test_missing_engine_or_malformed_ownership_fails_closed(self):
        original = inventory()
        del original["engines"]["tesseract"]
        with self.assertRaises(ValueError):
            prioritize_findings(scan(), sbom(), original, IMAGE, source_inventory())
        original = inventory()
        original["engines"]["qpdf"] = ["../../private"]
        with self.assertRaises(ValueError):
            prioritize_findings(scan(), sbom(), original, IMAGE, source_inventory())
        original = inventory(unmapped=-1)
        with self.assertRaises(ValueError):
            prioritize_findings(scan(), sbom(), original, IMAGE, source_inventory())

    def test_unknown_and_unmapped_are_never_auto_suppressed(self):
        result = prioritize_findings(
            scan(finding("dynamic-parser", "UNKNOWN", "CVE-2026-70001")),
            sbom(), inventory(unmapped=2), IMAGE, source_inventory()
        )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["unknown_dependency_owners"], 2)
        self.assertEqual(result["not_observed_blocking"], 1)
        self.assertEqual(result["priorities"][0]["unknown"], 1)
        self.assertFalse(result["ownership_complete"])

    def test_output_is_bounded_and_deterministic(self):
        issues = [finding("library-" + str(i), "HIGH", "CVE-2026-" + str(10000 + i))
                  for i in range(60)]
        one = prioritize_findings(scan(*issues), sbom(), inventory(), IMAGE, source_inventory())
        two = prioritize_findings(scan(*issues), sbom(), inventory(), IMAGE, source_inventory())
        self.assertEqual(one, two)
        self.assertEqual(one["total_packages"], 60)
        self.assertEqual(one["returned_packages"], 15)
        self.assertTrue(one["priorities_truncated"])
        self.assertEqual(one["total_blocking_findings"], 60)

    def test_cli_invalid_input_returns_error_without_private_source(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            arguments = [
                "triage_image.py", "--vulnerabilities", str(base / "missing.json"),
                "--sbom", str(base / "missing-sbom.json"),
                "--inventory", str(base / "missing-inventory.json"),
                "--source-inventory", str(base / "missing-native.json"),
                "--image", IMAGE,
            ]
            with patch.object(sys, "argv", arguments), patch("builtins.print") as emitted:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(emitted.call_args.args[0]),
                                 {"status": "error", "reason": "runtime_triage_incomplete"})


if __name__ == "__main__":
    unittest.main()
