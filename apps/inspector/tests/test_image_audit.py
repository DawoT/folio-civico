"""Fail-closed policy tests for the inspector image vulnerability gate."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from audit_image import evaluate_image_audit, main

IMAGE="folio-civico-inspector:validation"

def scan(*issues):
    return {
        "SchemaVersion": 2,
        "ArtifactName": IMAGE,
        "ArtifactType": "container_image",
        "Results": [{
            "Target": IMAGE + " (debian 12.15)",
            "Type": "debian",
            "Vulnerabilities": list(issues),
        }],
    }

def sbom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {"component": {"name": IMAGE}},
        "components": [{"type": "library", "name": "qpdf", "version": "11.3.0"}],
    }

def issue(severity, name="libnative", fixed=""):
    return {
        "VulnerabilityID": "CVE-2026-12345", "PkgName": name,
        "InstalledVersion": "1.0", "Severity": severity,
        "FixedVersion": fixed,
    }

class ImageAuditTests(unittest.TestCase):
    def test_image_fails_critical_and_high_even_without_available_fixes(self):
        result=evaluate_image_audit(
            scan(issue("CRITICAL"),issue("HIGH"),issue("MEDIUM")),
            sbom(), IMAGE,
        )
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["critical"],1)
        self.assertEqual(result["high"],1)
        self.assertEqual(result["medium"],1)
        self.assertEqual(result["fixable_high_critical"],0)
        self.assertEqual(result["components"],1)

    def test_unknown_severity_is_not_silently_considered_safe(self):
        result=evaluate_image_audit(scan(issue("UNKNOWN")),sbom(),IMAGE)
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["unknown"],1)

    def test_fixable_high_is_still_blocking(self):
        result=evaluate_image_audit(
            scan(issue("HIGH",fixed="2.0")),sbom(),IMAGE
        )
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["fixable_high_critical"],1)

    def test_clean_low_severity_report_can_pass(self):
        result=evaluate_image_audit(scan(issue("LOW")),sbom(),IMAGE)
        self.assertEqual(result["status"],"passed")
        self.assertEqual(result["high"],0)
        self.assertEqual(result["critical"],0)

    def test_missing_scan_results_or_sbom_components_fail_closed(self):
        badscan=scan()
        badscan["Results"]=[]
        with self.assertRaises(ValueError):
            evaluate_image_audit(badscan,sbom(),IMAGE)
        badbom=sbom()
        badbom["components"]=[]
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(),badbom,IMAGE)

    def test_scanner_must_have_an_os_target_not_just_python(self):
        incomplete=scan()
        incomplete["Results"][0]["Type"]="python-pkg"
        with self.assertRaisesRegex(ValueError,"OS dependencies"):
            evaluate_image_audit(incomplete,sbom(),IMAGE)

    def test_mismatched_images_or_unknown_severities_fail_closed(self):
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(),sbom(),"some-other-image:latest")
        wrong=sbom()
        wrong["metadata"]["component"]["name"]="other"
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(),wrong,IMAGE)
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(issue("UNRECOGNIZED")),sbom(),IMAGE)

    def test_malformed_sbom_metadata_fails_closed_without_tracebacks(self):
        invalid=sbom()
        invalid["metadata"]["component"]="invalid"
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(),invalid,IMAGE)

    def test_cli_returns_error_code_three_on_missing_reports(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(sys,"argv",[
                "audit_image.py", "--vulnerabilities",str(Path(root)/"missing.json"),
                "--sbom",str(Path(root)/"missing-sbom.json"),"--image",IMAGE
            ]),patch("builtins.print") as emitted:
                self.assertEqual(main(),3)
                self.assertEqual(json.loads(emitted.call_args.args[0]),
                                 {"status":"error","reason":"image_scan_incomplete"})

    def test_cli_reports_explicit_block_with_nonzero_exit_code(self):
        with tempfile.TemporaryDirectory() as root:
            vuln=Path(root)/"trivy.json"
            bom=Path(root)/"sbom.json"
            vuln.write_text(json.dumps(scan(issue("CRITICAL"))),encoding="utf-8")
            bom.write_text(json.dumps(sbom()),encoding="utf-8")
            with patch.object(sys,"argv",[
                "audit_image.py", "--vulnerabilities",str(vuln),
                "--sbom",str(bom),"--image",IMAGE
            ]),patch("builtins.print") as emitted:
                self.assertEqual(main(),2)
                value=json.loads(emitted.call_args.args[0])
                self.assertEqual(value["status"],"blocked")
                self.assertNotIn("InstalledVersion",str(value))

if __name__=="__main__":
    unittest.main()
