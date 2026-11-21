"""Fail-closed policy tests for the inspector image vulnerability gate."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from audit_image import evaluate_image_audit, main

IMAGE="folio-civico-inspector:validation"

def source_inventory():
    return {
        "source":"folio-local-elf-provenance-v1",
        "mode":"validation",
        "components":[],
        "source_cve_coverage":"not_applicable",
    }


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
            sbom(), IMAGE, source_inventory(),
        )
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["critical"],1)
        self.assertEqual(result["high"],1)
        self.assertEqual(result["medium"],1)
        self.assertEqual(result["fixable_high_critical"],0)
        self.assertEqual(result["components"],1)

    def test_unknown_severity_is_not_silently_considered_safe(self):
        result=evaluate_image_audit(scan(issue("UNKNOWN")),sbom(),IMAGE,source_inventory())
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["unknown"],1)

    def test_fixable_high_is_still_blocking(self):
        result=evaluate_image_audit(
            scan(issue("HIGH",fixed="2.0")),sbom(),IMAGE,source_inventory()
        )
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["fixable_high_critical"],1)

    def test_clean_low_severity_report_can_pass(self):
        result=evaluate_image_audit(scan(issue("LOW")),sbom(),IMAGE,source_inventory())
        self.assertEqual(result["status"],"passed")
        self.assertEqual(result["high"],0)
        self.assertEqual(result["critical"],0)

    def test_missing_scan_results_or_sbom_components_fail_closed(self):
        badscan=scan()
        badscan["Results"]=[]
        with self.assertRaises(ValueError):
            evaluate_image_audit(badscan,sbom(),IMAGE,source_inventory())
        badbom=sbom()
        badbom["components"]=[]
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(),badbom,IMAGE,source_inventory())

    def test_scanner_must_have_an_os_target_not_just_python(self):
        incomplete=scan()
        incomplete["Results"][0]["Type"]="python-pkg"
        with self.assertRaisesRegex(ValueError,"OS dependencies"):
            evaluate_image_audit(incomplete,sbom(),IMAGE,source_inventory())

    def test_mismatched_images_or_unknown_severities_fail_closed(self):
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(),sbom(),"some-other-image:latest",source_inventory())
        wrong=sbom()
        wrong["metadata"]["component"]["name"]="other"
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(),wrong,IMAGE,source_inventory())
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(issue("UNRECOGNIZED")),sbom(),IMAGE,source_inventory())

    def test_malformed_sbom_metadata_fails_closed_without_tracebacks(self):
        invalid=sbom()
        invalid["metadata"]["component"]="invalid"
        with self.assertRaises(ValueError):
            evaluate_image_audit(scan(),invalid,IMAGE,source_inventory())

    def test_clean_trivy_cannot_release_unassessed_source_built_engines(self):
        image="folio-civico-inspector:poppler-experiment"
        vulnerabilities=scan()
        vulnerabilities["ArtifactName"]=image
        bill=sbom()
        bill["metadata"]["component"]["name"]=image
        components=[
            {"name":name,"version":version,
             "executable_sha256":"a"*64,
             "library_sha256":"b"*64,
             "provenance_sha256":"c"*64,
             "tool_sha256":({name:"d"*64 for name in (
                 "pdfinfo","pdftotext","pdfimages","pdftoppm","pdfdetach","pdfattach")}
                 if name == "poppler" else {}),
             "model_sha256":({"eng": "e"*64, "spa": "f"*64}
                             if name == "tesseract" else {}),
             "cve_assessment":"required",
             "automated_cve_coverage":"not_verified"}
            for name,version in (
                ("tesseract","5.5.4"),
                ("poppler","25.03.0-5+deb13u4"),
            )
        ]
        native={"source":"folio-local-elf-provenance-v1",
                "mode":"experiment","source_cve_coverage":"unassessed",
                "components":components}
        report=evaluate_image_audit(vulnerabilities,bill,image,native)
        self.assertEqual(report["status"],"blocked")
        self.assertEqual(report["high"],0)
        self.assertEqual(report["unknown"],0)
        self.assertEqual(report["source_components_unassessed"],2)
        self.assertEqual(report["source_advisory_coverage"],"pending_review")
        self.assertEqual([x["name"] for x in report["native_components"]],
                         ["tesseract","poppler"])
        self.assertEqual(report["native_components"][0]["library_sha256"],"b"*64)
        self.assertEqual(report["native_components"][0]["model_sha256"],
                         {"eng":"e"*64,"spa":"f"*64})
        for bad in (
            dict(native,components=[]),
            dict(native,source_cve_coverage="verified"),
            dict(native,mode="candidate"),
            dict(native,components=[components[0],components[0]]),
            dict(native,components=[components[0], dict(
                components[1], tool_sha256={
                    key: value for key, value in components[1]["tool_sha256"].items()
                    if key != "pdfimages"
                }
            )]),
            dict(native,components=[dict(components[0],library_sha256="not-a-hash"),components[1]]),
            dict(native,components=[dict(components[0],model_sha256={}),components[1]]),
            dict(native,components=[dict(components[0],model_sha256={"eng":"a"*64,"spa":"bad"}),components[1]]),
            dict(native,components=[dict(components[1],name="poppler",model_sha256={"eng":"a"*64}),
                                    components[0]]),
        ):
            with self.subTest(bad=bad.get("mode")), self.assertRaises(ValueError):
                evaluate_image_audit(vulnerabilities,bill,image,bad)
        with self.assertRaises(TypeError):
            evaluate_image_audit(vulnerabilities,bill,image)

    def test_cli_returns_error_code_three_on_missing_reports(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(sys,"argv",[
                "audit_image.py", "--vulnerabilities",str(Path(root)/"missing.json"),
                "--sbom",str(Path(root)/"missing-sbom.json"),"--source-inventory",str(Path(root)/"missing-native.json"),"--image",IMAGE
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
            native=Path(root)/"native.json"
            native.write_text(json.dumps(source_inventory()),encoding="utf-8")
            with patch.object(sys,"argv",[
                "audit_image.py", "--vulnerabilities",str(vuln),
                "--sbom",str(bom),"--source-inventory",str(native),"--image",IMAGE
            ]),patch("builtins.print") as emitted:
                self.assertEqual(main(),2)
                value=json.loads(emitted.call_args.args[0])
                self.assertEqual(value["status"],"blocked")
                self.assertNotIn("InstalledVersion",str(value))

if __name__=="__main__":
    unittest.main()
