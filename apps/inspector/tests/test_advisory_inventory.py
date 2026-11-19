"""Fail-closed contract tests for exact ClamAV/Expat CVE investigation."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from advisory_inventory import targeted_advisories, main

IMAGE = "folio-civico-inspector:poppler-experiment"


def scan(*findings):
    return {"ArtifactName": IMAGE, "ArtifactType": "container_image", "Results": [
        {"Type":"debian", "Target":"debian:13", "Vulnerabilities": list(findings)},
    ]}


def sbom():
    return {"bomFormat":"CycloneDX", "metadata":{"component":{"name":IMAGE}},
            "components":[{"name":"libexpat1","type":"library","version":"synthetic"}]}


def issue(package, severity, identifier, version="synthetic", fixed=""):
    return {"PkgName":package,"Severity":severity,"VulnerabilityID":identifier,
            "InstalledVersion":version, "FixedVersion":fixed}


def source_inventory():
    components=[
        {"name":name,"version":version,
         "executable_sha256":"a"*64,
         "library_sha256":"b"*64,
         "provenance_sha256":"c"*64,
         "tool_sha256":({tool:"d"*64 for tool in (
             "pdfinfo","pdftotext","pdftoppm","pdfdetach","pdfattach")}
             if name == "poppler" else {}),
         "cve_assessment":"required",
         "automated_cve_coverage":"not_verified"}
        for name,version in [
            ("tesseract","5.5.4"),
            ("poppler","25.03.0-5+deb13u4"),
        ]
    ]
    return {
        "source":"folio-local-elf-provenance-v1",
        "mode":"experiment",
        "components":components,
        "source_cve_coverage":"unassessed",
    }


class AdvisoryInventoryTests(unittest.TestCase):
    def test_targeted_ids_are_deterministic_and_other_findings_remain_blocking(self):
        result=targeted_advisories(
            scan(issue("libexpat1","HIGH","CVE-2026-124317"),
                 issue("clamav","HIGH","CVE-2026-76422",fixed="1.5.6"),
                 issue("clamav","LOW","CVE-2020-1000"),
                 issue("libexpat1","UNKNOWN","CVE-2026-115506"),
                 issue("libc6","HIGH","CVE-2026-77777")),
            sbom(), IMAGE, source_inventory()
        )
        self.assertEqual(result["status"],"blocked")
        self.assertEqual(result["total_blocking"],4)
        self.assertEqual(result["selected_blocking"],3)
        self.assertEqual([x["package"] for x in result["packages"]],["clamav","libexpat1"])
        self.assertEqual([x["id"] for x in result["packages"][1]["advisories"]],
                         ["CVE-2026-115506","CVE-2026-124317"])
        self.assertEqual(result["packages"][0]["advisories"][0]["fixed_version"],"1.5.6")
        self.assertTrue(result["non_selected_findings_remain_blocking"])
        self.assertFalse(result["declares_not_affected"])
        self.assertFalse(result["source_built_coverage_verified"])
        self.assertEqual(result["native_selected_cve_count"], 24)
        self.assertEqual(result["native_source_advisories"]["status"], "review_required")
        self.assertFalse(result["native_source_advisories"]["release_authorized"])
        self.assertFalse(result["native_source_advisories"]["complete_source_advisory_coverage"])
        self.assertEqual([x["cve_count"] for x in
                          result["native_source_advisories"]["components"]], [14,10])
        self.assertNotIn("description",json.dumps(result))

    def test_missing_metadata_or_excessive_findings_fail_closed(self):
        base=scan(issue("clamav","HIGH","CVE-2026-76422"))
        for field in ("VulnerabilityID","InstalledVersion"):
            copy_scan=copy.deepcopy(base)
            del copy_scan["Results"][0]["Vulnerabilities"][0][field]
            with self.subTest(field=field), self.assertRaises((ValueError,KeyError)):
                targeted_advisories(copy_scan,sbom(),IMAGE,source_inventory())
        for invalid in ("1.5.5\n/private", "../escape", "bad version"):
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                targeted_advisories(
                    scan(issue("clamav","HIGH","CVE-2026-20213",version=invalid)),
                    sbom(),IMAGE,source_inventory()
                )
        spam=scan(*[issue("clamav","HIGH",f"CVE-2026-{10000+i}") for i in range(51)])
        with self.assertRaises(ValueError):
            targeted_advisories(spam,sbom(),IMAGE,source_inventory())

    def test_clean_selected_packages_do_not_override_other_blocks(self):
        value=targeted_advisories(scan(issue("libc6","UNKNOWN","CVE-2026-88888")),
                                  sbom(),IMAGE,source_inventory())
        self.assertEqual(value["status"],"blocked")
        self.assertEqual(value["selected_blocking"],0)
        self.assertEqual(value["total_blocking"],1)
        self.assertFalse(any(x["vendor_analysis_required"] for x in value["packages"]))
        self.assertEqual(value["native_selected_cve_count"], 24)
        self.assertEqual(value["native_source_advisories"]["status"], "review_required")
        self.assertEqual(value["status"], "blocked")

    def test_mismatched_image_or_missing_report_returns_error_three(self):
        with self.assertRaises(ValueError):
            targeted_advisories(scan(),sbom(),"wrong",source_inventory())
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(sys,"argv",[
                "advisory_inventory.py","--vulnerabilities",str(Path(folder)/"missing"),
                "--sbom",str(Path(folder)/"missing2"),"--source-inventory",str(Path(folder)/"native-missing"),"--image",IMAGE,
            ]), patch("builtins.print") as emitted:
                self.assertEqual(main(),3)
                self.assertEqual(json.loads(emitted.call_args.args[0]),
                                 {"status":"error","reason":"advisory_inventory_incomplete"})


if __name__=="__main__":
    unittest.main()
