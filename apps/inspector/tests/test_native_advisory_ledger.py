"""TDD: source-built engines must retain visible, attributable CVE review debt."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_advisory_ledger import source_cve_ledger, SOURCE_CVES

EXPERIMENT = "folio-civico-inspector:poppler-experiment"
CANDIDATE = "folio-civico-inspector:ocr-integrated"
VALIDATION = "folio-civico-inspector:validation"


def inventory(mode="experiment", names=("tesseract", "poppler")):
    versions = {"tesseract": "5.5.4", "poppler": "25.03.0-5+deb13u4"}
    return {
        "source": "folio-local-elf-provenance-v1",
        "mode": mode,
        "source_cve_coverage": "unassessed" if names else "not_applicable",
        "components": [{
            "name": name, "version": versions[name],
            "executable_sha256": "a" * 64,
            "library_sha256": "b" * 64,
            "provenance_sha256": "c" * 64,
            "tool_sha256": ({tool: "d" * 64 for tool in
                            ("pdfinfo", "pdftotext", "pdftoppm", "pdfdetach", "pdfattach")}
                            if name == "poppler" else {}),
            "cve_assessment": "required",
            "automated_cve_coverage": "not_verified",
        } for name in names]
    }


class NativeAdvisoryLedgerTests(unittest.TestCase):
    def test_experiment_reconciles_tesseract_and_poppler_with_elf_identity(self):
        report = source_cve_ledger(inventory(), EXPERIMENT)
        self.assertEqual(report["status"], "review_required")
        self.assertEqual(report["snapshot_date"], "2026-11-19")
        self.assertFalse(report["complete_source_advisory_coverage"])
        self.assertFalse(report["declares_not_affected"])
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["scope"], "selected_open_debian_trixie_advisories_not_exhaustive")
        rows = report["components"]
        self.assertEqual([c["name"] for c in rows], ["tesseract", "poppler"])
        self.assertEqual([c["version"] for c in rows], ["5.5.4", "25.03.0-5+deb13u4"])
        self.assertEqual([c["cve_count"] for c in rows], [14, 10])
        self.assertEqual(report["selected_cve_total"], 24)
        self.assertEqual(rows[0]["executable_sha256"], "a" * 64)
        self.assertEqual(rows[1]["library_sha256"], "b" * 64)
        for row in rows:
            self.assertEqual(row["source_build_status"], "unassessed")
            self.assertEqual(row["tracker"], "https://security-tracker.debian.org/tracker/source-package/" + row["name"])
            self.assertEqual(len(row["cves"]), row["cve_count"])
            self.assertEqual([r["id"] for r in row["cves"]],
                             sorted({r["id"] for r in row["cves"]}))
            for item in row["cves"]:
                self.assertEqual(item["disposition"], "individual_review_required")
                self.assertEqual(item["source_binary_applicability"], "unassessed")
                self.assertEqual(item["reference"], "https://security-tracker.debian.org/tracker/" + item["id"])
        self.assertIn("CVE-2026-119338", [c["id"] for c in rows[0]["cves"]])
        self.assertIn("CVE-2026-107705", [c["id"] for c in rows[1]["cves"]])
        self.assertFalse(report["declares_not_affected"])
        self.assertTrue(all(
            item["disposition"] != "not_affected"
            for component in rows for item in component["cves"]
        ))

    def test_only_source_engines_present_in_matching_class_are_reported(self):
        candidate = source_cve_ledger(inventory("candidate", ("tesseract",)), CANDIDATE)
        self.assertEqual(candidate["selected_cve_total"], 14)
        self.assertEqual([x["name"] for x in candidate["components"]], ["tesseract"])
        empty = source_cve_ledger(inventory("validation", ()), VALIDATION)
        self.assertEqual(empty["selected_cve_total"], 0)
        self.assertEqual(empty["status"], "not_applicable")
        self.assertEqual(empty["components"], [])
        self.assertFalse(empty["complete_source_advisory_coverage"])

    def test_wrong_image_or_tampered_provenance_cannot_emit_attributed_report(self):
        source = inventory()
        for bad_image, bad_source in (
            ("random-image", source),
            (CANDIDATE, source),
            (EXPERIMENT, dict(source, mode="validation")),
            (EXPERIMENT, dict(source, components=[])),
            (EXPERIMENT, dict(source, source_cve_coverage="verified")),
            (EXPERIMENT, dict(source, components=[dict(source["components"][0], version="9.9.9"),
                                                source["components"][1]])),
            (EXPERIMENT, dict(source, components=[dict(source["components"][0],
                                                      library_sha256="not-a-hash"),
                                                source["components"][1]])),
        ):
            with self.subTest(image=bad_image, mode=bad_source.get("mode")):
                with self.assertRaises((ValueError, TypeError)):
                    source_cve_ledger(bad_source, bad_image)

    def test_incomplete_or_duplicate_snapshot_fails_instead_of_claiming_coverage(self):
        source = inventory()
        for corrupt in (
            {"tesseract": (), "poppler": SOURCE_CVES["poppler"]},
            {"tesseract": ("CVE-2026-119338", "CVE-2026-119338"), "poppler": SOURCE_CVES["poppler"]},
            {"tesseract": ("not-a-cve",), "poppler": SOURCE_CVES["poppler"]},
            {"tesseract": SOURCE_CVES["tesseract"]},
        ):
            with patch("native_advisory_ledger.SOURCE_CVES", corrupt):
                with self.assertRaises(ValueError):
                    source_cve_ledger(source, EXPERIMENT)


if __name__ == "__main__":
    unittest.main()
