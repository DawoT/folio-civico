"""Fail-closed evidence reconciliation for ONE experimental image.

SBOM + Trivy + immutable image ID + two source-built engines + local Expat ELF.
This is NOT a release decision or a VEX, even if CVE counts were zero.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from urllib.parse import quote

from audit_image import verify_native_source_inventory
from native_advisory_ledger import source_cve_ledger

IMAGE = "folio-civico-inspector:expat-experiment"
POPPLER_BASE = "folio-civico-inspector:poppler-experiment"
VERSION = "2.10.0-1+folio1"
SOURCE_SHA = "b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f"
PATCH_SHA = "0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3"
ELF_HASH = re.compile(r"^[a-f0-9]{64}$")
IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
TOOLS = ["pdfinfo", "pdftotext", "pdftoppm", "pdfdetach", "pdfattach"]
SEVERITIES = frozenset(("CRITICAL", "HIGH", "UNKNOWN", "MEDIUM", "LOW"))


def verify_evidence(
    scan: dict, sbom: dict, native: dict, expat: dict, image_id: str,
    image: str = IMAGE,
) -> dict:
    if not isinstance(image, str) or image != IMAGE or not (
        isinstance(image_id, str) and IMAGE_ID.fullmatch(image_id)
    ):
        raise ValueError("Experimental image and immutable digest required")
    if not isinstance(scan, dict) or scan.get("ArtifactName") != image or (
        scan.get("ArtifactType") != "container_image"
    ):
        raise ValueError("Mismatched vulnerability scan")
    sections = scan.get("Results")
    if not isinstance(sections, list) or not sections or not any(
        isinstance(row, dict) and row.get("Type") == "debian" for row in sections
    ):
        raise ValueError("Debian scan is missing")
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("CycloneDX SBOM missing")
    metadata = sbom.get("metadata")
    item = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(item, dict) or item.get("name") != image or (
        item.get("type") != "container"
    ):
        raise ValueError("SBOM image mismatch")
    properties = item.get("properties")
    if not isinstance(properties, list):
        raise ValueError("SBOM immutable image ID missing")
    ids = [
        prop.get("value") for prop in properties
        if isinstance(prop, dict) and prop.get("name") == "aquasecurity:trivy:ImageID"
    ]
    if ids != [image_id]:
        raise ValueError("SBOM/image ID mismatch")
    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("Empty CycloneDX component inventory")
    expat_components = [
        comp for comp in components if isinstance(comp, dict)
        and comp.get("name") == "libexpat1"
    ]
    if len(expat_components) != 1:
        raise ValueError("Exactly one packaged Expat SBOM component required")
    bill = expat_components[0]
    expected_purl = "pkg:deb/debian/libexpat1@" + quote(VERSION, safe="") + "?"
    if bill.get("version") != VERSION or not isinstance(
        bill.get("purl"), str
    ) or not bill["purl"].startswith(expected_purl):
        raise ValueError("Expat SBOM package identity mismatch")

    # Strict existing inventory policy validates unscanned custom Poppler/OCR
    # and prevents an empty Trivy result from masquerading as native coverage.
    custom_count = verify_native_source_inventory(native, POPPLER_BASE)
    ledger = source_cve_ledger(native, POPPLER_BASE)
    if custom_count != 2 or ledger["selected_cve_total"] != 24 or (
        ledger["complete_source_advisory_coverage"] is not False
    ):
        raise ValueError("Source-built OCR/PDF advisory evidence incomplete")

    required = {
        "source", "package", "package_version", "library_sha256",
        "provenance_sha256", "source_sha256", "patch_sha256",
        "runtime_version", "linked_poppler_tools", "xmlwf_present",
        "native_cve_coverage",
    }
    if not isinstance(expat, dict) or set(expat) != required or any((
        expat.get("source") != "folio-expat-local-provenance-v1",
        expat.get("package") != "libexpat1",
        expat.get("package_version") != VERSION,
        expat.get("source_sha256") != SOURCE_SHA,
        expat.get("patch_sha256") != PATCH_SHA,
        expat.get("runtime_version") != "expat_2.10.0",
        expat.get("linked_poppler_tools") != TOOLS,
        expat.get("xmlwf_present") is not False,
        expat.get("native_cve_coverage") != "unassessed",
    )):
        raise ValueError("Expat provenance is not the reviewed source build")
    for field in ("library_sha256", "provenance_sha256"):
        value = expat[field]
        if not isinstance(value, str) or not ELF_HASH.fullmatch(value):
            raise ValueError("Missing native Expat identity")

    counts: Counter[str] = Counter()
    for section in sections:
        if not isinstance(section, dict) or not isinstance(
            section.get("Target"), str
        ):
            raise ValueError("Malformed scanner target")
        findings = section.get("Vulnerabilities") or []
        if not isinstance(findings, list):
            raise ValueError("Malformed scanner findings")
        for finding in findings:
            if not isinstance(finding, dict) or (
                finding.get("Severity") not in SEVERITIES
            ) or not isinstance(finding.get("VulnerabilityID"), str) or (
                not finding["VulnerabilityID"]
            ):
                raise ValueError("Malformed advisory entry")
            if finding.get("PkgName") == "libexpat1" and (
                finding.get("InstalledVersion") != VERSION
            ):
                raise ValueError("Expat scan contradicts attested package version")
            counts[finding["Severity"]] += 1

    return {
        "status": "evidence_valid_release_blocked",
        "release_authorized": False,
        "advisory_coverage_incomplete": True,
        "image": image,
        "image_id": image_id,
        "sbom_components": len(components),
        "source_components_unassessed": custom_count + 1,
        "selected_native_cves_unassessed": ledger["selected_cve_total"],
        "expat_library_sha256": expat["library_sha256"],
        "expat_patch_sha256": expat["patch_sha256"],
        "blocking_scan_critical": counts["CRITICAL"],
        "blocking_scan_high": counts["HIGH"],
        "blocking_scan_unknown": counts["UNKNOWN"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerabilities", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--source-inventory", required=True, type=Path)
    parser.add_argument("--expat-inventory", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    try:
        report = verify_evidence(
            json.loads(args.vulnerabilities.read_text(encoding="utf-8")),
            json.loads(args.sbom.read_text(encoding="utf-8")),
            json.loads(args.source_inventory.read_text(encoding="utf-8")),
            json.loads(args.expat_inventory.read_text(encoding="utf-8")),
            args.image_id, args.image,
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print(json.dumps({"status": "error", "reason": "expat_image_evidence_incomplete"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    # This is ONLY an evidence-integrity result. The scanner gate exits 2.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
