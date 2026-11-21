"""Validate Trivy JSON and CycloneDX SBOM for the exact inspector image.

Only aggregate counts are emitted. A successful scan is NOT a security approval
when any CRITICAL, HIGH or UNKNOWN findings remain. No automatic suppressions.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

SOURCE_MODES = {
    "folio-civico-inspector:validation": "validation",
    "folio-civico-inspector:ocr-integrated": "candidate",
    "folio-civico-inspector:poppler-experiment": "experiment",
}
EXPECTED_SOURCE_VERSIONS = {
    "tesseract": "5.5.4",
    "poppler": "25.03.0-5+deb13u4",
}
SHA256 = re.compile(r"^[a-f0-9]{64}$")

ALLOWED_SEVERITIES = frozenset(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"))
BLOCKING_SEVERITIES = frozenset(("CRITICAL", "HIGH", "UNKNOWN"))


def verify_native_source_inventory(inventory: dict, image: str) -> int:
    """Verify native ELF and OCR model hashes, not CVE applicability or authenticity."""
    mode = SOURCE_MODES.get(image)
    if mode is None or not isinstance(inventory, dict):
        raise ValueError("Unknown image or missing native source inventory")
    if (inventory.get("source") != "folio-local-elf-provenance-v1"
            or inventory.get("mode") != mode):
        raise ValueError("Native source inventory is missing or targets another image")
    components = inventory.get("components")
    if not isinstance(components, list) or len(components) > 2:
        raise ValueError("Malformed native source component list")
    names: list[str] = []
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("Malformed native source component")
        name = component.get("name")
        if (name not in EXPECTED_SOURCE_VERSIONS
                or name in names
                or component.get("version") != EXPECTED_SOURCE_VERSIONS[name]
                or component.get("cve_assessment") != "required"
                or component.get("automated_cve_coverage") != "not_verified"):
            raise ValueError("Native source version or assessment is unverified")
        for field in ("executable_sha256", "library_sha256", "provenance_sha256"):
            value = component.get(field)
            if not isinstance(value, str) or not SHA256.fullmatch(value):
                raise ValueError("Native ELF fingerprint missing")
        tool_hashes = component.get("tool_sha256")
        if not isinstance(tool_hashes, dict):
            raise ValueError("Native tool inventory missing")
        expected_tools = ({"pdfinfo", "pdftotext", "pdftoppm", "pdfdetach", "pdfattach"}
                          if name == "poppler" else set())
        if (set(tool_hashes) != expected_tools or any(
                not isinstance(value, str) or not SHA256.fullmatch(value)
                for value in tool_hashes.values())):
            raise ValueError("Native source utility fingerprints incomplete")
        model_hashes = component.get("model_sha256")
        expected_models = {"eng", "spa"} if name == "tesseract" else set()
        if (not isinstance(model_hashes, dict)
                or set(model_hashes) != expected_models
                or any(not isinstance(value, str) or not SHA256.fullmatch(value)
                       for value in model_hashes.values())):
            raise ValueError("Native OCR model identity is not attested")
        names.append(name)
    required = {
        "validation": set(),
        "candidate": {"tesseract"},
        "experiment": {"tesseract", "poppler"},
    }[mode]
    if mode == "validation":
        if "poppler" in names and "tesseract" not in names:
            raise ValueError("Unexpected source component composition")
    elif set(names) != required:
        raise ValueError("Mandatory native source component is unaccounted for")
    expected_coverage = "unassessed" if names else "not_applicable"
    if inventory.get("source_cve_coverage") != expected_coverage:
        raise ValueError("Native source advisory coverage claimed without evidence")
    return len(names)


def evaluate_image_audit(
    vulnerabilities: dict, sbom: dict, image: str, source_inventory: dict
) -> dict:
    if not image or vulnerabilities.get("ArtifactName") != image:
        raise ValueError("Vulnerability report targets a different image")
    if vulnerabilities.get("ArtifactType") != "container_image":
        raise ValueError("Expected a container image vulnerability report")
    results = vulnerabilities.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Trivy did not report scanned image targets")
    if not any(isinstance(section, dict) and section.get("Type") == "debian"
               for section in results):
        raise ValueError("Debian OS dependencies were not audited")
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("Missing CycloneDX SBOM")
    metadata = sbom.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict) or component.get("name") != image:
        raise ValueError("SBOM image does not match vulnerability report")
    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("SBOM must enumerate installed components")

    source_unassessed = verify_native_source_inventory(source_inventory, image)
    counts: Counter[str] = Counter()
    fixable = 0
    for section in results:
        if not isinstance(section, dict) or not isinstance(section.get("Target"), str):
            raise ValueError("Invalid Trivy target section")
        findings = section.get("Vulnerabilities") or []
        if not isinstance(findings, list):
            raise ValueError("Invalid vulnerability collection")
        for entry in findings:
            if not isinstance(entry, dict):
                raise ValueError("Invalid vulnerability finding")
            severity = entry.get("Severity")
            if severity not in ALLOWED_SEVERITIES:
                raise ValueError("Unsupported vulnerability severity")
            if not isinstance(entry.get("VulnerabilityID"), str):
                raise ValueError("Missing CVE or advisory identifier")
            counts[severity] += 1
            if severity in ("CRITICAL", "HIGH") and entry.get("FixedVersion"):
                fixable += 1

    blocked = (bool(source_unassessed)
               or any(counts[severity] > 0 for severity in BLOCKING_SEVERITIES))
    return {
        "native_components": [
            {field: component[field] for field in (
                "name", "version", "executable_sha256",
                "library_sha256", "provenance_sha256", "tool_sha256",
                "model_sha256",
            )}
            for component in source_inventory["components"]
        ],
        "source_components_unassessed": source_unassessed,
        "source_advisory_coverage": "pending_review" if source_unassessed else "no_custom_components",
        "status": "blocked" if blocked else "passed",
        "image": image,
        "components": len(components),
        "targets_scanned": len(results),
        "total_findings": sum(counts.values()),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "unknown": counts["UNKNOWN"],
        "fixable_high_critical": fixable,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerabilities", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--source-inventory", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    try:
        scan = json.loads(args.vulnerabilities.read_text(encoding="utf-8"))
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
        native = json.loads(args.source_inventory.read_text(encoding="utf-8"))
        result = evaluate_image_audit(scan, sbom, args.image, native)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        print(json.dumps({"status": "error", "reason": "image_scan_incomplete"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
