"""Experimental, fail-closed Trivy summary. NOT the production image audit."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

IMAGE = "folio-civico-inspector:expat-experiment"
SEVERITIES = frozenset(("CRITICAL", "HIGH", "UNKNOWN", "MEDIUM", "LOW"))


def summarize(scan: dict, image: str = IMAGE) -> dict:
    if not isinstance(scan, dict) or image != IMAGE:
        raise ValueError("Experimental image identity required")
    if scan.get("ArtifactName") != image or scan.get("ArtifactType") != "container_image":
        raise ValueError("Mismatched image identity")
    sections = scan.get("Results")
    if not isinstance(sections, list) or not sections:
        raise ValueError("No vulnerability coverage")
    if not any(isinstance(section, dict) and section.get("Type") == "debian"
               for section in sections):
        raise ValueError("OS packages were not scanned")
    counts = Counter()
    expat = Counter()
    expat_versions: set[str] = set()
    for section in sections:
        if not isinstance(section, dict) or not isinstance(section.get("Target"), str):
            raise ValueError("Invalid vulnerability section")
        findings = section.get("Vulnerabilities") or []
        if not isinstance(findings, list):
            raise ValueError("Invalid findings")
        for finding in findings:
            if (not isinstance(finding, dict)
                    or finding.get("Severity") not in SEVERITIES
                    or not isinstance(finding.get("VulnerabilityID"), str)
                    or not finding["VulnerabilityID"]):
                raise ValueError("Invalid vulnerability record")
            severity = finding["Severity"]
            counts[severity] += 1
            if finding.get("PkgName") == "libexpat1":
                version = finding.get("InstalledVersion")
                if not isinstance(version, str) or not version:
                    raise ValueError("Expat version is missing from Trivy")
                expat_versions.add(version)
                expat[severity] += 1

    if len(expat_versions) > 1:
        raise ValueError("Inconsistent Expat versions in scan")

    # Even a zero-report cannot pass: the source-built library has no formal
    # package VEX/coverage, and the parent Poppler experiment is blocked.
    return {
        "status": "blocked",
        "image": image,
        "experimental_only": True,
        "release_authorized": False,
        "scan_is_not_official_gate": True,
        "source_built_expat_cve_assessment": "required",
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "unknown": counts["UNKNOWN"],
        "expat_high": expat["HIGH"],
        "expat_unknown": expat["UNKNOWN"],
        "expat_installed_version": next(iter(expat_versions), None),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    try:
        scan = json.loads(args.input.read_text(encoding="utf-8"))
        report = summarize(scan, args.image)
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "error", "reason": "experimental_scan_invalid"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 2


if __name__ == "__main__":
    sys.exit(main())
