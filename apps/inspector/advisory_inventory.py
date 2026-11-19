"""Read-only CVE details for selected parser dependencies in a Trivy image scan.

Runs only after the authoritative audit has evaluated the same image and
SBOM. This is diagnostic evidence, never a VEX, waiver, or release approval.
No PDFs, extracted text, internal paths, or service secrets are processed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from audit_image import evaluate_image_audit

SELECTED_PACKAGES = ("clamav", "libexpat1")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$")
MAX_PER_PACKAGE = 50
BLOCKING = frozenset(("CRITICAL", "HIGH", "UNKNOWN"))


def targeted_advisories(
    vulnerabilities: dict, sbom: dict, image: str, source_inventory: dict
) -> dict:
    audit = evaluate_image_audit(vulnerabilities, sbom, image, source_inventory)
    reported: dict[str, list[dict]] = {package: [] for package in SELECTED_PACKAGES}
    for section in vulnerabilities["Results"]:
        for finding in section.get("Vulnerabilities") or []:
            package = finding.get("PkgName")
            if package not in reported or finding["Severity"] not in BLOCKING:
                continue
            identifier = finding["VulnerabilityID"]
            version = finding.get("InstalledVersion")
            fixed = finding.get("FixedVersion") or None
            if (not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier)
                    or not isinstance(version, str) or not VERSION.fullmatch(version)
                    or (fixed is not None and
                        (not isinstance(fixed, str) or not VERSION.fullmatch(fixed)))):
                raise ValueError("Malformed scanner advisory metadata")
            # Never emit scanner descriptions, paths or arbitrary external URLs.
            reported[package].append({
                "id": identifier,
                "severity": finding["Severity"],
                "installed_version": version,
                "fixed_version": fixed,
            })

    result = []
    for package in SELECTED_PACKAGES:
        rows = reported[package]
        if len(rows) > MAX_PER_PACKAGE:
            raise ValueError("Too many parser advisories for bounded output")
        rows.sort(key=lambda x: (x["id"], x["severity"], x["installed_version"]))
        result.append({
            "package": package,
            "blocking_count": len(rows),
            "advisories": rows,
            "vendor_analysis_required": bool(rows),
        })

    return {
        "status": audit["status"],
        "image": image,
        "total_blocking": audit["critical"] + audit["high"] + audit["unknown"],
        "selected_blocking": sum(len(x["advisories"]) for x in result),
        "packages": result,
        "non_selected_findings_remain_blocking": True,
        "declares_not_affected": False,
        "source_built_coverage_verified": False,
        "source_components_unassessed": audit["source_components_unassessed"],
        "source_advisory_coverage": audit["source_advisory_coverage"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerabilities", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--source-inventory", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    try:
        vulnerabilities = json.loads(args.vulnerabilities.read_text(encoding="utf-8"))
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
        source_inventory = json.loads(args.source_inventory.read_text(encoding="utf-8"))
        report = targeted_advisories(vulnerabilities, sbom, args.image, source_inventory)
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "error", "reason": "advisory_inventory_incomplete"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
