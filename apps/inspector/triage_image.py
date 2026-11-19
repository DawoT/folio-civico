"""Prioritize all blocking CVEs by OBSERVED dynamic linkage in the PDF engines.

This triage is informational only. An ldd/dpkg match is useful evidence of
installed runtime linkage; absence of a match DOES NOT establish that a
package is unreachable, unused, unexploitable or "not affected". The separate
audit_image.py gate MUST continue to block CRITICAL/HIGH/UNKNOWN findings.
No institutional documents are read, no vulnerabilities are suppressed.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

from audit_image import evaluate_image_audit

REQUIRED_ENGINES = frozenset((
    "clamscan", "qpdf", "pdfdetach", "pdfinfo", "pdftotext",
    "pdftoppm", "tesseract",
))
PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:-]{0,127}$")
MAX_PRIORITIES = 15
BLOCKING = frozenset(("CRITICAL", "HIGH", "UNKNOWN"))


def validate_inventory(inventory: dict) -> tuple[dict[str, list[str]], int]:
    if not isinstance(inventory, dict) or inventory.get("source") != "ldd-dpkg-query":
        raise ValueError("Expected a real ldd/dpkg runtime inventory")
    engines = inventory.get("engines")
    if not isinstance(engines, dict) or set(engines) != REQUIRED_ENGINES:
        raise ValueError("Runtime inventory lacks a required scanner engine")
    for name, packages in engines.items():
        if (not isinstance(packages, list) or not packages
                or len(packages) > 400
                or any(not isinstance(p, str) or not PACKAGE.fullmatch(p)
                       for p in packages)
                or len(set(packages)) != len(packages)):
            raise ValueError("Malformed runtime dependency inventory")
    unmapped = inventory.get("unmapped_libraries")
    if (not isinstance(unmapped, dict)
            or not set(unmapped).issubset(REQUIRED_ENGINES)):
        raise ValueError("Malformed runtime ownership diagnostics")
    for count in unmapped.values():
        if type(count) is not int or count < 0 or count > 1000:
            raise ValueError("Invalid library ownership count")
    return engines, sum(unmapped.values())


def prioritize_findings(
    scan: dict, sbom: dict, inventory: dict, image: str,
    source_inventory: dict,
) -> dict:
    # Use the SAME validation policy, not a simplified or weaker one.
    audit = evaluate_image_audit(scan, sbom, image, source_inventory)
    engines, unmapped = validate_inventory(inventory)
    linked = defaultdict(set)
    for engine, packages in engines.items():
        for package in packages:
            linked[package].add(engine)

    rows: dict[str, dict] = {}
    observed, not_observed = 0, 0
    for section in scan["Results"]:
        for finding in section.get("Vulnerabilities") or []:
            if finding["Severity"] not in BLOCKING:
                continue
            package = finding.get("PkgName")
            if not isinstance(package, str) or not PACKAGE.fullmatch(package):
                raise ValueError("Missing or malformed vulnerable package name")
            row = rows.setdefault(package, {
                "package": package,
                "critical": 0, "high": 0, "unknown": 0,
                "linked_engines": sorted(linked.get(package, set())),
                "linkage": ("observed_dynamic_link" if package in linked
                            else "not_observed_in_ldd"),
            })
            row[finding["Severity"].lower()] += 1
            if package in linked:
                observed += 1
            else:
                not_observed += 1

    priorities = sorted(
        rows.values(), key=lambda row: (
            -row["critical"], -row["high"], -row["unknown"],
            row["linkage"] != "observed_dynamic_link",
            -len(row["linked_engines"]), row["package"],
        )
    )
    return {
        "status": audit["status"],
        "image": image,
        "audit_critical": audit["critical"],
        "audit_high": audit["high"],
        "audit_unknown": audit["unknown"],
        "source_components_unassessed": audit["source_components_unassessed"],
        "source_advisory_coverage": audit["source_advisory_coverage"],
        "total_blocking_findings": observed + not_observed,
        "observed_linked_blocking": observed,
        "not_observed_blocking": not_observed,
        "total_packages": len(priorities),
        "returned_packages": min(len(priorities), MAX_PRIORITIES),
        "priorities_truncated": len(priorities) > MAX_PRIORITIES,
        "priorities": priorities[:MAX_PRIORITIES],
        "engine_count": len(engines),
        "unknown_dependency_owners": unmapped,
        "ownership_complete": unmapped == 0,
        "dynamic_linkage_only": True,
        "declares_not_affected": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerabilities", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--source-inventory", required=True, type=Path)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    try:
        report = prioritize_findings(
            json.loads(args.vulnerabilities.read_text(encoding="utf-8")),
            json.loads(args.sbom.read_text(encoding="utf-8")),
            json.loads(args.inventory.read_text(encoding="utf-8")),
            args.image,
            json.loads(args.source_inventory.read_text(encoding="utf-8")),
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        print(json.dumps({"status": "error", "reason": "runtime_triage_incomplete"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    # This is an additive report, never a gate override.
    return 2 if report["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
