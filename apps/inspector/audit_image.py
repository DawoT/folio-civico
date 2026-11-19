"""Validate Trivy JSON and CycloneDX SBOM for the exact inspector image.

Only aggregate counts are emitted. A successful scan is NOT a security approval
when any CRITICAL, HIGH or UNKNOWN findings remain. No automatic suppressions.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

ALLOWED_SEVERITIES = frozenset(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"))
BLOCKING_SEVERITIES = frozenset(("CRITICAL", "HIGH", "UNKNOWN"))


def evaluate_image_audit(vulnerabilities: dict, sbom: dict, image: str) -> dict:
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

    blocked = any(counts[severity] > 0 for severity in BLOCKING_SEVERITIES)
    return {
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
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    try:
        scan = json.loads(args.vulnerabilities.read_text(encoding="utf-8"))
        sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
        result = evaluate_image_audit(scan, sbom, args.image)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        print(json.dumps({"status": "error", "reason": "image_scan_incomplete"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
