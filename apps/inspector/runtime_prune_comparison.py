"""Differential, fail-closed Trivy/SBOM check for an isolated runtime-pruning experiment.

This is an evidence check, not an allowlist, VEX or release gate. It rejects any
unexpected change and exits 2 even if the differential scan is clean.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

OLD = "folio-civico-inspector:expat-experiment"
NEW = "folio-civico-inspector:runtime-pruned-experiment"
REMOVED_PACKAGES = frozenset((
    "dirmngr", "gnupg", "gnupg-l10n", "gpg", "gpg-agent", "gpgconf",
    "gpgsm", "libgpgme11t64", "libgpgmepp6t64",
))
SEVERITIES = frozenset(("CRITICAL", "HIGH", "UNKNOWN", "MEDIUM", "LOW"))
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


def _scan(scan: dict, image: str) -> Counter:
    if (not isinstance(scan, dict) or scan.get("ArtifactName") != image
            or scan.get("ArtifactType") != "container_image"):
        raise ValueError("Trivy vulnerability scan image identity mismatch")
    rows = scan.get("Results")
    if not isinstance(rows, list) or not rows or not any(
        isinstance(row, dict) and row.get("Type") == "debian" for row in rows
    ):
        raise ValueError("Missing Debian OS scan coverage")
    result: Counter = Counter()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("Target"), str):
            raise ValueError("Invalid Trivy scan target")
        vulnerabilities = row.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy vulnerability section malformed")
        for item in vulnerabilities:
            if (not isinstance(item, dict)
                    or item.get("Severity") not in SEVERITIES
                    or not isinstance(item.get("PkgName"), str)
                    or not item["PkgName"]
                    or not isinstance(item.get("InstalledVersion"), str)
                    or not item["InstalledVersion"]
                    or not isinstance(item.get("VulnerabilityID"), str)
                    or not item["VulnerabilityID"]):
                raise ValueError("Invalid Trivy vulnerability record")
            key = (
                row.get("Type"), item["PkgName"], item["InstalledVersion"],
                item["VulnerabilityID"], item["Severity"],
            )
            result[key] += 1
    return result


def _sbom(bom: dict, image: str, digest: str) -> Counter:
    if (not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX"):
        raise ValueError("CycloneDX package inventory missing")
    metadata = bom.get("metadata")
    main = metadata.get("component") if isinstance(metadata, dict) else None
    if (not isinstance(main, dict) or main.get("name") != image
            or main.get("type") != "container"):
        raise ValueError("CycloneDX container identity mismatch")
    props = main.get("properties")
    if not isinstance(props, list) or [
        row.get("value") for row in props if isinstance(row, dict)
        and row.get("name") == "aquasecurity:trivy:ImageID"
    ] != [digest]:
        raise ValueError("CycloneDX immutable image ID mismatch")
    packages = bom.get("components")
    if not isinstance(packages, list) or not packages:
        raise ValueError("Missing CycloneDX packages")
    result: Counter = Counter()
    for comp in packages:
        if not isinstance(comp, dict):
            raise ValueError("Malformed SBOM component")
        if (comp.get("type") == "operating-system" and comp.get("name") == "debian"
                and isinstance(comp.get("version"), str)
                and comp["version"] and comp.get("purl") is None):
            # Trivy CycloneDX 1.7 records Debian OS with no purl.
            key = ("operating-system", "debian", comp["version"], "")
        elif (not isinstance(comp.get("name"), str) or not comp["name"]
                or not isinstance(comp.get("version"), str)
                or not comp["version"]
                or not isinstance(comp.get("purl"), str)
                or not comp["purl"]):
            raise ValueError("Malformed SBOM package")
        else:
            key = (comp.get("type"), comp["name"], comp["version"], comp["purl"])
        result[key] += 1
    return result


def compare_images(
    before_scan: dict, after_scan: dict, before_sbom: dict, after_sbom: dict,
    before_id: str, after_id: str,
) -> dict:
    if (not isinstance(before_id, str) or not isinstance(after_id, str)
            or not DIGEST.fullmatch(before_id) or not DIGEST.fullmatch(after_id)
            or before_id == after_id):
        raise ValueError("Distinct immutable image identities required")
    a = _scan(before_scan, OLD)
    b = _scan(after_scan, NEW)
    sbom_a = _sbom(before_sbom, OLD, before_id)
    sbom_b = _sbom(after_sbom, NEW, after_id)

    deleted_components = sbom_a - sbom_b
    introduced_components = sbom_b - sbom_a
    if introduced_components:
        raise ValueError("New SBOM package in reduced runtime")
    removed_names = {key[1] for key in deleted_components}
    if removed_names != REMOVED_PACKAGES or any(
        key[1] not in REMOVED_PACKAGES for key in deleted_components
    ):
        raise ValueError("Pruning deleted unexpected packages or missed the intended set")
    if any(key[1] in REMOVED_PACKAGES for key in sbom_b):
        raise ValueError("Disallowed GnuPG package remains in runtime")

    eliminated = a - b
    created = b - a
    if created:
        raise ValueError("New or altered CVE entries in pruned runtime")
    if any(key[1] not in REMOVED_PACKAGES for key in eliminated):
        raise ValueError("An unrelated CVE entry vanished from runtime")
    if any(key[1] in REMOVED_PACKAGES for key in b):
        raise ValueError("Removed package still has CVE entries")

    # Count remains explicit; no allowed alerts are automatically considered
    # fixed/nonexploitable. The observed reduction must be real and attributable.
    removed_high = sum(n for key, n in eliminated.items() if key[4] == "HIGH")
    if removed_high < 1:
        raise ValueError("No measured high-severity reduction")
    counts_a = Counter()
    counts_b = Counter()
    for key,n in a.items():
        counts_a[key[4]] += n
    for key,n in b.items():
        counts_b[key[4]] += n
    if (counts_b["CRITICAL"] != counts_a["CRITICAL"]
            or counts_b["UNKNOWN"] != counts_a["UNKNOWN"]):
        raise ValueError("Unaccounted CRITICAL/UNKNOWN changes")

    return {
        "status": "surface_reduced_release_blocked",
        "release_authorized": False,
        "source_image": OLD, "source_image_id": before_id,
        "experimental_image": NEW, "experimental_image_id": after_id,
        "removed_packages": sorted(removed_names),
        "removed_high": removed_high,
        "high_before": counts_a["HIGH"], "high_after": counts_b["HIGH"],
        "critical_before": counts_a["CRITICAL"],
        "critical_after": counts_b["CRITICAL"],
        "unknown_before": counts_a["UNKNOWN"],
        "unknown_after": counts_b["UNKNOWN"],
        "unapproved_package_changes": 0,
        "unapproved_vulnerability_changes": 0,
        "scanner_gate": "blocked",
        "vex": "not_issued",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("before-scan", "after-scan", "before-sbom", "after-sbom"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--before-id", required=True)
    parser.add_argument("--after-id", required=True)
    args = parser.parse_args()
    try:
        report = compare_images(
            json.loads(args.before_scan.read_text(encoding="utf-8")),
            json.loads(args.after_scan.read_text(encoding="utf-8")),
            json.loads(args.before_sbom.read_text(encoding="utf-8")),
            json.loads(args.after_sbom.read_text(encoding="utf-8")),
            args.before_id, args.after_id,
        )
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "error", "reason": "runtime_pruning_evidence_incomplete"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    # Never confer a release. The original Expat and Poppler CVEs are unresolved.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
