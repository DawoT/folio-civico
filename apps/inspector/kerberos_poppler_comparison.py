"""Fail-closed differential Trivy/SBOM comparison for a Poppler research image.

Not a CVE remediation claim or VEX. The source-built Poppler disappears from
Debian package records and its vulnerability coverage remains UNVERIFIED.
Audits must independently use the exact local Docker IDs and one Trivy DB
snapshot. Every successful comparison still returns the blocked exit code 2.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from runtime_prune_comparison import _scan, _sbom

BASE = "folio-civico-inspector:ocr-integrated"
EXPERIMENT = "folio-civico-inspector:poppler-experiment"
REMOVED_PACKAGES = frozenset({
    "poppler-utils", "libpoppler147", "libcurl3t64-gnutls",
    "libgssapi-krb5-2", "libk5crypto3", "libkrb5-3",
    "libkrb5support0",
})
KERBEROS_PACKAGES = frozenset({
    "libgssapi-krb5-2", "libk5crypto3", "libkrb5-3", "libkrb5support0",
})
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOCKING = frozenset(("CRITICAL", "HIGH", "UNKNOWN"))


def compare_poppler_cve_surface(
    base_scan: dict, experiment_scan: dict,
    base_sbom: dict, experiment_sbom: dict,
    base_id: str, experiment_id: str,
) -> dict:
    """Measure removal; never reinterpret reduced scanner visibility as safety."""
    if (not isinstance(base_id, str) or not isinstance(experiment_id, str)
            or not IMAGE_ID.fullmatch(base_id)
            or not IMAGE_ID.fullmatch(experiment_id)
            or base_id == experiment_id):
        raise ValueError("Distinct immutable candidate and experiment IDs required")

    old = _scan(base_scan, BASE)
    new = _scan(experiment_scan, EXPERIMENT)
    old_packages = _sbom(base_sbom, BASE, base_id)
    new_packages = _sbom(experiment_sbom, EXPERIMENT, experiment_id)
    packages_gone = old_packages - new_packages
    packages_new = new_packages - old_packages
    if packages_new:
        raise ValueError("Unapproved new package introduced by Poppler rebuild")
    removed_names = {row[1] for row in packages_gone}
    if removed_names != REMOVED_PACKAGES or any(
        row[1] not in REMOVED_PACKAGES or count != 1
        for row, count in packages_gone.items()
    ):
        raise ValueError("Unexpected exact Debian package removal")
    if any(row[1] in REMOVED_PACKAGES for row in new_packages):
        raise ValueError("A supposedly removed Debian package remains")

    lost = old - new
    added = new - old
    if added:
        raise ValueError("New or changed Trivy vulnerability in experiment")
    if any(row[1] not in REMOVED_PACKAGES for row in lost):
        raise ValueError("Unrelated existing vulnerability silently disappeared")
    if any(row[1] in REMOVED_PACKAGES for row in new):
        raise ValueError("Removed package still has scanner vulnerability records")

    before_sev = Counter()
    after_sev = Counter()
    removed_by_package: Counter[str] = Counter()
    for row, count in old.items():
        before_sev[row[4]] += count
    for row, count in new.items():
        after_sev[row[4]] += count
    for row, count in lost.items():
        if row[4] == "HIGH":
            removed_by_package[row[1]] += count

    removed_high = sum(removed_by_package.values())
    if (removed_high < 1
            or sum(after_sev.get(level, 0) for level in BLOCKING) < 1):
        raise ValueError("No observed reduction or incomplete residual-CVE scan")
    if sum(before_sev.get(s, 0) - after_sev.get(s, 0) for s in BLOCKING) != sum(
        n for row, n in lost.items() if row[4] in BLOCKING
    ):
        raise ValueError("Discrepant blocking finding counters")

    return {
        "status": "scanner_visible_surface_reduced_release_blocked",
        "candidate_image_id": base_id,
        "experiment_image_id": experiment_id,
        "removed_debian_packages": sorted(REMOVED_PACKAGES),
        "removed_high_by_package": dict(sorted(removed_by_package.items())),
        "removed_high_kerberos": sum(removed_by_package.get(p, 0)
                                     for p in KERBEROS_PACKAGES),
        "removed_high_total": removed_high,
        "candidate_blocking": sum(before_sev.get(level, 0) for level in BLOCKING),
        "experiment_blocking": sum(after_sev.get(level, 0) for level in BLOCKING),
        "experiment_unknown": after_sev.get("UNKNOWN", 0),
        "new_scanner_findings": 0,
        "unapproved_package_changes": 0,
        "unapproved_vulnerability_changes": 0,
        "poppler_native_cve_coverage_verified": False,
        "tesseract_native_cve_coverage_verified": False,
        "scanner_records_missing_source_built_poppler": True,
        "cve_remediation_claimed": False,
        "release_authorized": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("base-scan", "experiment-scan", "base-sbom", "experiment-sbom"):
        p.add_argument("--" + key, required=True, type=Path)
    p.add_argument("--base-id", required=True)
    p.add_argument("--experiment-id", required=True)
    args = p.parse_args()
    try:
        sources = [
            args.base_scan, args.experiment_scan,
            args.base_sbom, args.experiment_sbom,
        ]
        if any(not x.is_file() or not 0 < x.stat().st_size <= 16 * 1024 * 1024
               for x in sources):
            raise ValueError("Missing or oversized immutable evidence")
        result = compare_poppler_cve_surface(
            *(json.loads(x.read_text(encoding="utf-8")) for x in sources),
            args.base_id, args.experiment_id,
        )
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print(json.dumps({"status": "error", "release_authorized": False}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
