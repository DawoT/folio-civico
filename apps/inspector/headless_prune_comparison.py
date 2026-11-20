"""Strict differential CVE/SBOM proof for NON-DEPLOYABLE headless X11 pruning.

Reuses the R1.21 scan parsers; rejecting any other removed/added packages and
findings is essential to avoid mistaking disappearance of scanner coverage for
a security fix. Never authorizes a release.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from runtime_prune_comparison import _scan, _sbom

BASE = "folio-civico-inspector:runtime-pruned-experiment"
NEW = "folio-civico-inspector:headless-pruned-experiment"
REMOVED_PACKAGES = frozenset((
    "libcairo2", "libxext6", "libxrender1", "libx11-6", "libx11-data",
))
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


def compare_headless(
    before_scan: dict, after_scan: dict, before_sbom: dict, after_sbom: dict,
    before_id: str, after_id: str,
) -> dict:
    if (not isinstance(before_id, str) or not isinstance(after_id, str)
            or not DIGEST.fullmatch(before_id) or not DIGEST.fullmatch(after_id)
            or before_id == after_id):
        raise ValueError("Distinct immutable Docker image IDs required")
    a, b = _scan(before_scan, BASE), _scan(after_scan, NEW)
    source_packages = _sbom(before_sbom, BASE, before_id)
    target_packages = _sbom(after_sbom, NEW, after_id)
    deleted = source_packages - target_packages
    introduced = target_packages - source_packages

    if introduced:
        raise ValueError("Unexpected package introduced by headless pruning")
    deleted_names = {key[1] for key in deleted}
    if deleted_names != REMOVED_PACKAGES or any(
        key[1] not in REMOVED_PACKAGES for key in deleted
    ):
        raise ValueError("Expected X11/Cairo pruning differs from SBOM")
    if any(key[1] in REMOVED_PACKAGES for key in target_packages):
        raise ValueError("X11/Cairo runtime package retained")

    gone = a - b
    new = b - a
    if new or any(key[1] not in REMOVED_PACKAGES for key in gone):
        raise ValueError("Unrelated vulnerability findings changed unexpectedly")
    if any(key[1] in REMOVED_PACKAGES for key in b):
        raise ValueError("Removed X11 package still recorded as vulnerable")

    count_a: Counter[str] = Counter()
    count_b: Counter[str] = Counter()
    for key, n in a.items():
        count_a[key[4]] += n
    for key, n in b.items():
        count_b[key[4]] += n
    known_removed_high = {
        ("libx11-6", "CVE-2026-88806"),
        ("libx11-data", "CVE-2026-88806"),
        ("libxrender1", "CVE-2026-88807"),
    }
    gone_high = {
        (key[1], key[3]) for key in gone if key[4] == "HIGH"
    }
    if (gone_high != known_removed_high
            or any(count != 1 for key, count in gone.items()
                   if key[4] == "HIGH")
            or any(key[4] in ("CRITICAL", "UNKNOWN") for key in gone)):
        raise ValueError("Unexpected CRITICAL/HIGH/UNKNOWN removal in X11 pruning")
    eliminated_high = sum(n for key, n in gone.items() if key[4] == "HIGH")
    removed_medium = sum(n for key, n in gone.items() if key[4] == "MEDIUM")
    removed_low = sum(n for key, n in gone.items() if key[4] == "LOW")
    if eliminated_high != 3 or (
        count_a["CRITICAL"] != count_b["CRITICAL"]
        or count_a["UNKNOWN"] != count_b["UNKNOWN"]
        or count_a["HIGH"] - count_b["HIGH"] != eliminated_high
    ):
        raise ValueError("Unsupported vulnerability reduction or missing coverage")

    return {
        "status": "surface_reduced_release_blocked",
        "release_authorized": False,
        "scanner_gate": "blocked",
        "source_image": BASE, "source_image_id": before_id,
        "experimental_image": NEW, "experimental_image_id": after_id,
        "removed_packages": sorted(deleted_names),
        "removed_high": eliminated_high,
        "removed_medium": removed_medium,
        "removed_low": removed_low,
        "high_before": count_a["HIGH"], "high_after": count_b["HIGH"],
        "unknown_before": count_a["UNKNOWN"],
        "unknown_after": count_b["UNKNOWN"],
        "critical_before": count_a["CRITICAL"],
        "critical_after": count_b["CRITICAL"],
        "unapproved_package_changes": 0,
        "unapproved_vulnerability_changes": 0,
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
        report = compare_headless(
            json.loads(args.before_scan.read_text(encoding="utf-8")),
            json.loads(args.after_scan.read_text(encoding="utf-8")),
            json.loads(args.before_sbom.read_text(encoding="utf-8")),
            json.loads(args.after_sbom.read_text(encoding="utf-8")),
            args.before_id, args.after_id,
        )
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "error", "reason": "headless_prune_evidence_incomplete"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    # Release is forbidden irrespective of the observed row count.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
