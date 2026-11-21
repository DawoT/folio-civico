"""Fail-closed scanner differential for an Expat 2.10.0 research rebuild.

A matched differential always returns status BLOCKED / exit 2. It measures
Trivy-visible differences without granting CVE remediation or release approval.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from audit_image import verify_native_source_inventory
from expat_runtime_inventory import SOURCE_SHA, PATCH_SHA, VERSION, TOOLS
from runtime_prune_comparison import _scan, _sbom

SOURCE = "folio-civico-inspector:poppler-experiment"
TARGET = "folio-civico-inspector:expat-experiment"
SOURCE_ID = "sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f"
SOURCE_EXPAT_VERSION = "2.9.0-1~deb13u1"
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
BLOCKING = frozenset(("CRITICAL", "HIGH", "UNKNOWN"))


def verify_delta(
    old_scan: dict, new_scan: dict, old_sbom: dict, new_sbom: dict,
    old_native: dict, new_native: dict, expat_native: dict,
    old_id: str, new_id: str,
) -> dict:
    if (old_id != SOURCE_ID or not isinstance(new_id, str)
            or not SHA.fullmatch(new_id) or old_id == new_id):
        raise ValueError("Parent and target immutable image identity required")

    old_v = _scan(old_scan, SOURCE)
    new_v = _scan(new_scan, TARGET)
    old_packages = _sbom(old_sbom, SOURCE, old_id)
    new_packages = _sbom(new_sbom, TARGET, new_id)

    original = [row for row in old_packages if row[1] == "libexpat1"]
    changed = [row for row in new_packages if row[1] == "libexpat1"]
    if (len(original) != 1 or len(changed) != 1
            or original[0][2] != SOURCE_EXPAT_VERSION
            or changed[0][2] != VERSION
            or old_packages[original[0]] != 1
            or new_packages[changed[0]] != 1):
        raise ValueError("Expat package version transition missing or inconsistent")
    old_other = Counter({k: v for k, v in old_packages.items()
                         if k[1] != "libexpat1"})
    new_other = Counter({k: v for k, v in new_packages.items()
                         if k[1] != "libexpat1"})
    if old_other != new_other:
        raise ValueError("Unexpected package inventory change")

    old_not_expat = Counter({k: v for k, v in old_v.items()
                             if k[1] != "libexpat1"})
    new_not_expat = Counter({k: v for k, v in new_v.items()
                             if k[1] != "libexpat1"})
    if old_not_expat != new_not_expat:
        raise ValueError("Unrelated advisory change or Trivy DB drift")
    if any(k[2] != SOURCE_EXPAT_VERSION for k in old_v if k[1] == "libexpat1"):
        raise ValueError("Old Expat CVEs mismatch installed package")
    if any(k[2] != VERSION for k in new_v if k[1] == "libexpat1"):
        raise ValueError("New Expat CVEs mismatch installed package")

    if (verify_native_source_inventory(old_native, SOURCE) != 2
            or verify_native_source_inventory(new_native, SOURCE) != 2
            or old_native != new_native):
        raise ValueError("Poppler or Tesseract native source identity changed")

    if (not isinstance(expat_native, dict)
            or expat_native.get("source") != "folio-expat-local-provenance-v1"
            or expat_native.get("package") != "libexpat1"
            or expat_native.get("package_version") != VERSION
            or expat_native.get("runtime_version") != "expat_2.10.0"
            or expat_native.get("source_sha256") != SOURCE_SHA
            or expat_native.get("patch_sha256") != PATCH_SHA
            or expat_native.get("native_cve_coverage") != "unassessed"
            or expat_native.get("linked_poppler_tools") != list(TOOLS)
            or expat_native.get("xmlwf_present") is not False
            or any(not isinstance(expat_native.get(key), str)
                   or not HEX.fullmatch(expat_native[key])
                   for key in ("library_sha256", "provenance_sha256"))):
        raise ValueError("Patched Expat ELF or provenance is unverified")

    old_count = Counter()
    new_count = Counter()
    for key, n in old_v.items():
        old_count[key[4]] += n
    for key, n in new_v.items():
        new_count[key[4]] += n
    old_cves = {(key[3], key[4]) for key in old_v if key[1] == "libexpat1"}
    new_cves = {(key[3], key[4]) for key in new_v if key[1] == "libexpat1"}
    blockers = sum(new_count[level] for level in BLOCKING)
    if blockers < 1:
        raise ValueError("No residual CVE visibility in experiment")
    return {
        "status": "measured_expat_transition_release_blocked",
        "source_image_id": old_id, "experimental_image_id": new_id,
        "expat_package_before": SOURCE_EXPAT_VERSION,
        "expat_package_after": VERSION,
        "other_packages_unchanged": True,
        "other_advisories_unchanged": True,
        "native_poppler_tesseract_hashes_unchanged": True,
        "expat_source_patch_and_runtime_elf_verified": True,
        "before_blocking": sum(old_count[x] for x in BLOCKING),
        "after_blocking": blockers,
        "before_high": old_count["HIGH"], "after_high": new_count["HIGH"],
        "before_unknown": old_count["UNKNOWN"], "after_unknown": new_count["UNKNOWN"],
        "expat_advisory_pairs_absent_from_new_scanner": sorted(old_cves - new_cves),
        "expat_advisory_pairs_new_in_scanner": sorted(new_cves - old_cves),
        "native_expat_cve_coverage_verified": False,
        "native_poppler_tesseract_cve_coverage_verified": False,
        "advisory_remediation_claimed": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    keys = ("old-scan", "new-scan", "old-sbom", "new-sbom",
            "old-native", "new-native", "expat-native")
    for key in keys:
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--old-id", required=True)
    parser.add_argument("--new-id", required=True)
    args = parser.parse_args()
    try:
        paths = [getattr(args, k.replace("-", "_")) for k in keys]
        if any(not p.is_file() or not 0 < p.stat().st_size <= 16 * 1024 * 1024
               for p in paths):
            raise ValueError("Missing or oversized scanner evidence")
        result = verify_delta(
            *(json.loads(p.read_text(encoding="utf-8")) for p in paths),
            args.old_id, args.new_id,
        )
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print(json.dumps({"status": "error", "release_authorized": False}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
