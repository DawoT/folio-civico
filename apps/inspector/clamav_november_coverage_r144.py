"""R1.44: reconcile November ClamAV advisories with signed native bytes and Trivy.

The 2026-11-18 Talos release notes list ten CVEs addressed in ClamAV 1.5.5:
https://blog.clamav.net/2026/11/clamav-155-147-security-patch-release.html
https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-multi-e93M3vdA

This is a curated public advisory snapshot, not automatically signed advisory
metadata, a CVE-specific source-code audit, a VEX or a release gate override.
The only successful outcome is exit 2 / release blocked.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from clamav_runtime_inventory import VERSION
from clamav_signed_gate import CVES, MEDIUM_CVES, NATIVE_REQUIRED, _signed_files
from clamav_vendor_evidence import TALOS_FINGERPRINT
from runtime_prune_comparison import _scan, _sbom

IMAGE = "folio-civico-inspector:expat-experiment"
IMAGE_ID = "sha256:3447fed5e20f4c7f31110403738ffba08ab6b203141cea1b2158f60ef3ed5731"
JULY_CVES = tuple(CVES)
NOVEMBER_CVES = (
    "CVE-2026-76411", "CVE-2026-76414", "CVE-2026-76415",
    "CVE-2026-76416", "CVE-2026-76417", "CVE-2026-76421",
    "CVE-2026-76422", "CVE-2026-76430", "CVE-2026-76515",
    "CVE-2026-76516",
)
SEVERITIES = frozenset(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"))
SHA = re.compile(r"[a-f0-9]{64}\Z")
MAX_JSON_BYTES = 16 * 1024 * 1024


def review_clamav_coverage(
    scan: dict, sbom: dict, vendor: dict, runtime: dict, image_id: str,
) -> dict:
    if image_id != IMAGE_ID:
        raise ValueError("Exact R1.43 research Docker ID is required")
    if (len(set(NOVEMBER_CVES)) != 10
            or set(NOVEMBER_CVES) & set(JULY_CVES)):
        raise ValueError("November advisory corpus is inconsistent")

    scan_rows = _scan(scan, IMAGE)
    inventory = _sbom(sbom, IMAGE, image_id)
    packages = [
        (name, version, count)
        for (_, name, version, _), count in inventory.items()
        if name == "clamav"
    ]
    if packages != [("clamav", VERSION, 1)]:
        raise ValueError("ClamAV CycloneDX Debian package changed")
    if not any(key[0] == "operating-system" and key[1] == "debian"
               for key in inventory):
        raise ValueError("Debian OS SBOM identity is missing")

    scanner_entries = {}
    severity_counts = Counter()
    for (kind, package, version, cve, severity), n in scan_rows.items():
        if (kind == "debian" and package == "clamav"):
            if version != VERSION or not cve.startswith("CVE-") or n != 1:
                raise ValueError("Duplicate or malformed ClamAV scan record")
            if cve in scanner_entries:
                raise ValueError("Conflicting scanner entries for the same CVE")
            scanner_entries[cve] = severity
        severity_counts[severity] += n
    if sum(severity_counts[x] for x in ("CRITICAL", "HIGH", "UNKNOWN")) < 1:
        raise ValueError("Incomplete scanner block coverage")
    if any(scanner_entries.get(cve) != "HIGH" for cve in JULY_CVES):
        raise ValueError("Previously reported July HIGH CVE lost from scanner")
    if any(scanner_entries.get(cve) != "MEDIUM" for cve in MEDIUM_CVES):
        raise ValueError("Previously reported July MEDIUM CVE lost from scanner")

    if (not isinstance(vendor, dict)
            or vendor.get("source") != "talos-detached-debian-package-v1"
            or vendor.get("signature_verified") is not True
            or vendor.get("signer_fingerprint") != TALOS_FINGERPRINT
            or vendor.get("package") != "clamav"
            or vendor.get("package_version") != VERSION
            or vendor.get("architecture") != "amd64"
            or vendor.get("vendor_patched_floor") != "1.5.3"
            or vendor.get("release_authorized") is not False
            or not isinstance(vendor.get("signed_deb_sha256"), str)
            or not SHA.fullmatch(vendor["signed_deb_sha256"])):
        raise ValueError("Talos signed package integrity claim is incomplete")
    if (not isinstance(runtime, dict)
            or runtime.get("source") != "folio-clamav-installed-native-v1"
            or runtime.get("package") != "clamav"
            or runtime.get("package_version") != VERSION
            or runtime.get("architecture") != "amd64"
            or runtime.get("clamscan_version") != "ClamAV 1.5.5"
            or runtime.get("dpkg_verify_clean") is not True
            or runtime.get("shared_library_linked") is not True
            or runtime.get("release_authorized") is not False):
        raise ValueError("Installed ClamAV runtime is not independently verified")

    vendor_files = _signed_files(vendor.get("files"))
    installed_files = _signed_files(runtime.get("files"))
    if vendor_files != installed_files:
        raise ValueError("Installed native code differs from Talos signed .deb")
    if not set(NATIVE_REQUIRED).issubset({x["path"] for x in vendor_files}):
        raise ValueError("Vendor package lacks ClamAV scanner/core native code")

    # The seven historical July findings are tied to Debian's clamav package,
    # but visibility of a November CVE must be checked across the WHOLE image.
    # Trivy may attribute the same advisory to a different package/ecosystem.
    nov_locations = sorted(
        [
            {"id": cve, "severity": severity, "kind": kind,
             "package": package, "version": version, "occurrences": count}
            for (kind, package, version, cve, severity), count in scan_rows.items()
            if cve in NOVEMBER_CVES
        ],
        key=lambda row: (row["id"], row["kind"], row["package"],
                         row["version"], row["severity"]),
    )
    nov_reported = [
        {"id": cve, "severity": severity}
        for cve, severity in sorted({
            (row["id"], row["severity"]) for row in nov_locations
        })
    ]
    nov_absent = sorted(set(NOVEMBER_CVES) -
                        {row["id"] for row in nov_locations})
    return {
        "status": "talos_november_coverage_measured_release_blocked",
        "image_id": image_id,
        "clamav_package_version": VERSION,
        "vendor_release_claim_fixed_in": "1.5.5",
        "vendor_advisory_published": "2026-11-18",
        "vendor_advisory_ids": list(NOVEMBER_CVES),
        "november_vendor_cve_total": len(NOVEMBER_CVES),
        "november_reported_by_trivy": nov_reported,
        "november_reported_locations": nov_locations,
        "november_not_reported_by_trivy": nov_absent,
        "july_still_reported_high": sorted(JULY_CVES),
        "vendor_signed_file_hashes_match": True,
        "talos_detached_signature_verified": True,
        "native_files_measured": len(vendor_files),
        "scanner_critical": severity_counts["CRITICAL"],
        "scanner_high": severity_counts["HIGH"],
        "scanner_unknown": severity_counts["UNKNOWN"],
        "scanner_blocking": sum(severity_counts[x] for x in
                                ("CRITICAL", "HIGH", "UNKNOWN")),
        "scanner_package_cve_entries": len(scanner_entries),
        "vendor_advisory_applicability_reviewed_by_owner": False,
        "november_cve_binary_patch_proven": False,
        "vex_issued": False,
        "no_scanner_entry_is_not_a_vex": True,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for item in ("scan", "sbom", "vendor", "runtime"):
        parser.add_argument("--" + item, type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    try:
        names = [args.scan, args.sbom, args.vendor, args.runtime]
        if any(not path.is_file() or not 0 < path.stat().st_size <= MAX_JSON_BYTES
               for path in names):
            raise ValueError("Missing, oversized or empty evidence")
        result = review_clamav_coverage(
            *(json.loads(path.read_text(encoding="utf-8")) for path in names),
            args.image_id,
        )
    except (OSError, ValueError, TypeError, AttributeError, KeyError, UnicodeError):
        print(json.dumps({"status": "error", "release_authorized": False}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
