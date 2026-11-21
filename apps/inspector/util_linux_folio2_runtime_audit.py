"""R1.47: fail-closed evidence for locally patched, UNSIGNED Debian util-linux.

Eight versioned quilt packages are installed only in a disposable research OCI.
This gate does NOT suppress CVEs, issue VEX, prove exploit resistance or
authorize any deployment. Valid evidence exits 2, malformed evidence exits 3.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from urllib.parse import quote

from audit_image import verify_native_source_inventory
from gnupg_flat_prune_comparison import EMPTY_LAYER, CONFIG_FIELDS
from runtime_prune_comparison import DIGEST, _scan, _sbom
from util_linux_folio2_binary import SOURCE_HASHES, SOURCE_VERSION
from util_linux_folio2_cve_regression import REQUIRED_CVES

BASE = "folio-civico-inspector:surface-pruned-research-r146"
NEW = "folio-civico-inspector:folio2-runtime-research-r147"
BASE_ID = (
    "sha256:c0011755a54a4af8c749ef60a2d0f40be5a186dbb071ea19d760e34a7d8360ee"
)
EXPECTED_VERSIONS = {
    name: SOURCE_VERSION for name in (
        "util-linux", "libblkid1", "liblastlog2-2",
        "libmount1", "libsmartcols1", "libuuid1",
    )
}
EXPECTED_VERSIONS["bsdutils"] = "1:" + SOURCE_VERSION
EXPECTED_VERSIONS["login"] = "1:4.16.0-2+really" + SOURCE_VERSION
BASE_VERSIONS = {
    name: (
        "1:4.16.0-2+really2.41.5-0+deb13u1" if name == "login" else
        "1:2.41.5-0+deb13u1" if name == "bsdutils" else
        "2.41.5-0+deb13u1"
    )
    for name in EXPECTED_VERSIONS
}
CHANGED = frozenset(EXPECTED_VERSIONS)
CVES = frozenset((
    "CVE-2026-76642", "CVE-2026-78408",
    "CVE-2026-78409", "CVE-2026-78410",
))
assert CVES == frozenset(REQUIRED_CVES)
MAX_FILE_BYTES = 20 * 1024 * 1024


def _validate_sbom_versions(bom: Counter, versions: dict[str, str]) -> None:
    for name, wanted in versions.items():
        entries = [
            (kind, version, purl, count) for (kind, pkg, version, purl), count in bom.items()
            if pkg == name
        ]
        if len(entries) != 1:
            raise ValueError("Expected exactly one util-linux package per SBOM")
        kind, version, purl, count = entries[0]
        expected = (
            "pkg:deb/debian/" + name + "@" +
            quote(wanted.split(":")[-1], safe="~") +
            "?arch=amd64&distro=debian-13.7" +
            ("&epoch=1" if wanted.startswith("1:") else "")
        )
        if (kind != "library" or version != wanted or purl != expected
                or count != 1):
            raise ValueError("Versioned quilt package or PURL does not match")


def _normalized_scan(scan: Counter) -> Counter:
    normalized: Counter = Counter()
    for (kind, package, version, cve, severity), count in scan.items():
        if package in CHANGED:
            version = "<util-linux-verified-version>"
        normalized[(kind, package, version, cve, severity)] += count
    return normalized


def _source_paths(source: dict) -> None:
    if (not isinstance(source, dict)
            or source.get("source_version") != SOURCE_VERSION
            or source.get("source_handoff_validated") is not True
            or source.get("source_sha256") != SOURCE_HASHES
            or source.get("source_cve_paths_accounted_for") is not True
            or source.get("unresolved_cve_paths") != []
            or source.get("source_scope_not_applicable") != ["CVE-2026-78409"]
            or source.get("runtime_cve_regressions_passed") is not False
            or source.get("cve_remediated") is not False
            or source.get("release_authorized") is not False):
        raise ValueError("Unsigned source gate missing or claims a release")
    records = source.get("cve_guard_results")
    if not isinstance(records, dict) or set(records) != CVES:
        raise ValueError("Incomplete four-CVE source path verification")
    for cve in CVES:
        row = records[cve]
        if not isinstance(row, dict) or row.get("source_guard_present") is not (
            cve != "CVE-2026-78409"
        ):
            raise ValueError("Security guard evidence does not match folio2")
        if cve == "CVE-2026-78409" and (
            row.get("applicability") != "not_affected_detached_fast_path_absent"
            or row.get("legacy_restricted_user_path_rejected") is not True
            or row.get("affected_detached_fast_path_present") is not False
        ):
            raise ValueError("Missing restricted-user path proof for CVE-2026-78409")


def _verify_oci(before: dict, after: dict, before_id: str, after_id: str) -> None:
    if before_id != BASE_ID or not isinstance(after_id, str) or (
        not DIGEST.fullmatch(after_id) or after_id == before_id
    ):
        raise ValueError("Image IDs not pinned to R1.46 and distinct research output")
    for record, image_id in ((before, before_id), (after, after_id)):
        if not isinstance(record, dict) or record.get("Id") != image_id:
            raise ValueError("Docker inspection does not match immutable ID")
        fs, config = record.get("RootFS"), record.get("Config")
        if not isinstance(fs, dict) or not isinstance(config, dict):
            raise ValueError("Malformed Docker metadata")
        layers = fs.get("Layers")
        if (fs.get("Type") != "layers" or not isinstance(layers, list)
                or len(layers) != 2 or layers.count(EMPTY_LAYER) != 1
                or any(not isinstance(x, str) or not DIGEST.fullmatch(x)
                       for x in layers)):
            raise ValueError("Research image is not scratch-flattened")
    b, a = before["Config"], after["Config"]
    if (any(b.get(field) != a.get(field) for field in CONFIG_FIELDS)
            or a.get("User") != "65534:65534"
            or a.get("Cmd") != ["python3", "-I", "/srv/folio-inspector/inspector.py"]
            or a.get("Entrypoint") is not None):
        raise ValueError("Operational container identity has changed")
    before_layers = set(before["RootFS"]["Layers"]) - {EMPTY_LAYER}
    after_layers = set(after["RootFS"]["Layers"]) - {EMPTY_LAYER}
    if before_layers & after_layers:
        raise ValueError("Inherited historical OCI layer retains old packages")


def compare_folio2_runtime(
    before_scan: dict, after_scan: dict, before_sbom: dict, after_sbom: dict,
    before_id: str, after_id: str, before_inspect: dict, after_inspect: dict,
    before_native: dict, after_native: dict, source_report: dict,
    before_privileges: dict, after_privileges: dict,
) -> dict:
    _verify_oci(before_inspect, after_inspect, before_id, after_id)
    _source_paths(source_report)

    if (not isinstance(before_privileges, dict) or not before_privileges
            or before_privileges != after_privileges):
        raise ValueError("Potential newly elevated executable privileges")
    if (not isinstance(before_native, dict)
            or before_native != after_native):
        raise ValueError("Unrelated Poppler/Tesseract/ocr-model bytes changed")
    verify_native_source_inventory(before_native, "folio-civico-inspector:poppler-experiment")
    verify_native_source_inventory(after_native, "folio-civico-inspector:poppler-experiment")

    sbom_a, sbom_b = (
        _sbom(before_sbom, BASE, before_id), _sbom(after_sbom, NEW, after_id)
    )
    _validate_sbom_versions(sbom_a, BASE_VERSIONS)
    _validate_sbom_versions(sbom_b, EXPECTED_VERSIONS)
    if ({key: n for key, n in sbom_a.items() if key[1] not in CHANGED}
            != {key: n for key, n in sbom_b.items() if key[1] not in CHANGED}):
        raise ValueError("Unexpected package introduced or modified")

    scan_a, scan_b = _scan(before_scan, BASE), _scan(after_scan, NEW)
    if _normalized_scan(scan_a) != _normalized_scan(scan_b):
        raise ValueError("A vulnerability appeared or silently disappeared")
    # Do NOT classify the 2.41.6 Debian scanner state as patched or waived:
    # Trixie still lists all four advisories for all eight source packages.
    for scan in (scan_a, scan_b):
        for package in CHANGED:
            for cve in CVES:
                if sum(n for (_, p, _, found_id, sev), n in scan.items()
                       if p == package and found_id == cve and sev == "HIGH") != 1:
                    raise ValueError("Required unresolved util-linux CVE was hidden")

    counts_a = Counter()
    counts_b = Counter()
    for key, n in scan_a.items():
        counts_a[key[4]] += n
    for key, n in scan_b.items():
        counts_b[key[4]] += n
    if any(counts_a[sev] != counts_b[sev]
           for sev in ("HIGH", "CRITICAL", "UNKNOWN", "MEDIUM", "LOW")):
        raise ValueError("Trivy counts changed outside tracked package upgrades")
    return {
        "status": "unsigned_folio2_integrated_runtime_research_release_blocked",
        "source_image": BASE,
        "source_image_id": before_id,
        "experimental_image": NEW,
        "experimental_image_id": after_id,
        "source_version": SOURCE_VERSION,
        "updated_package_count": len(CHANGED),
        "updated_packages": sorted(CHANGED),
        "source_security_guards_present": sorted(CVES - {"CVE-2026-78409"}),
        "source_scope_conflict_with_debian": ["CVE-2026-78409"],
        "util_high_before": len(CHANGED) * len(CVES),
        "util_high_after": len(CHANGED) * len(CVES),
        "high_before": counts_a["HIGH"],
        "high_after": counts_b["HIGH"],
        "unknown_before": counts_a["UNKNOWN"],
        "unknown_after": counts_b["UNKNOWN"],
        "critical_after": counts_b["CRITICAL"],
        "nonempty_base_layers_reused": 0,
        "new_privileged_paths": 0,
        "source_elf_identity": "unchanged",
        "unexpected_package_changes": 0,
        "unrelated_vulnerability_drift": 0,
        "runtime_cve_exploit_regression": "not_executed",
        "vex": "not_issued",
        "vendor_release_signed": False,
        "cve_remediated": False,
        "scanner_gate": "blocked",
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    keys = (
        "before-scan", "after-scan", "before-sbom", "after-sbom",
        "before-inspect", "after-inspect", "before-native", "after-native",
        "source-report", "before-privileges", "after-privileges",
    )
    for key in keys:
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--before-id", required=True)
    parser.add_argument("--after-id", required=True)
    args = parser.parse_args()
    try:
        values = []
        for key in keys:
            path = getattr(args, key.replace("-", "_"))
            if not path.is_file() or not 0 < path.stat().st_size <= MAX_FILE_BYTES:
                raise ValueError("Unverified source or oversized scan evidence")
            values.append(json.loads(path.read_text(encoding="utf-8")))
        report = compare_folio2_runtime(
            *values[:4], args.before_id, args.after_id, *values[4:]
        )
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print(json.dumps({"status": "error", "release_authorized": False}))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
