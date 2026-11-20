"""Fail-closed R1.27 comparator: ClamAV CLI permissions, signed code, CVE.

No package mutation or CVE suppression. The original image is independently
attested against the official signed Talos .deb, and all compiled native bytes
are remeasured in both images. A good comparison still exits 2 (no release).
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from clamav_cli_surface import CLI_PATHS, DENY, KEEP, PACKAGE_VERSION, SOURCE
from clamav_signed_gate import verify_signed_vendor_evidence
from runtime_prune_comparison import _scan, _sbom

BEFORE = "folio-civico-inspector:nonprivileged-experiment"
AFTER = "folio-civico-inspector:clamav-cli-limited-experiment"
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
HASH = re.compile(r"^[a-f0-9]{64}$")
EMPTY = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
CONFIG_FIELDS = (
    "User", "Cmd", "Entrypoint", "WorkingDir", "ExposedPorts", "Volumes",
    "Healthcheck", "StopSignal", "Env",
)


def _image(meta: object, *, child: bool) -> tuple[str, dict, set[str]]:
    if (not isinstance(meta, dict)
            or not isinstance(meta.get("Id"), str)
            or not DIGEST.fullmatch(meta["Id"])
            or meta.get("Os") != "linux"
            or meta.get("Architecture") != "amd64"):
        raise ValueError("Immutable architecture-pinned Docker image required")
    layers = meta.get("RootFS", {}).get("Layers") if isinstance(
        meta.get("RootFS"), dict
    ) else None
    if (not isinstance(layers, list) or len(layers) != 2
            or layers.count(EMPTY) != 1
            or not all(isinstance(v, str) and DIGEST.fullmatch(v)
                       for v in layers)):
        raise ValueError("Expected flattened two-layer OCI filesystem")
    config = meta.get("Config")
    if (not isinstance(config, dict)
            or config.get("User") != "65534:65534"
            or config.get("Cmd") != [
                "python3", "-I", "/srv/folio-inspector/inspector.py"
            ]):
        raise ValueError("Inspector runtime/user identity changed")
    return meta["Id"], config, set(layers)


def _surface(report: object, *, after: bool) -> dict[str, str]:
    if (not isinstance(report, dict) or set(report) != {
        "source", "scan_complete", "state", "package",
        "package_version", "absent", "files"
    } or report.get("source") != SOURCE
            or report.get("scan_complete") is not True
            or report.get("package") != "clamav"
            or report.get("package_version") != PACKAGE_VERSION
            or report.get("state") != ("limited" if after else "baseline")
            or report.get("absent") != (sorted(DENY) if after else [])):
        raise ValueError("ClamAV CLI deletion inventory untrusted")
    files = report["files"]
    expected = [KEEP] if after else list(CLI_PATHS)
    if (not isinstance(files, list) or len(files) != len(expected)
            or any(not isinstance(x, dict) for x in files)
            or [x.get("path") for x in files] != expected):
        raise ValueError("Expected ClamAV CLI files were not exactly present")
    digests: dict[str, str] = {}
    for x in files:
        path = x["path"]
        if (set(x) != {"path", "mode", "uid", "sha256"}
                or x.get("mode") != "0755"
                or x.get("uid") != 0
                or not isinstance(x.get("sha256"), str)
                or not HASH.fullmatch(x["sha256"])):
            raise ValueError("ClamAV CLI mode, owner or hash is incorrect")
        digests[path] = x["sha256"]
    return digests


def verify_cli_reduction(
    source_scan: dict, target_scan: dict,
    source_sbom: dict, target_sbom: dict,
    source_inspect: dict, target_inspect: dict,
    source_cli: dict, target_cli: dict,
    source_native: dict, target_native: dict,
    talos_vendor: dict,
) -> dict:
    before_id, before_config, before_layers = _image(source_inspect, child=False)
    after_id, after_config, after_layers = _image(target_inspect, child=True)
    if before_id == after_id or (before_layers & after_layers) - {EMPTY}:
        raise ValueError("Images share historical nonempty rootfs layers")
    if any(before_config.get(key) != after_config.get(key)
           for key in CONFIG_FIELDS):
        raise ValueError("Inspected command/user/Env/network metadata changed")

    before_cve = _scan(source_scan, BEFORE)
    after_cve = _scan(target_scan, AFTER)
    if before_cve != after_cve:
        raise ValueError("Vulnerability visibility changed without a package fix")
    before_packages = _sbom(source_sbom, BEFORE, before_id)
    after_packages = _sbom(target_sbom, AFTER, after_id)
    if before_packages != after_packages:
        raise ValueError("CycloneDX package inventory changed without permission")

    # This validation checks GPG signer identity, seven HIGH and six MEDIUM
    # CVEs against the original image, and EVERY hashed native file against
    # Cisco Talos-signed upstream package.
    source_report = verify_signed_vendor_evidence(
        source_scan, source_sbom, talos_vendor, source_native, before_id
    )
    if not source_report.get("native_binary_sha256_match") or (
        source_report.get("scanner_gate") != "blocked"
    ):
        raise ValueError("Original signed vendor provenance was not established")
    if not isinstance(target_native, dict) or set(target_native) != {
        "source", "package", "package_version", "architecture",
        "clamscan_version", "expected_absent",
        "dpkg_verified_expected_removals", "shared_library_linked",
        "files", "release_authorized",
    } or any((
        target_native.get("source") != "folio-clamav-minimal-native-v1",
        target_native.get("package") != "clamav",
        target_native.get("package_version") != PACKAGE_VERSION,
        target_native.get("architecture") != "amd64",
        target_native.get("clamscan_version") != "ClamAV 1.5.5",
        target_native.get("expected_absent") != sorted(DENY),
        target_native.get("dpkg_verified_expected_removals") is not True,
        target_native.get("shared_library_linked") is not True,
        target_native.get("release_authorized") is not False,
    )):
        raise ValueError("Minimal ClamAV package changes not verified by dpkg")
    expected_native = [
        row for row in source_native["files"]
        if row["path"] not in DENY
    ]
    if target_native.get("files") != expected_native:
        raise ValueError("Unexpected native code deletion, insertion or byte change")

    orig_modes = _surface(source_cli, after=False)
    new_modes = _surface(target_cli, after=True)
    if new_modes != {KEEP: orig_modes[KEEP]} or set(orig_modes) != set(CLI_PATHS):
        raise ValueError("Retained clamscan changed or unwanted CLI remains")
    counts = Counter()
    for (_, _, _, _, severity), n in before_cve.items():
        counts[severity] += n

    return {
        "status": "clamav_cli_limited_release_blocked",
        "release_authorized": False,
        "scanner_gate": "blocked",
        "vex": "not_issued",
        "cve_applicability": "individually_unassessed",
        "source_image_id": before_id,
        "experimental_image_id": after_id,
        "disabled_clamav_entrypoints": len(DENY),
        "allowlisted_clamav_entrypoints": [KEEP.rsplit("/", 1)[-1]],
        "native_files_preserved": len(target_native["files"]),
        "native_files_physically_removed": len(source_native["files"]) - len(target_native["files"]),
        "native_sha256_unchanged": True,
        "package_manifest_expected_missing": len(DENY),
        "talos_detached_signature_verified": True,
        "unapproved_package_changes": 0,
        "unapproved_cve_changes": 0,
        "nonempty_parent_layers_reused": 0,
        "critical_before": counts["CRITICAL"],
        "critical_after": counts["CRITICAL"],
        "high_before": counts["HIGH"],
        "high_after": counts["HIGH"],
        "unknown_before": counts["UNKNOWN"],
        "unknown_after": counts["UNKNOWN"],
        "clamav_high_still_reported": 7,
        "clamav_medium_still_reported": 6,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    args_names = (
        "source-scan", "target-scan", "source-sbom", "target-sbom",
        "source-inspect", "target-inspect", "source-cli", "target-cli",
        "source-native", "target-native", "talos-vendor",
    )
    for name in args_names:
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        values = [
            json.loads(getattr(args, name.replace("-", "_")).read_text(
                encoding="utf-8"
            )) for name in args_names
        ]
        result = verify_cli_reduction(*values)
    except (ValueError, TypeError, KeyError, OSError, AttributeError):
        print(json.dumps({"status": "error",
                          "reason": "clamav_cli_reduction_evidence_invalid"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2  # Image stays non-deployable regardless of signed equivalence.


if __name__ == "__main__":
    raise SystemExit(main())
