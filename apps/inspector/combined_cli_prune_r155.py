"""R1.55: exact two-image research diff for combined ClamAV and privileged CLI cuts.

Uses complete immutable-rootfs SHA evidence, Trivy JSON, CycloneDX, native
ELF/model inventories and dpkg manifest comparisons. A valid result is still
BLOCKED (exit 2): removal of entrypoints is NOT remediation of a CVE.
No VEX, vendor exception, release or access to institutional documents.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from audit_image import verify_native_source_inventory
from clamav_cli_surface import DENY, KEEP, PACKAGE_VERSION
from clamav_signed_gate import _signed_files
from gnupg_flat_prune_comparison import EMPTY_LAYER
from privileged_cli_prune_audit import _filesystem, _privileged_regular
from runtime_prune_comparison import DIGEST, _scan, _sbom

BASE = "folio-civico-inspector:privileged-cli-pruned-research-r148"
CANDIDATE = "folio-civico-inspector:combined-clamav-cli-r155-local"
BASE_ID = "sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a"
CANDIDATE_ID = "sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327"
EXPECTED_BLOCKERS = {"CRITICAL": 0, "HIGH": 55, "UNKNOWN": 15}
EXPECTED_OLD_NATIVE = 16
EXPECTED_NEW_NATIVE = 7
MAX_EVIDENCE_BYTES = 24 * 1024 * 1024


def _image(before: dict, after: dict) -> None:
    if (not isinstance(before, dict) or not isinstance(after, dict)
            or before.get("Id") != BASE_ID or after.get("Id") != CANDIDATE_ID
            or not DIGEST.fullmatch(BASE_ID) or not DIGEST.fullmatch(CANDIDATE_ID)
            or BASE_ID == CANDIDATE_ID):
        raise ValueError("Unpinned image identities")
    for record in (before, after):
        if record.get("Os") != "linux" or record.get("Architecture") != "amd64":
            raise ValueError("Unsupported image architecture")
        root = record.get("RootFS")
        layers = root.get("Layers") if isinstance(root, dict) else None
        if (not isinstance(root, dict) or root.get("Type") != "layers"
                or not isinstance(layers, list) or len(layers) != 2
                or layers.count(EMPTY_LAYER) != 1
                or not all(isinstance(v, str) and DIGEST.fullmatch(v)
                           for v in layers)):
            raise ValueError("Expected a flattened two-layer filesystem")
    base_layers = set(before["RootFS"]["Layers"]) - {EMPTY_LAYER}
    after_layers = set(after["RootFS"]["Layers"]) - {EMPTY_LAYER}
    if base_layers & after_layers:
        raise ValueError("Historical OCI filesystem layer is still recoverable")
    config = after.get("Config")
    if (not isinstance(config, dict) or config != before.get("Config")
            or config.get("User") != "65534:65534"
            or config.get("Entrypoint") is not None
            or config.get("Cmd") != [
                "python3", "-I", "/srv/folio-inspector/inspector.py"
            ] or config.get("WorkingDir") != "/srv/folio-inspector"
            or config.get("ExposedPorts") != {"8789/tcp": {}}
            or "CLAMAV_DB_DIR=/opt/clamdb" not in config.get("Env", [])):
        raise ValueError("Inspector runtime configuration changed")


def _clamav(base: dict, candidate: dict) -> tuple[int, int]:
    if not isinstance(base, dict) or not isinstance(candidate, dict):
        raise ValueError("Native package inventories missing")
    common = (
        ("package", "clamav"), ("package_version", PACKAGE_VERSION),
        ("architecture", "amd64"), ("clamscan_version", "ClamAV 1.5.5"),
        ("shared_library_linked", True), ("release_authorized", False),
    )
    if any(base.get(key) != value or candidate.get(key) != value
           for key, value in common):
        raise ValueError("ClamAV native identity or blocked decision changed")
    if (base.get("source") != "folio-clamav-installed-native-v1"
            or base.get("dpkg_verify_clean") is not True
            or candidate.get("source") != "folio-clamav-minimal-native-v1"
            or candidate.get("dpkg_verified_expected_removals") is not True
            or candidate.get("expected_absent") != sorted(DENY)):
        raise ValueError("Original package or expected-only deletion proof invalid")
    old = _signed_files(base.get("files"))
    new = _signed_files(candidate.get("files"))
    previous = {row["path"]: row["sha256"] for row in old}
    retained = {row["path"]: row["sha256"] for row in new}
    if (len(previous) != EXPECTED_OLD_NATIVE
            or len(retained) != EXPECTED_NEW_NATIVE
            or KEEP not in retained
            or set(previous) - set(retained) != (set(DENY) & set(previous))
            or any(previous.get(name) != digest for name, digest in retained.items())):
        raise ValueError("Retained ClamAV native bytes, coverage or CLI set changed")
    return len(previous), len(retained)


def compare(
    before_scan: dict, after_scan: dict,
    before_sbom: dict, after_sbom: dict,
    before_inspect: dict, after_inspect: dict,
    before_native: dict, after_native: dict,
    before_fs: dict, after_fs: dict,
    before_clamav: dict, after_clamav: dict,
) -> dict:
    """Fail closed on ANY change besides deletion of the ten named CLIs."""
    _image(before_inspect, after_inspect)
    old_paths, new_paths = _filesystem(before_fs), _filesystem(after_fs)
    if (before_fs.get("excluded_top_level") != after_fs.get("excluded_top_level")
            or before_fs.get("excluded_docker_injected")
            != after_fs.get("excluded_docker_injected")):
        raise ValueError("Filesystem snapshot exclusions changed")
    removed = set(old_paths) - set(new_paths)
    added = set(new_paths) - set(old_paths)
    changed = {name for name in set(old_paths) & set(new_paths)
               if old_paths[name] != new_paths[name]}
    if removed != set(DENY) or added or changed:
        raise ValueError("Unexpected native filesystem mutation")
    if _privileged_regular(new_paths):
        raise ValueError("Privileged filesystem entrypoint survived")
    if not isinstance(before_native, dict) or before_native != after_native:
        raise ValueError("Source-built native ELF or OCR models changed")
    if (verify_native_source_inventory(
            before_native, "folio-civico-inspector:poppler-experiment"
        ) != 2):
        raise ValueError("Incomplete legacy OCR/Poppler source fingerprints")

    original_findings = _scan(before_scan, BASE)
    target_findings = _scan(after_scan, CANDIDATE)
    if original_findings != target_findings or not original_findings:
        raise ValueError("Trivy advisories disappeared or changed")
    old_packages = _sbom(before_sbom, BASE, BASE_ID)
    new_packages = _sbom(after_sbom, CANDIDATE, CANDIDATE_ID)
    if old_packages != new_packages or not old_packages:
        raise ValueError("Debian/Python CycloneDX package identity changed")
    old_code_count, kept_code_count = _clamav(before_clamav, after_clamav)

    counts = Counter()
    for key, count in target_findings.items():
        counts[key[-1]] += count
    if any(counts[k] != v for k, v in EXPECTED_BLOCKERS.items()):
        raise ValueError("Unexpected CRITICAL, HIGH or UNKNOWN baseline")
    return {
        "status": "combined_cli_and_privileged_fs_reduction_verified_release_blocked",
        "base_id": BASE_ID, "experimental_id": CANDIDATE_ID,
        "fs_paths_before": len(old_paths), "fs_paths_after": len(new_paths),
        "removed_total": len(removed), "removed_paths": sorted(removed),
        "added_paths": 0, "changed_paths": 0,
        "suid_sgid_after": 0, "native_model_inventory_equal": True,
        "clamav_signed_code_before": old_code_count,
        "clamav_retained_code_after": kept_code_count,
        "retained_clamav_native_sha256_equal": True,
        "same_sbom": True, "same_trivy_records": True,
        "cve_counts": {key: counts[key] for key in EXPECTED_BLOCKERS},
        "scanner_gate": "blocked", "release_authorized": False,
        "vex": "not_issued",
    }


def _private_evidence(path: Path) -> dict:
    if (path.is_symlink() or not path.is_file()
            or not 0 < path.stat().st_size <= MAX_EVIDENCE_BYTES):
        raise ValueError("Evidence missing, symlinked, empty or oversized")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Evidence must be a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in (
        "base-scan", "cand-scan", "base-sbom", "cand-sbom",
        "base-inspect", "cand-inspect", "base-native", "cand-native",
        "base-fs", "cand-fs", "base-clamav", "cand-clamav",
    ):
        parser.add_argument("--" + key, required=True, type=Path)
    args = parser.parse_args()
    try:
        inputs = [
            _private_evidence(getattr(args, field.replace("-", "_")))
            for field in (
                "base-scan", "cand-scan", "base-sbom", "cand-sbom",
                "base-inspect", "cand-inspect", "base-native", "cand-native",
                "base-fs", "cand-fs", "base-clamav", "cand-clamav",
            )
        ]
        result = compare(*inputs)
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            UnicodeError):
        print(json.dumps({
            "status": "incomplete", "scanner_gate": "blocked",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2  # Valid research still forbids deployment or CVE waivers.


if __name__ == "__main__":
    raise SystemExit(main())
