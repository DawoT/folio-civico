"""R1.48: attest exact removal of privileged CLI entrypoints from research OCI.

Comparisons use complete filesystem SHA-256 inventories from both images,
same-DB Trivy/CycloneDX, full native source hashes, immutable Docker IDs and
unchanged runtime configuration. This is hardening, NOT a fix for any CVE.
Success returns exit 2 (release blocked), malformed evidence returns exit 3.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from audit_image import verify_native_source_inventory
from gnupg_flat_prune_comparison import CONFIG_FIELDS, EMPTY_LAYER
from runtime_prune_comparison import DIGEST, _scan, _sbom
from util_linux_folio2_runtime_audit import (
    CVES, EXPECTED_VERSIONS, _validate_sbom_versions,
)
from runtime_executable_surface_inventory import (
    DOCKER_INJECTED, EXCLUDED_TOP_LEVEL,
)

BASE = "folio-civico-inspector:folio2-runtime-research-r147"
CANDIDATE = "folio-civico-inspector:privileged-cli-pruned-research-r148"
PINNED_BASE_ID = (
    "sha256:c506a8b40953167ee4f6486cb90217298a39ce680f0bdd5fdc3a8b9638ddb92d"
)
SUID_SGID_MODES = {
    "/usr/bin/chage": "0o2755",
    "/usr/bin/chfn": "0o4755",
    "/usr/bin/chsh": "0o4755",
    "/usr/bin/expiry": "0o2755",
    "/usr/bin/gpasswd": "0o4755",
    "/usr/bin/newgrp": "0o4755",
    "/usr/bin/passwd": "0o4755",
    "/usr/bin/su": "0o4755",
    "/usr/sbin/unix_chkpwd": "0o2755",
}
NON_PRIVILEGED_CLI = frozenset((
    "/usr/bin/nsenter", "/usr/bin/unshare", "/usr/bin/login",
    "/usr/sbin/runuser", "/usr/bin/setpriv",
))
SYMLINK = "/usr/bin/sg"
REMOVED = frozenset(SUID_SGID_MODES) | NON_PRIVILEGED_CLI | {SYMLINK}
assert len(REMOVED) == 15
MAX_EVIDENCE_BYTES = 24 * 1024 * 1024
SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _filesystem(document: dict) -> dict[str, dict]:
    if not isinstance(document, dict) or (
        document.get("schema") != "folio-r148-complete-runtime-filesystem-v1"
        or document.get("excluded_top_level") != sorted(EXCLUDED_TOP_LEVEL)
        or document.get("excluded_docker_injected") != sorted(DOCKER_INJECTED)
    ):
        raise ValueError("Complete filesystem snapshot schema or exclusions changed")
    paths = document.get("paths")
    if not isinstance(paths, dict) or "/" not in paths:
        raise ValueError("No complete file tree")
    for path, record in paths.items():
        if (not isinstance(path, str) or not path.startswith("/")
                or ".." in Path(path).parts or not isinstance(record, dict)
                or not isinstance(record.get("mode"), str)
                or not re.fullmatch(r"0o[0-7]{3,4}", record["mode"])):
            raise ValueError("Malformed full filesystem entry")
        kind = record.get("kind")
        if kind == "file":
            if not isinstance(record.get("sha256"), str) or not SHA256.fullmatch(record["sha256"]):
                raise ValueError("Regular filesystem content lacks SHA256")
        elif kind == "symlink":
            if not isinstance(record.get("target"), str) or not record["target"]:
                raise ValueError("Invalid filesystem symlink")
        elif kind != "directory":
            raise ValueError("Unrecognized root filesystem inode")
    return paths


def _verify_image_metadata(a: dict, b: dict, old_id: str, new_id: str) -> None:
    if (old_id != PINNED_BASE_ID
            or not isinstance(new_id, str)
            or not DIGEST.fullmatch(new_id) or old_id == new_id):
        raise ValueError("Immutable base is not the pinned R1.47 image")
    for record, image_id in ((a, old_id), (b, new_id)):
        if not isinstance(record, dict) or record.get("Id") != image_id:
            raise ValueError("Docker inspect image ID mismatch")
        cfg, root = record.get("Config"), record.get("RootFS")
        if not isinstance(cfg, dict) or not isinstance(root, dict):
            raise ValueError("Docker config or layers unavailable")
        layers = root.get("Layers")
        if (root.get("Type") != "layers" or not isinstance(layers, list)
                or len(layers) != 2 or layers.count(EMPTY_LAYER) != 1
                or any(not isinstance(layer, str)
                       or not DIGEST.fullmatch(layer) for layer in layers)):
            raise ValueError("Image not flattened to one nonempty layer")
    cfg_a, cfg_b = a["Config"], b["Config"]
    if (any(cfg_a.get(k) != cfg_b.get(k) for k in CONFIG_FIELDS)
            or cfg_b.get("User") != "65534:65534"
            or cfg_b.get("Cmd") != ["python3", "-I", "/srv/folio-inspector/inspector.py"]
            or cfg_b.get("Entrypoint") is not None):
        raise ValueError("Runtime configuration changed")
    old = set(a["RootFS"]["Layers"]) - {EMPTY_LAYER}
    new = set(b["RootFS"]["Layers"]) - {EMPTY_LAYER}
    if old & new:
        raise ValueError("Nonempty historical OCI layer reused")


def _privileged_regular(paths: dict[str, dict]) -> set[str]:
    return {
        path for path, row in paths.items()
        if row.get("kind") == "file"
        and bool(int(row["mode"], 8) & 0o6000)
    }


def compare_privileged_cli_prune(
    before_scan: dict, after_scan: dict, before_sbom: dict, after_sbom: dict,
    before_inspect: dict, after_inspect: dict,
    before_native: dict, after_native: dict,
    before_fs: dict, after_fs: dict,
    before_id: str, after_id: str,
) -> dict:
    _verify_image_metadata(before_inspect, after_inspect, before_id, after_id)
    if (not isinstance(before_native, dict) or before_native != after_native):
        raise ValueError("Poppler/Tesseract native ELF or OCR models changed")
    verify_native_source_inventory(before_native, "folio-civico-inspector:poppler-experiment")
    verify_native_source_inventory(after_native, "folio-civico-inspector:poppler-experiment")

    original = _filesystem(before_fs)
    reduced = _filesystem(after_fs)
    if (set(original) - set(reduced) != REMOVED
            or set(reduced) - set(original)
            or any(original[path] != reduced[path] for path in reduced)):
        raise ValueError("Unexpected file deleted/added/modified beyond 15 entrypoints")
    for path, mode in SUID_SGID_MODES.items():
        if original.get(path, {}).get("kind") != "file" or (
            original[path].get("mode") != mode
        ):
            raise ValueError("Pinned root source SUID/SGID mode changed")
    if (original.get(SYMLINK) !=
            {"kind": "symlink", "mode": "0o777", "target": "newgrp"}):
        raise ValueError("Pinned sg privilege alias changed")
    for path in NON_PRIVILEGED_CLI:
        if (original.get(path, {}).get("kind") != "file"
                or original[path].get("mode") != "0o755"):
            raise ValueError("Root namespace/admin command set changed")
    if _privileged_regular(original) != set(SUID_SGID_MODES):
        raise ValueError("Unexpected SUID/SGID file outside the pinned set")
    if _privileged_regular(reduced):
        raise ValueError("Privileged executable still present in research runtime")

    packages_before = _sbom(before_sbom, BASE, before_id)
    packages_after = _sbom(after_sbom, CANDIDATE, after_id)
    if packages_before != packages_after:
        raise ValueError("Package inventory changed despite filesystem-only hardening")
    for packages in (packages_before, packages_after):
        _validate_sbom_versions(packages, EXPECTED_VERSIONS)

    vulnerabilities_before = _scan(before_scan, BASE)
    vulnerabilities_after = _scan(after_scan, CANDIDATE)
    if vulnerabilities_before != vulnerabilities_after:
        raise ValueError("A scanner advisory appeared, changed or disappeared")
    for source in (vulnerabilities_before, vulnerabilities_after):
        for package in EXPECTED_VERSIONS:
            for cve in CVES:
                if sum(
                    n for (_, pkg, _, vuln, severity), n in source.items()
                    if pkg == package and vuln == cve and severity == "HIGH"
                ) != 1:
                    raise ValueError("Unresolved util-linux CVE coverage was hidden")
    counts: Counter = Counter()
    for (_, _, _, _, severity), n in vulnerabilities_after.items():
        counts[severity] += n
    return {
        "status": "privileged_entrypoints_removed_release_blocked",
        "source_image": BASE,
        "source_image_id": before_id,
        "experimental_image": CANDIDATE,
        "experimental_image_id": after_id,
        "removed_entrypoints": sorted(REMOVED),
        "removed_entrypoint_count": len(REMOVED),
        "removed_suid_sgid_regular_files": len(SUID_SGID_MODES),
        "remaining_suid_sgid_regular_files": 0,
        "new_or_modified_other_files": 0,
        "unchanged_native_elf_and_models": True,
        "nonempty_base_layers_reused": 0,
        "critical_after": counts["CRITICAL"],
        "high_after": counts["HIGH"],
        "unknown_after": counts["UNKNOWN"],
        "util_linux_high_after": len(EXPECTED_VERSIONS) * len(CVES),
        "cve_remediated": False,
        "native_cve_coverage": "not_verified",
        "vendor_package_attested": False,
        "vex": "not_issued",
        "scanner_gate": "blocked",
        "release_authorized": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    docs = (
        "before-scan", "after-scan", "before-sbom", "after-sbom",
        "before-inspect", "after-inspect", "before-native", "after-native",
        "before-fs", "after-fs",
    )
    for name in docs:
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--before-id", required=True)
    p.add_argument("--after-id", required=True)
    args = p.parse_args()
    try:
        loaded = []
        for name in docs:
            path = getattr(args, name.replace("-", "_"))
            if not path.is_file() or not 0 < path.stat().st_size <= MAX_EVIDENCE_BYTES:
                raise ValueError("Missing or oversized image/scan/root evidence")
            loaded.append(json.loads(path.read_text(encoding="utf-8")))
        result = compare_privileged_cli_prune(
            *loaded, args.before_id, args.after_id,
        )
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print(json.dumps({"status": "error", "release_authorized": False}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
