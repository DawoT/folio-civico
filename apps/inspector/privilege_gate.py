"""Fail-closed integrity proof for R1.24: deny privileged CLI entrypoints.

The Debian packages and every CVE remain in Trivy's results. This compares
an immutable pair of images, their CycloneDX and measured executable modes,
without claiming the underlying util-linux library has been patched.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from runtime_prune_comparison import _scan, _sbom
from privilege_surface import GUARDED, PRIVILEGED, TAG

OLD = "folio-civico-inspector:flat-runtime-experiment"
NEW = "folio-civico-inspector:nonprivileged-experiment"
SHA = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
EMPTY = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
CONFIG_FIELDS = ("User", "Env", "Cmd", "Entrypoint", "WorkingDir", "ExposedPorts",
                 "Volumes", "Healthcheck", "StopSignal")


def _image(metadata: dict, identity: str, target: bool) -> dict:
    if not isinstance(metadata, dict) or metadata.get("Id") != identity or (
        metadata.get("Architecture") != "amd64" or metadata.get("Os") != "linux"
    ):
        raise ValueError("Image architecture, OS or identity mismatch")
    rootfs = metadata.get("RootFS")
    if not isinstance(rootfs, dict) or rootfs.get("Type") != "layers":
        raise ValueError("Unsupported rootfs")
    layers = rootfs.get("Layers")
    if not isinstance(layers, list) or len(layers) != 2 or (
        layers.count(EMPTY) != 1 or not all(
            isinstance(s, str) and DIGEST.fullmatch(s) for s in layers
        )
    ):
        raise ValueError("Two-layer flattened image and known empty layer required")
    config = metadata.get("Config")
    if not isinstance(config, dict) or config.get("User") != "65534:65534" or (
        config.get("Cmd") != ["python3", "-I", "/srv/folio-inspector/inspector.py"]
    ):
        raise ValueError("Unexpected inspector runtime identity")
    return config


def _surface(value: dict, before: bool) -> dict:
    if (not isinstance(value, dict) or value.get("source") != TAG
            or value.get("scan_complete") is not True):
        raise ValueError("Native privilege inventory missing or partial")
    rows = value.get("guarded")
    if not isinstance(rows, list) or [row.get("path") for row in rows if isinstance(row, dict)] != list(GUARDED) or len(rows) != len(GUARDED):
        raise ValueError("Sensitive command inventory incomplete")
    special = value.get("special")
    if not isinstance(special, list) or (
        set(special) != set(PRIVILEGED) if before else special != []
    ):
        raise ValueError("Unexpected privileged executable presence")
    results = {}
    for entry in rows:
        name = entry.get("path")
        mode = entry.get("mode")
        digest = entry.get("sha256")
        if (not isinstance(mode, str) or not re.fullmatch(r"[0-7]{4}", mode)
                or not isinstance(digest, str) or not SHA.fullmatch(digest)):
            raise ValueError("Malformed privilege artifact")
        bits = int(mode, 8)
        if before and (
            not bits & 0o111 or
            ((name in PRIVILEGED) != bool(bits & 0o6000))
        ):
            raise ValueError("Unexpected source binary privilege bits")
        if not before and bits != 0o644:
            raise ValueError("Residual executable permission on disabled entrypoint")
        results[name] = digest
    return results


def verify_privilege_hardening(
    before_scan: dict, after_scan: dict,
    before_sbom: dict, after_sbom: dict,
    before_inspect: dict, after_inspect: dict,
    before_inventory: dict, after_inventory: dict,
) -> dict:
    before_id = before_inspect.get("Id") if isinstance(before_inspect, dict) else None
    after_id = after_inspect.get("Id") if isinstance(after_inspect, dict) else None
    if not isinstance(before_id, str) or not isinstance(after_id, str) or (
        not DIGEST.fullmatch(before_id) or not DIGEST.fullmatch(after_id)
        or before_id == after_id
    ):
        raise ValueError("Distinct immutable images required")
    c_before = _image(before_inspect, before_id, False)
    c_after = _image(after_inspect, after_id, True)
    if any(c_before.get(field) != c_after.get(field) for field in CONFIG_FIELDS):
        raise ValueError("Privilege mitigation changed runtime configuration")
    parent_layers = set(before_inspect["RootFS"]["Layers"])
    child_layers = set(after_inspect["RootFS"]["Layers"])
    if (parent_layers & child_layers) - {EMPTY}:
        raise ValueError("Unsafe historical content layer reuse")

    source_digest = _surface(before_inventory, before=True)
    target_digest = _surface(after_inventory, before=False)
    if source_digest != target_digest:
        raise ValueError("Disabling privilege launchers modified executable bytes")

    source_sbom = _sbom(before_sbom, OLD, before_id)
    target_sbom = _sbom(after_sbom, NEW, after_id)
    if source_sbom != target_sbom:
        raise ValueError("Debian CycloneDX package coverage was changed")
    alerts_before = _scan(before_scan, OLD)
    alerts_after = _scan(after_scan, NEW)
    if alerts_before != alerts_after:
        raise ValueError("Vulnerability scan changed without a package fix")
    counts = Counter()
    for entry,n in alerts_before.items():
        counts[entry[4]] += n

    return {
        "status": "nonprivileged_runtime_release_blocked",
        "release_authorized": False,
        "scanner_gate": "blocked",
        "vex": "not_issued",
        "source_image_id": before_id,
        "experimental_image_id": after_id,
        "setid_removed": len(PRIVILEGED),
        "disabled_entrypoints": len(GUARDED),
        "native_executable_bytes_unchanged": True,
        "nonempty_parent_layers_reused": 0,
        "all_suid_sgid_bits_absent": True,
        "critical_before": counts["CRITICAL"],
        "critical_after": counts["CRITICAL"],
        "high_before": counts["HIGH"],
        "high_after": counts["HIGH"],
        "unknown_before": counts["UNKNOWN"],
        "unknown_after": counts["UNKNOWN"],
        "source_advisory_coverage": "unassessed",
        "unapproved_package_changes": 0,
        "unapproved_vulnerability_changes": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    fields = ("before-scan", "after-scan", "before-sbom", "after-sbom",
              "before-inspect", "after-inspect",
              "before-inventory", "after-inventory")
    for field in fields:
        parser.add_argument("--"+field,required=True,type=Path)
    args=parser.parse_args()
    try:
        report = verify_privilege_hardening(*(
            json.loads(getattr(args,field.replace("-","_")).read_text(encoding="utf-8"))
            for field in fields
        ))
    except (ValueError, TypeError, OSError, KeyError, AttributeError):
        print(json.dumps({"status":"error","reason":"privilege_hardening_evidence_invalid"}))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 2


if __name__=="__main__":
    raise SystemExit(main())
