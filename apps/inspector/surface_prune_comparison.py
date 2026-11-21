"""R1.46: independently verify a strictly smaller, non-deployable PDF runtime.

Same Trivy database, identical native engines/models, pinned Docker IDs,
no historical nonempty OCI layers, and no new CVE/package drift.
This validator always denies release (exit 2 for complete evidence, 3 otherwise).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit_image import verify_native_source_inventory
from runtime_prune_comparison import (
    SURFACE_OLD, SURFACE_NEW, DIGEST, compare_images,
)
from gnupg_flat_prune_comparison import EMPTY_LAYER, CONFIG_FIELDS

BASE = SURFACE_OLD
CANDIDATE = SURFACE_NEW
PINNED_BASE_ID = (
    "sha256:8e3bba6979ed0664531db7bd7fd55124afa7bb8afadae5df8b4d849f1c9ac3d2"
)
MAX_JSON_BYTES = 16 * 1024 * 1024


def compare_surface_prune(
    before_scan: dict, after_scan: dict,
    before_sbom: dict, after_sbom: dict,
    before_id: str, after_id: str,
    before_inspect: dict, after_inspect: dict,
    before_native: dict, after_native: dict,
) -> dict:
    if before_id != PINNED_BASE_ID:
        raise ValueError("Unapproved R1.45 base image")
    if (not isinstance(after_id, str) or not DIGEST.fullmatch(after_id)
            or after_id == before_id):
        raise ValueError("Distinct verified R1.46 image ID required")

    for inspected, image_id in ((before_inspect, before_id),
                                (after_inspect, after_id)):
        if not isinstance(inspected, dict) or inspected.get("Id") != image_id:
            raise ValueError("Docker inspect evidence is not immutable")
        cfg, fs = inspected.get("Config"), inspected.get("RootFS")
        if not isinstance(cfg, dict) or not isinstance(fs, dict):
            raise ValueError("Docker metadata missing")
        layers = fs.get("Layers")
        if (fs.get("Type") != "layers" or not isinstance(layers, list)
                or len(layers) != 2 or layers.count(EMPTY_LAYER) != 1
                or any(not isinstance(layer, str) or not DIGEST.fullmatch(layer)
                       for layer in layers)):
            raise ValueError("Expected flattened two-layer Docker image")

    cfg_before, cfg_after = before_inspect["Config"], after_inspect["Config"]
    if (any(cfg_before.get(k) != cfg_after.get(k) for k in CONFIG_FIELDS)
            or cfg_after.get("User") != "65534:65534"
            or cfg_after.get("Entrypoint") is not None
            or cfg_after.get("Cmd") != ["python3", "-I", "/srv/folio-inspector/inspector.py"]):
        raise ValueError("Operational inspector metadata differs")
    prior = set(before_inspect["RootFS"]["Layers"]) - {EMPTY_LAYER}
    after = set(after_inspect["RootFS"]["Layers"]) - {EMPTY_LAYER}
    if prior & after:
        raise ValueError("Nonempty historical OCI layer reused")

    if before_native != after_native:
        raise ValueError("Native executables, linked libraries or OCR models differ")
    verify_native_source_inventory(before_native, "folio-civico-inspector:poppler-experiment")
    verify_native_source_inventory(after_native, "folio-civico-inspector:poppler-experiment")

    report = compare_images(
        before_scan, after_scan, before_sbom, after_sbom, before_id, after_id,
        before_image=BASE, after_image=CANDIDATE,
    )
    report.update({
        "source_elf_identity": "unchanged",
        "nonempty_base_layers_reused": 0,
        "native_cve_coverage": "not_verified",
        "vendor_advisory_review": "required",
        "scanner_gate": "blocked",
        "vex": "not_issued",
        "release_authorized": False,
    })
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    keys = (
        "before-scan", "after-scan", "before-sbom", "after-sbom",
        "before-inspect", "after-inspect", "before-native", "after-native",
    )
    for key in keys:
        p.add_argument("--" + key, type=Path, required=True)
    p.add_argument("--before-id", required=True)
    p.add_argument("--after-id", required=True)
    args = p.parse_args()
    try:
        docs = []
        for key in keys:
            path = getattr(args, key.replace("-", "_"))
            if not path.is_file() or not 0 < path.stat().st_size <= MAX_JSON_BYTES:
                raise ValueError("Missing or oversized R1.46 evidence")
            docs.append(json.loads(path.read_text(encoding="utf-8")))
        result = compare_surface_prune(*docs[:4], args.before_id, args.after_id, *docs[4:])
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print(json.dumps({"status": "error", "release_authorized": False}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
