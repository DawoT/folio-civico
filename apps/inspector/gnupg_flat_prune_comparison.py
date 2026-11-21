"""R1.45: strict differential proof for offline GnuPG-pruned Poppler research.

Compares scanner and CycloneDX inventories from the SAME Trivy DB snapshot,
Docker immutable IDs, complete operational configuration, layer DiffIDs and
native Poppler/Tesseract ELF/model identities. Never authorizes release or VEX.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit_image import verify_native_source_inventory
from runtime_prune_comparison import (
    FLAT_OLD, FLAT_NEW, DIGEST, compare_images,
)

BASE = FLAT_OLD
CANDIDATE = FLAT_NEW
PINNED_BASE_ID = (
    "sha256:a68bce319afff0a0f50d50f5a717e077061dbe1eb93c9465910d7f002ba23f18"
)
EMPTY_LAYER = (
    "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
)
MAX_JSON_BYTES = 16 * 1024 * 1024
CONFIG_FIELDS = ("User", "Cmd", "Entrypoint", "WorkingDir", "Env", "ExposedPorts")


def compare_flat_prune(
    before_scan: dict, after_scan: dict,
    before_sbom: dict, after_sbom: dict, before_id: str, after_id: str,
    before_inspect: dict, after_inspect: dict,
    before_native: dict, after_native: dict,
) -> dict:
    if before_id != PINNED_BASE_ID:
        raise ValueError("Research requires the measured R1.42 base image")
    if (not isinstance(after_id, str) or not DIGEST.fullmatch(after_id)
            or after_id == before_id):
        raise ValueError("Distinct immutable output ID required")
    for evidence, image_id in ((before_inspect, before_id),
                               (after_inspect, after_id)):
        if not isinstance(evidence, dict) or evidence.get("Id") != image_id:
            raise ValueError("Docker inspection is not bound to the image ID")
        cfg = evidence.get("Config")
        fs = evidence.get("RootFS")
        if not isinstance(cfg, dict) or not isinstance(fs, dict):
            raise ValueError("Missing Docker image configuration")
        layers = fs.get("Layers")
        if (fs.get("Type") != "layers" or not isinstance(layers, list)
                or len(layers) != 2 or layers.count(EMPTY_LAYER) != 1
                or any(not isinstance(layer, str)
                       or not DIGEST.fullmatch(layer) for layer in layers)):
            raise ValueError("Research must be a two-layer flattened image")
    config_a, config_b = before_inspect["Config"], after_inspect["Config"]
    if (any(config_a.get(field) != config_b.get(field) for field in CONFIG_FIELDS)
            or config_b.get("User") != "65534:65534"
            or config_b.get("Cmd") != ["python3", "-I", "/srv/folio-inspector/inspector.py"]
            or config_b.get("Entrypoint") is not None):
        raise ValueError("Inspector runtime metadata changed")
    source_layers = set(before_inspect["RootFS"]["Layers"]) - {EMPTY_LAYER}
    candidate_layers = set(after_inspect["RootFS"]["Layers"]) - {EMPTY_LAYER}
    if source_layers & candidate_layers:
        raise ValueError("Historical nonempty OCI layer survived")
    if before_native != after_native:
        raise ValueError("Poppler/Tesseract native binaries or OCR models changed")
    # Verify the full ELF, tools, OCR models and source provenance contract.
    # These are hash identities, NOT complete CVE coverage or reproducible builds.
    verify_native_source_inventory(before_native, "folio-civico-inspector:poppler-experiment")
    verify_native_source_inventory(after_native, "folio-civico-inspector:poppler-experiment")

    result = compare_images(
        before_scan, after_scan, before_sbom, after_sbom, before_id, after_id,
        before_image=BASE, after_image=CANDIDATE,
    )
    result.update({
        "source_elf_identity": "unchanged",
        "nonempty_base_layers_reused": 0,
        "scanner_gate": "blocked",
        "vex": "not_issued",
        "source_cve_coverage": "unassessed",
        "vendor_advisory_disposition": "independent_review_required",
        "release_authorized": False,
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    kinds = (
        "before-scan", "after-scan", "before-sbom", "after-sbom",
        "before-inspect", "after-inspect", "before-native", "after-native",
    )
    for name in kinds:
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--before-id", required=True)
    parser.add_argument("--after-id", required=True)
    args = parser.parse_args()
    try:
        docs = []
        for name in kinds:
            path = getattr(args, name.replace("-", "_"))
            if not path.is_file() or not 0 < path.stat().st_size <= MAX_JSON_BYTES:
                raise ValueError("Missing or oversized research evidence")
            docs.append(json.loads(path.read_text(encoding="utf-8")))
        report = compare_flat_prune(
            *docs[:4], args.before_id, args.after_id, *docs[4:],
        )
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print(json.dumps({"status": "error", "release_authorized": False}))
        return 3
    print(json.dumps(report, sort_keys=True))
    # A measured CVE reduction must never become release approval.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
