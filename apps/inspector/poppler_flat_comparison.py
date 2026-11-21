"""R1.42: fail-closed R1.41 -> scratch-flattened research image evidence.

This is a differential experiment, NEVER an approval of source-built Poppler,
Tesseract, ClamAV, ExpAt, scanner completeness, or a release/VEX decision.
An exact match returns exit 2 (blocked); invalid or incomplete evidence exits 3.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from runtime_prune_comparison import _scan, _sbom

SOURCE = "folio-civico-inspector:poppler-experiment"
FLAT = "folio-civico-inspector:poppler-flat-research"
EMPTY_LAYER = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
PUBLIC_BUILD_GPG_KEY = "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305"
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
METADATA_KEYS = (
    "User", "Cmd", "Entrypoint", "WorkingDir", "ExposedPorts", "Volumes",
    "Healthcheck", "StopSignal",
)
BLOCKING = frozenset(("CRITICAL", "HIGH", "UNKNOWN"))


def _image(meta: dict, *, is_flat: bool) -> tuple[str, list[str], dict]:
    if not isinstance(meta, dict) or not isinstance(meta.get("Id"), str) or (
        not SHA.fullmatch(meta["Id"])
    ):
        raise ValueError("Missing immutable image identity")
    if meta.get("Os") != "linux" or meta.get("Architecture") != "amd64":
        raise ValueError("Unexpected platform or architecture")
    rootfs = meta.get("RootFS")
    if not isinstance(rootfs, dict) or rootfs.get("Type") != "layers":
        raise ValueError("Invalid rootfs metadata")
    layers = rootfs.get("Layers")
    if not isinstance(layers, list) or not layers or any(
        not isinstance(x, str) or not SHA.fullmatch(x) for x in layers
    ):
        raise ValueError("Layer DiffID evidence missing")
    if (is_flat and (len(layers) != 2 or layers.count(EMPTY_LAYER) != 1
                     or len(set(layers)) != 2)):
        raise ValueError("Expected only flattened content and empty WORKDIR layer")
    if not is_flat and len(layers) < 3:
        raise ValueError("Expected pre-flattening source ancestry")
    config = meta.get("Config")
    if not isinstance(config, dict) or not isinstance(config.get("Env"), list):
        raise ValueError("Runtime config missing")
    env = config["Env"]
    if any(not isinstance(x, str) or "=" not in x for x in env):
        raise ValueError("Malformed runtime environment")
    names = [x.partition("=")[0] for x in env]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate environment variable name")
    if (config.get("User") != "65534:65534"
            or config.get("Cmd") != [
                "python3", "-I", "/srv/folio-inspector/inspector.py"
            ]
            or config.get("WorkingDir") != "/srv/folio-inspector"
            or config.get("ExposedPorts") != {"8789/tcp": {}}):
        raise ValueError("Nonstandard inspector runtime configuration")
    return meta["Id"], layers, config


def _native(provenance: dict) -> None:
    if (not isinstance(provenance, dict)
            or provenance.get("source") != "folio-local-elf-provenance-v1"
            or provenance.get("mode") != "experiment"
            or provenance.get("source_cve_coverage") != "unassessed"):
        raise ValueError("Native source CVE coverage is not represented")
    items = provenance.get("components")
    if not isinstance(items, list) or len(items) != 2 or {
        x.get("name") for x in items if isinstance(x, dict)
    } != {"tesseract", "poppler"}:
        raise ValueError("Two custom source engines required")
    for item in items:
        for field in ("library_sha256", "executable_sha256", "provenance_sha256"):
            digest = item.get(field)
            if not isinstance(digest, str) or not HEX.fullmatch(digest):
                raise ValueError("Missing native binary/source hash")
        if (item.get("automated_cve_coverage") != "not_verified"
                or item.get("cve_assessment") != "required"):
            raise ValueError("Cannot assume source CVE coverage")
        if item["name"] == "poppler":
            tools = item.get("tool_sha256")
            if (not isinstance(tools, dict) or set(tools) != {
                "pdfinfo", "pdftotext", "pdftoppm", "pdfdetach", "pdfattach"
            } or any(not isinstance(x, str) or not HEX.fullmatch(x)
                     for x in tools.values())):
                raise ValueError("Poppler tool fingerprints incomplete")
        if item["name"] == "tesseract":
            models = item.get("model_sha256")
            if (not isinstance(models, dict) or set(models) != {"eng", "spa"}
                    or any(not isinstance(x, str) or not HEX.fullmatch(x)
                           for x in models.values())):
                raise ValueError("OCR model hashes incomplete")


def verify_flat_poppler(
    before_scan: dict, after_scan: dict,
    before_sbom: dict, after_sbom: dict,
    before_inspect: dict, after_inspect: dict,
    before_native: dict, after_native: dict,
) -> dict:
    before_id, old_layers, old_config = _image(before_inspect, is_flat=False)
    after_id, new_layers, new_config = _image(after_inspect, is_flat=True)
    if before_id == after_id:
        raise ValueError("Unchanged image cannot substantiate flattening")
    if (set(old_layers) & set(new_layers)) - {EMPTY_LAYER}:
        raise ValueError("Historical nonempty OCI layer inherited")
    for name in METADATA_KEYS:
        if old_config.get(name) != new_config.get(name):
            raise ValueError("Security-relevant runtime metadata changed")
    expected_env = old_config["Env"]
    if (expected_env.count(PUBLIC_BUILD_GPG_KEY) != 1
            or new_config["Env"] != [
                x for x in expected_env if x != PUBLIC_BUILD_GPG_KEY
            ]):
        raise ValueError("Runtime environment changed beyond public GPG key")

    _native(before_native)
    _native(after_native)
    if before_native != after_native:
        raise ValueError("Source ELF/model/provenance changed during flattening")

    scan_old, scan_new = _scan(before_scan, SOURCE), _scan(after_scan, FLAT)
    bom_old = _sbom(before_sbom, SOURCE, before_id)
    bom_new = _sbom(after_sbom, FLAT, after_id)
    if bom_old != bom_new:
        raise ValueError("CycloneDX package inventory changed")
    if scan_old != scan_new:
        raise ValueError("Trivy vulnerability or severity inventory changed")
    blocking = sum(n for key, n in scan_new.items() if key[4] in BLOCKING)
    high = sum(n for key, n in scan_new.items() if key[4] == "HIGH")
    unknown = sum(n for key, n in scan_new.items() if key[4] == "UNKNOWN")
    if blocking <= 0 or unknown <= 0:
        raise ValueError("Expected unresolved HIGH/UNKNOWN risk absent")

    return {
        "status": "flattened_filesystem_verified_release_blocked",
        "source_image_id": before_id,
        "flat_image_id": after_id,
        "source_layers": len(old_layers),
        "flat_layers": len(new_layers),
        "inherited_nonempty_layer_ids": 0,
        "native_elf_model_hashes_unchanged": True,
        "runtime_configuration_unchanged_except_public_build_key": True,
        "trivy_cve_entries_unchanged": True,
        "cyclonedx_components": sum(bom_new.values()),
        "trivy_blocking_findings": blocking,
        "trivy_high": high,
        "trivy_unknown": unknown,
        "native_components_without_verified_cve_coverage": 2,
        "poppler_native_cve_coverage_verified": False,
        "tesseract_native_cve_coverage_verified": False,
        "risk_of_adversarial_document_exploitation_excluded": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = ("before-scan", "after-scan", "before-sbom", "after-sbom",
              "before-inspect", "after-inspect", "before-native", "after-native")
    for name in inputs:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        paths = [getattr(args, name.replace("-", "_")) for name in inputs]
        if any(not p.is_file() or not 0 < p.stat().st_size <= 16 * 1024 * 1024
               for p in paths):
            raise ValueError("Missing, empty, or oversized evidence")
        objects = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
        report = verify_flat_poppler(*objects)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print(json.dumps({"status": "error", "release_authorized": False}))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
