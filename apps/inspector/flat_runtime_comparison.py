"""R1.23 strict experimental runtime flattening evidence, never a release waiver.

Compares Trivy CVE records, CycloneDX package identity, native source
provenance and Docker runtime config before/after exact orphan-package removal.
Requires exactly ONE filesystem layer after the scratch-copy flattening.
All outcomes remain release-blocked; an integrity mismatch exits 3.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from runtime_prune_comparison import _scan, _sbom

BEFORE = "folio-civico-inspector:headless-pruned-experiment"
AFTER = "folio-civico-inspector:flat-runtime-experiment"
REMOVED_PACKAGES = frozenset(("pinentry-curses", "libncursesw6"))
KNOWN_REMOVED_HIGH = {("libncursesw6", "CVE-2025-69720")}
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
# BuildKit adds an empty WORKDIR tar layer, which can be content-addressed
# identically to an empty layer of the former parent. No old file bytes.
EMPTY_LAYER = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
HASH = re.compile(r"^[a-f0-9]{64}$")
PUBLIC_PYTHON_BUILD_GPG_KEY = "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305"
RUNTIME_CONFIG_KEYS = (
    "User", "Cmd", "Entrypoint", "WorkingDir",
    "ExposedPorts", "Volumes", "Healthcheck", "StopSignal",
)


def _inspect(meta: dict, expected_id: str, *, flat: bool) -> tuple[int, dict]:
    if (not isinstance(meta, dict) or meta.get("Id") != expected_id
            or meta.get("Os") != "linux"
            or meta.get("Architecture") != "amd64"):
        raise ValueError("Docker image ID / architecture changed")
    rootfs = meta.get("RootFS")
    if not isinstance(rootfs, dict) or rootfs.get("Type") != "layers":
        raise ValueError("Docker root filesystem absent")
    layers = rootfs.get("Layers")
    if (not isinstance(layers, list) or not layers
            or any(not isinstance(x, str) or not DIGEST.fullmatch(x) for x in layers)):
        raise ValueError("Unverifiable filesystem layers")
    if flat and (len(layers) != 2 or layers.count(EMPTY_LAYER) != 1):
        raise ValueError("Flattened runtime must contain one content and one empty metadata layer")
    if not flat and len(layers) < 2:
        raise ValueError("Expected layered source runtime")
    config = meta.get("Config")
    if not isinstance(config, dict):
        raise ValueError("Docker runtime config missing")
    if (config.get("User") != "65534:65534"
            or config.get("WorkingDir") != "/srv/folio-inspector"
            or config.get("Cmd") != ["python3","-I","/srv/folio-inspector/inspector.py"]
            or config.get("Entrypoint") is not None
            or config.get("ExposedPorts") != {"8789/tcp": {}}):
        raise ValueError("Inspector runtime identity changed")
    env = config.get("Env")
    if not isinstance(env, list) or not all(isinstance(s, str) and "=" in s for s in env):
        raise ValueError("Inspector environment not declared")
    names = [s.split("=",1)[0] for s in env]
    if len(names) != len(set(names)) or not {
        "PATH","TESSDATA_PREFIX","CLAMAV_DB_DIR","FOLIO_INSPECTOR_BIND",
    }.issubset(names):
        raise ValueError("Runtime environment malformed")
    return len(layers), config


def _provenance(native: dict, expat: dict) -> None:
    if (not isinstance(native, dict)
            or native.get("source") != "folio-local-elf-provenance-v1"
            or native.get("source_cve_coverage") != "unassessed"
            or native.get("mode") not in (None,"experiment")):
        raise ValueError("Native source advisory coverage missing")
    items = native.get("components")
    if not isinstance(items, list) or {
        item.get("name") for item in items if isinstance(item, dict)
    } != {"tesseract", "poppler"} or len(items) != 2:
        raise ValueError("OCR/PDF native inventory incomplete")
    for item in items:
        if (not isinstance(item, dict)
                or not isinstance(item.get("library_sha256"), str)
                or not HASH.fullmatch(item["library_sha256"])):
            raise ValueError("ELF native SHA-256 missing")
    if (not isinstance(expat, dict)
            or expat.get("source") != "folio-expat-local-provenance-v1"
            or expat.get("package") != "libexpat1"
            or expat.get("package_version") != "2.10.0-1+folio1"
            or expat.get("native_cve_coverage") != "unassessed"):
        raise ValueError("Experimental Expat provenance missing")
    for key in ("patch_sha256","library_sha256"):
        digest = expat.get(key)
        if not isinstance(digest, str) or not HASH.fullmatch(digest):
            raise ValueError("Experimental Expat ELF / patch identity missing")


def verify_flattening(
    before_scan: dict, after_scan: dict,
    before_sbom: dict, after_sbom: dict,
    before_inspect: dict, after_inspect: dict,
    before_native: dict, after_native: dict,
    before_expat: dict, after_expat: dict,
) -> dict:
    before_id = before_inspect.get("Id") if isinstance(before_inspect, dict) else None
    after_id = after_inspect.get("Id") if isinstance(after_inspect, dict) else None
    if (not isinstance(before_id, str) or not isinstance(after_id, str)
            or not DIGEST.fullmatch(before_id)
            or not DIGEST.fullmatch(after_id) or before_id == after_id):
        raise ValueError("Independent immutable Docker IDs required")

    before_layers, before_config = _inspect(before_inspect, before_id, flat=False)
    after_layers, after_config = _inspect(after_inspect, after_id, flat=True)
    # The only reusable DiffID is the well-known empty-tar layer generated
    # by WORKDIR; any shared nonempty DiffID means hidden ancestry survived.
    shared_layers = (set(before_inspect["RootFS"]["Layers"])
                     & set(after_inspect["RootFS"]["Layers"]))
    if shared_layers - {EMPTY_LAYER}:
        raise ValueError("Flattened runtime reuses historical filesystem content")
    if any(before_config.get(key) != after_config.get(key)
           for key in RUNTIME_CONFIG_KEYS):
        raise ValueError("Flattening altered security-relevant container metadata")
    # The public Python image build-key fingerprint is not used at runtime.
    # Delete ONLY this exact metadata entry; all functional ENV must match.
    before_env = before_config["Env"]
    after_env = after_config["Env"]
    if (before_env.count(PUBLIC_PYTHON_BUILD_GPG_KEY) != 1
            or after_env != [item for item in before_env
                             if item != PUBLIC_PYTHON_BUILD_GPG_KEY]):
        raise ValueError("Unexpected inherited or modified runtime environment")

    _provenance(before_native, before_expat)
    _provenance(after_native, after_expat)
    if before_native != after_native or before_expat != after_expat:
        raise ValueError("Flattening changed native OCR/PDF/Expat binary identities")

    a, b = _scan(before_scan, BEFORE), _scan(after_scan, AFTER)
    sbom_a = _sbom(before_sbom, BEFORE, before_id)
    sbom_b = _sbom(after_sbom, AFTER, after_id)
    removed_sbom, added_sbom = sbom_a - sbom_b, sbom_b - sbom_a
    if added_sbom:
        raise ValueError("Flattened image unexpectedly introduces packages")
    removed_names = {key[1] for key in removed_sbom}
    if (removed_names != REMOVED_PACKAGES
            or any(key[1] not in REMOVED_PACKAGES for key in removed_sbom)
            or any(key[1] in REMOVED_PACKAGES for key in sbom_b)):
        raise ValueError("Package changes exceed two declared orphan dependencies")

    expat_packages = [
        key for key in sbom_b if key[1] == "libexpat1"
    ]
    if (len(expat_packages) != 1
            or expat_packages[0][2] != after_expat["package_version"]):
        raise ValueError("Expat scanner SBOM and ELF provenance disagree")

    gone, added = a - b, b - a
    if added or any(key[1] not in REMOVED_PACKAGES for key in gone):
        raise ValueError("Unrelated vulnerability records were altered")
    gone_high = {
        (key[1], key[3]) for key, count in gone.items() if key[4] == "HIGH"
    }
    if gone_high != KNOWN_REMOVED_HIGH or any(
        key[4] in ("CRITICAL", "UNKNOWN") or (
            key[4] == "HIGH" and count != 1
        ) for key,count in gone.items()
    ):
        raise ValueError("Unapproved critical/high/unknown CVE disappearance")

    before_counts, after_counts = Counter(), Counter()
    for key,n in a.items():
        before_counts[key[4]] += n
    for key,n in b.items():
        after_counts[key[4]] += n
    if (before_counts["CRITICAL"] != after_counts["CRITICAL"]
            or before_counts["UNKNOWN"] != after_counts["UNKNOWN"]
            or before_counts["HIGH"] - after_counts["HIGH"] != 1):
        raise ValueError("Unexpected blocker-count differences")

    return {
        "status": "flattened_runtime_release_blocked",
        "release_authorized": False,
        "scanner_gate": "blocked",
        "vex": "not_issued",
        "source_image": BEFORE, "source_image_id": before_id,
        "experimental_image": AFTER, "experimental_image_id": after_id,
        "before_layers": before_layers, "after_layers": after_layers,
        "nonempty_parent_layers_reused": 0,
        "removed_unused_env": ["GPG_KEY"],
        "removed_packages": sorted(removed_names), "removed_high": 1,
        "high_before": before_counts["HIGH"],
        "high_after": after_counts["HIGH"],
        "unknown_before": before_counts["UNKNOWN"],
        "unknown_after": after_counts["UNKNOWN"],
        "critical_before": before_counts["CRITICAL"],
        "critical_after": after_counts["CRITICAL"],
        "native_provenance_unchanged": True,
        "unapproved_package_changes": 0,
        "unapproved_vulnerability_changes": 0,
    }


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    fields=("before-scan","after-scan","before-sbom","after-sbom",
            "before-inspect","after-inspect","before-native","after-native",
            "before-expat","after-expat")
    for field in fields:
        parser.add_argument("--"+field,required=True,type=Path)
    args=parser.parse_args()
    try:
        report=verify_flattening(*(
            json.loads(getattr(args,field.replace("-","_")).read_text(encoding="utf-8"))
            for field in fields
        ))
    except (ValueError,TypeError,OSError,KeyError,AttributeError):
        print(json.dumps({"status":"error","reason":"flattened_runtime_evidence_invalid"}))
        return 3
    print(json.dumps(report,sort_keys=True))
    # This prototype cannot release independently of the blocked CVE gate.
    return 2


if __name__=="__main__":
    raise SystemExit(main())
