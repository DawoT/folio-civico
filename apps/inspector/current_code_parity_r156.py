"""R1.56 research: immutable source-to-runtime Python parity, NOT CVE remediation.

Only the seven named first-party Python files may be altered. Complete
rootfs differential is required; a partial inventory cannot pass.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from audit_image import verify_native_source_inventory
from gnupg_flat_prune_comparison import EMPTY_LAYER
from privileged_cli_prune_audit import _filesystem, _privileged_regular
from runtime_prune_comparison import DIGEST, _scan, _sbom

BASE_ID = "sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327"
BASE_NAME = "folio-civico-inspector:combined-clamav-cli-r155-local"
CANDIDATE_NAME = "folio-civico-inspector:current-code-parity-no-pyc-r156-local"
CODE_FILES = (
    "fixtures.py", "inspector.py", "preflight.py",
    "qpdf_paint_triage_r154.py", "qpdf_scoped_gate_r155.py",
    "smoke_http_real.py", "smoke_real_engines.py",
)
EXPECTED_ADDED = {"qpdf_paint_triage_r154.py", "qpdf_scoped_gate_r155.py"}
EXPECTED_CHANGED = {"fixtures.py", "inspector.py", "preflight.py"}
EXPECTED_IDENTICAL = {"smoke_http_real.py", "smoke_real_engines.py"}
PREFIX = "/srv/folio-inspector/"
STALE_CACHE = PREFIX + "__pycache__"
STALE_PYC = STALE_CACHE + "/inspector.cpython-312.pyc"
STALE_PYC_SHA = "834cf9412cec3e83fee99c0480847e50d0d32952bd1f768dc08033682bfc81ea"
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
MAX_EVIDENCE_BYTES = 24 * 1024 * 1024


def compare_code_roots(before: dict, after: dict, source: dict) -> dict:
    """Reject any OS, native engine, signature, or executable modification."""
    if not isinstance(source, dict) or set(source) != set(CODE_FILES):
        raise ValueError("Required complete main source manifest missing")
    if any(not isinstance(h, str) or not SHA256.fullmatch(h) for h in source.values()):
        raise ValueError("Source SHA-256 manifest malformed")
    old, new = _filesystem(before), _filesystem(after)
    if set(new) - set(old) != {PREFIX + n for n in EXPECTED_ADDED}:
        raise ValueError("Unexpected new rootfs files")
    if set(old) - set(new) != {STALE_CACHE, STALE_PYC}:
        raise ValueError("Unexpected deleted rootfs entries")
    if (old[STALE_CACHE] != {"kind": "directory", "mode": "0o755"}
            or old[STALE_PYC] != {"kind": "file", "mode": "0o644",
                                  "sha256": STALE_PYC_SHA}):
        raise ValueError("Legacy compiled Python code lacks immutable provenance")
    changed = {p for p in set(old) & set(new) if old[p] != new[p]}
    if changed != {PREFIX + n for n in EXPECTED_CHANGED}:
        raise ValueError("Unexpected mutated runtime file")
    if _privileged_regular(new):
        raise ValueError("SUID/SGID regular file survived")
    for filename in CODE_FILES:
        path = PREFIX + filename
        value = new.get(path)
        # Preserve the pinned source-image permission contract verbatim.
        if value != {"kind": "file", "mode": "0o664", "sha256": source[filename]}:
            raise ValueError("Current main code bytes/mode differ in candidate")
        if filename in EXPECTED_IDENTICAL and old[path] != value:
            raise ValueError("Unchanged source unexpectedly modified")
    return {
        "main_code_parity": "verified_by_sha256", "code_matches_main": True,
        "changed_python": sorted(EXPECTED_CHANGED),
        "added_python": sorted(EXPECTED_ADDED),
        "unchanged_python": sorted(EXPECTED_IDENTICAL),
        "fs_path_count_before": len(old), "fs_path_count_after": len(new),
        "native_or_signature_mutations": 0, "suid_sgid_after": 0,
        "deleted_stale_bytecode": 2,
        "scanner_gate": "blocked", "release_authorized": False,
    }


def compare_image_metadata(before: dict, after: dict, candidate_id: str) -> None:
    if (not isinstance(before, dict) or not isinstance(after, dict)
            or before.get("Id") != BASE_ID or after.get("Id") != candidate_id
            or not isinstance(candidate_id, str) or not DIGEST.fullmatch(candidate_id)
            or BASE_ID == candidate_id):
        raise ValueError("Docker identity mismatch")
    for record in (before, after):
        if record.get("Os") != "linux" or record.get("Architecture") != "amd64":
            raise ValueError("Unexpected architecture")
        root = record.get("RootFS")
        layers = root.get("Layers") if isinstance(root, dict) else None
        if (not isinstance(root, dict) or root.get("Type") != "layers"
                or not isinstance(layers, list) or len(layers) != 2
                or layers.count(EMPTY_LAYER) != 1
                or any(not isinstance(row, str) or not DIGEST.fullmatch(row)
                           for row in layers)):
            raise ValueError("Expected flattened OCI filesystem")
    old_layer = set(before["RootFS"]["Layers"]) - {EMPTY_LAYER}
    new_layer = set(after["RootFS"]["Layers"]) - {EMPTY_LAYER}
    if old_layer & new_layer:
        raise ValueError("Old deletions recoverable from inherited layer")
    config = after.get("Config")
    if (not isinstance(config, dict) or config != before.get("Config")
            or config.get("User") != "65534:65534"
            or config.get("Entrypoint") is not None
            or config.get("Cmd") != [
                "python3", "-I", "/srv/folio-inspector/inspector.py"
            ] or config.get("WorkingDir") != "/srv/folio-inspector"):
        raise ValueError("Inspector runtime metadata changed")


def compare_security_evidence(base_scan: dict, current_scan: dict,
                              base_sbom: dict, current_sbom: dict,
                              candidate_id: str, base_native: dict,
                              current_native: dict) -> dict:
    """Same vuln records/SBOM/ELF; changing code cannot erase CVEs."""
    old_findings = _scan(base_scan, BASE_NAME)
    new_findings = _scan(current_scan, CANDIDATE_NAME)
    if not old_findings or old_findings != new_findings:
        raise ValueError("Vulnerability records disappeared, were added or changed")
    old_pkgs = _sbom(base_sbom, BASE_NAME, BASE_ID)
    new_pkgs = _sbom(current_sbom, CANDIDATE_NAME, candidate_id)
    if not old_pkgs or old_pkgs != new_pkgs:
        raise ValueError("OS/dependency SBOM does not match")
    if not isinstance(base_native, dict) or base_native != current_native:
        raise ValueError("Native source/ELF/model inventory altered")
    if verify_native_source_inventory(base_native, "folio-civico-inspector:poppler-experiment") != 2:
        raise ValueError("Native source-to-ELF coverage incomplete")
    counts = Counter()
    for key, amount in new_findings.items():
        counts[key[-1]] += amount
    return {
        "same_all_trivy_findings": True,
        "same_cyclonedx_packages": True,
        "same_elf_and_ocr_models": True,
        "cve_counts": dict(sorted(counts.items())),
        "scanner_gate": "blocked", "release_authorized": False,
    }


def _read(path: Path) -> dict:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ValueError("Evidence file missing or too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Nonobject evidence")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for kind in ("base-fs", "candidate-fs", "manifest", "base-inspect",
                 "candidate-inspect", "base-scan", "candidate-scan",
                 "base-sbom", "candidate-sbom", "base-native",
                 "candidate-native"):
        parser.add_argument("--" + kind, type=Path, required=True)
    parser.add_argument("--candidate-id", required=True)
    args = parser.parse_args()
    try:
        evidence = {key: _read(getattr(args, key.replace("-", "_")))
                    for key in ("base-fs", "candidate-fs", "manifest",
                                "base-inspect", "candidate-inspect", "base-scan",
                                "candidate-scan", "base-sbom", "candidate-sbom",
                                "base-native", "candidate-native")}
        result = compare_code_roots(evidence["base-fs"], evidence["candidate-fs"],
                                    evidence["manifest"])
        compare_image_metadata(evidence["base-inspect"],
                               evidence["candidate-inspect"], args.candidate_id)
        result.update(compare_security_evidence(
            evidence["base-scan"], evidence["candidate-scan"],
            evidence["base-sbom"], evidence["candidate-sbom"],
            args.candidate_id, evidence["base-native"],
            evidence["candidate-native"],
        ))
        result.update({
            "status": "current_main_code_parity_verified_release_blocked",
            "base_image_id": BASE_ID, "candidate_image_id": args.candidate_id,
        })
        print(json.dumps(result, sort_keys=True))
        return 2
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        print(json.dumps({"status": "code_parity_evidence_incomplete",
                          "scanner_gate": "blocked", "release_authorized": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
