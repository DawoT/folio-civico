"""R1.42: reconcile hash-pinned Tesseract source excerpts with actual candidate ELF.

This is a cross-check, NOT a reproducible-build proof. It proves that an
existing local candidate contains the ELF/model/provenance fingerprints
already inventoried in the immutable R1.40 snapshot AND that its declared
tarball identity matches the SHA-pinned R1.42 source guard record.

The Dockerfile's source-provenance.json is self-declared build metadata,
not a signed compiler attestation. Accordingly G2 is never authorized.
No builds, installations, network, mounts, deployments, waivers, or VEX.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from snapshot_candidate_image import verify_snapshot
from source_inventory import (
    TESSERACT_METADATA, TESSERACT_SOURCE_SHA256,
)
from tesseract_554_guard_landmarks import (
    SOURCE_SHA, private_report, CVE_IDS,
)

SNAPSHOT_NATIVE = "native-source-inventory.json"
SNAPSHOT_MANIFEST = "SNAPSHOT_RESEARCH_ONLY.json"
IMAGE = "folio-civico-inspector:ocr-integrated"
IMAGE_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPORT_RE = re.compile(r"folio-r142-lineage-[a-z0-9_-]{4,80}\.json\Z")


def _json_private(path: Path, *, limit: int = 1_500_000) -> dict:
    if (path.is_symlink() or not path.is_file()
            or path.stat().st_size > limit
            or stat.S_IMODE(path.stat().st_mode) != 0o600):
        raise ValueError("Missing or unsafe private evidence")
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid private JSON") from error
    if not isinstance(result, dict):
        raise ValueError("Report is not a JSON object")
    return result


def _run(argv: list[str], timeout: int = 50) -> str:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Nonprivileged Docker proof unavailable") from error
    if result.returncode != 0:
        raise ValueError("Nonprivileged Docker proof failed")
    return result.stdout


def validated_context(snapshot_dir: Path, source_path: Path) -> tuple[dict, dict]:
    if not snapshot_dir.is_absolute() or snapshot_dir.parent != Path("/tmp"):
        raise ValueError("Only retained /tmp candidate evidence is accepted")
    summary = verify_snapshot(snapshot_dir)
    if (summary["audit_gate_status"] != "blocked"
            or summary["security_gate"] != "blocked"
            or summary["release_authorized"] is not False
            or not IMAGE_SHA.fullmatch(summary["image_id"])):
        raise ValueError("Candidate snapshot does not retain G2 block")
    source = private_report(source_path)
    if (source["security_gate"] != "blocked"
            or source["release_authorized"] is not False
            or source["source_tarball_sha256"] != SOURCE_SHA
            or SOURCE_SHA != TESSERACT_SOURCE_SHA256
            or set(source["guards"]) != set(CVE_IDS)
            or any(not row["source_guard_landmarks_present"]
                   for row in source["guards"].values())):
        raise ValueError("Source guard scope cannot be linked to candidate")
    saved = _json_private(snapshot_dir / SNAPSHOT_NATIVE)
    if (saved.get("mode") != "candidate"
            or saved.get("source") != "folio-local-elf-provenance-v1"
            or not isinstance(saved.get("components"), list)
            or len(saved["components"]) != 1
            or saved["components"][0].get("name") != "tesseract"
            or saved["components"][0].get("version") != "5.5.4"):
        raise ValueError("Candidate snapshot does not contain one Tesseract")
    saved_manifest = _json_private(snapshot_dir / SNAPSHOT_MANIFEST)
    if (saved_manifest.get("immutable_local_image_id") != summary["image_id"]
            or saved_manifest.get("native_inspector_sha256") !=
            hashlib.sha256(Path(__file__).with_name(
                "source_inventory.py").read_bytes()).hexdigest()):
        raise ValueError("Native inspector implementation/ID changed")
    return summary, {
        "source": source,
        "saved": saved,
        "native_inspector_sha256": saved_manifest["native_inspector_sha256"],
    }


def capture(snapshot_dir: Path, source_path: Path) -> dict:
    if os.geteuid() == 0:
        raise ValueError("Host root prohibited")
    host = os.environ.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        raise ValueError("Remote Docker host prohibited")
    context = _run([
        "docker", "context", "inspect",
        "--format", "{{.Endpoints.docker.Host}}",
    ], 20).strip()
    if not context.startswith("unix://"):
        raise ValueError("Local Docker socket required")
    snapshot, evidence = validated_context(snapshot_dir, source_path)
    image_id = snapshot["image_id"]
    def assert_tag() -> None:
        selected = _run([
            "docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"
        ], 20).strip()
        if selected != image_id:
            raise ValueError("Candidate tag was changed after audited snapshot")
    assert_tag()
    inspector = Path(__file__).with_name("source_inventory.py").read_text(
        encoding="utf-8"
    )
    output = _run([
        "docker", "run", "--rm", "--pull", "never",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--user", "65534:65534",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "4g", "--memory-swap", "4g",
        "--entrypoint", "python3", image_id,
        "-I", "-c", inspector, "--mode", "candidate",
    ], timeout=90)
    assert_tag()
    try:
        current = json.loads(output)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Runtime native inventory malformed") from error
    if current != evidence["saved"]:
        raise ValueError("Candidate ELF/model hashes diverged from R1.40")
    component = current["components"][0]
    if (TESSERACT_METADATA["source_sha256"] != SOURCE_SHA
            or component.get("automated_cve_coverage") != "not_verified"
            or component.get("cve_assessment") != "required"):
        raise ValueError("Candidate source metadata or assessment differs")
    return {
        "status": "local_candidate_elf_identity_reconciled_no_build_attestation",
        "candidate_image_tag": IMAGE,
        "candidate_immutable_local_image_id": image_id,
        "r140_snapshot_sha256": snapshot["report_sha256"],
        "r142_guard_report_sha256": evidence["source"]["report_sha256"],
        "source_tarball_sha256_in_build_metadata": SOURCE_SHA,
        "native_inspector_sha256": evidence["native_inspector_sha256"],
        "tesseract_executable_sha256": component["executable_sha256"],
        "tesseract_library_sha256": component["library_sha256"],
        "tesseract_provenance_json_sha256": component["provenance_sha256"],
        "ocr_model_sha256": component["model_sha256"],
        "runtime_inventory_matches_R140": True,
        "cve_guard_landmarks_present_in_pinned_source": True,
        "source_to_ELF_reproducible_build_attested": False,
        "signed_binary_build_provenance": False,
        "full_runtime_CVE_regressions_passed": False,
        "registry_manifest_digest_attested": False,
        "complete_source_advisory_coverage": False,
        "vex": "not_issued",
        "security_gate": "blocked",
        "release_authorized": False,
    }


def verify_receipt(path: Path, snapshot_dir: Path, source_path: Path) -> dict:
    if (not path.is_absolute() or path.parent != Path("/tmp")
            or not REPORT_RE.fullmatch(path.name)):
        raise ValueError("Lineage report must be private /tmp")
    report = _json_private(path)
    snapshot, evidence = validated_context(snapshot_dir, source_path)
    fixed = {
        "status": "local_candidate_elf_identity_reconciled_no_build_attestation",
        "candidate_image_tag": IMAGE,
        "candidate_immutable_local_image_id": snapshot["image_id"],
        "r140_snapshot_sha256": snapshot["report_sha256"],
        "r142_guard_report_sha256": evidence["source"]["report_sha256"],
        "source_tarball_sha256_in_build_metadata": SOURCE_SHA,
        "native_inspector_sha256": evidence["native_inspector_sha256"],
        "runtime_inventory_matches_R140": True,
        "cve_guard_landmarks_present_in_pinned_source": True,
        "source_to_ELF_reproducible_build_attested": False,
        "signed_binary_build_provenance": False,
        "full_runtime_CVE_regressions_passed": False,
        "registry_manifest_digest_attested": False,
        "complete_source_advisory_coverage": False,
        "vex": "not_issued",
        "security_gate": "blocked",
        "release_authorized": False,
    }
    comp = evidence["saved"]["components"][0]
    fixed.update({
        "tesseract_executable_sha256": comp["executable_sha256"],
        "tesseract_library_sha256": comp["library_sha256"],
        "tesseract_provenance_json_sha256": comp["provenance_sha256"],
        "ocr_model_sha256": comp["model_sha256"],
    })
    if report != fixed:
        raise ValueError("Lineage report contains an unsupported identity or claim")
    return {
        "status": "offline_candidate_lineage_consistent_without_build_proof",
        "image_id": snapshot["image_id"],
        "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "source_to_ELF_reproducible_build_attested": False,
        "security_gate": "blocked",
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument("--source-report", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", type=Path)
    args = parser.parse_args()
    try:
        if args.verify_only is not None:
            result = verify_receipt(args.verify_only,
                                    args.snapshot_dir, args.source_report)
        else:
            result = capture(args.snapshot_dir, args.source_report)
            if args.output is not None:
                path = args.output
                if (not path.is_absolute() or path.parent != Path("/tmp")
                        or not REPORT_RE.fullmatch(path.name)
                        or path.is_symlink() or path.exists()):
                    raise ValueError("New /tmp research receipt path required")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as out:
                    json.dump(result, out, sort_keys=True, indent=2)
                    out.write("\n")
        print(json.dumps(result, sort_keys=True))
        return 2  # Credible evidence cannot override the blocked G2 gate.
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({
            "status": "candidate_lineage_evidence_unverified",
            "security_gate": "blocked", "release_authorized": False,
        }, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
