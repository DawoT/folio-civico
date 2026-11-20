"""R1.40: preserve a private, read-only audit of an exact *local* inspector image.

This research tool scans the existing candidate tag using Trivy while pinning
and repeatedly checking its SHA-256 image ID. It retains raw vulnerability
JSON, CycloneDX, and native-source evidence for reproducibility. It NEVER
installs packages, builds/pushes an image, issues VEX or authorizes a release.

Exit 2: evidence recorded, release remains BLOCKED, even if scan gate passed.
Exit 3: incomplete or untrusted evidence; partial results marked UNVERIFIED.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from audit_image import evaluate_image_audit
from advisory_inventory import targeted_advisories

IMAGE = "folio-civico-inspector:ocr-integrated"
MODE = "candidate"
FILES = (
    "trivy-vulnerabilities.json",
    "trivy-cyclonedx.json",
    "native-source-inventory.json",
    "advisories.json",
    "SNAPSHOT_RESEARCH_ONLY.json",
)
INCOMPLETE = "UNVERIFIED_INCOMPLETE.txt"
SOURCE_FILE = Path(__file__).with_name("source_inventory.py")
IMAGE_SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
CVE_SET = frozenset((
    "CVE-2026-76642", "CVE-2026-78408",
    "CVE-2026-78409", "CVE-2026-78410",
))


def _run(argv: list[str], timeout: int = 180) -> str:
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Auditing subprocess could not complete") from error
    if done.returncode != 0:
        raise ValueError("Inspector candidate evidence collection failed")
    return done.stdout


def _image_id() -> str:
    image = _run([
        "docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"
    ], 20).strip()
    if not IMAGE_SHA.fullmatch(image):
        raise ValueError("Candidate image ID not a SHA-256")
    return image


def validate_output(dest: Path) -> None:
    if (not dest.is_absolute() or dest.parent != Path("/tmp")
            or not re.fullmatch(r"folio-r140-[a-z0-9_-]{4,80}", dest.name)
            or dest.exists() or dest.is_symlink()
            or dest.parent.is_symlink()
            or dest.parent.resolve(strict=True) != dest.parent):
        raise ValueError("Snapshot must use a new private /tmp/folio-r140-* path")


def _sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(data)
    return sha.hexdigest()


def _save_json(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("Snapshot output file already exists")
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    os.chmod(path, 0o600)


def _read_json(path: Path, *, max_bytes: int = 50 * 1024 * 1024) -> dict:
    if (not path.is_file() or path.is_symlink()
            or path.stat().st_size > max_bytes):
        raise ValueError("Trivy report missing/unsafe/oversized")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid scanner JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Report root must be an object")
    os.chmod(path, 0o600)
    return value


def _ensure_same(original: str) -> None:
    if _image_id() != original:
        raise ValueError("Candidate tag moved during audit; discard snapshot")


def summarize_cve_findings(vulnerabilities: dict) -> dict:
    """Record exact Trivy findings without treating missing scans as a waiver."""
    found: dict[str, list[dict[str, str]]] = {name: [] for name in CVE_SET}
    for section in vulnerabilities.get("Results", []):
        if not isinstance(section, dict):
            raise ValueError("Invalid Trivy target")
        for entry in section.get("Vulnerabilities") or []:
            if not isinstance(entry, dict):
                raise ValueError("Invalid Trivy vulnerability")
            cve = entry.get("VulnerabilityID")
            if cve not in found:
                continue
            for k in ("PkgName", "InstalledVersion", "Severity"):
                if not isinstance(entry.get(k), str):
                    raise ValueError("Invalid selected CVE evidence")
            found[cve].append({
                "package": entry["PkgName"],
                "installed_version": entry["InstalledVersion"],
                "severity": entry["Severity"],
                "fixed_version": entry.get("FixedVersion") or "",
            })
    return {
        "tracker_remains_authoritative": True,
        "scanner_findings": {cve: sorted(rows, key=lambda x: (
            x["package"], x["installed_version"], x["severity"]
        )) for cve, rows in sorted(found.items())},
        "scanner_absence_does_not_mean_not_affected": True,
        "cve_remediated": False,
        "vex": "not_issued",
    }


def capture_snapshot(dest: Path) -> dict:
    if os.geteuid() == 0:
        raise ValueError("Host-root audit not allowed")
    validate_output(dest)
    host = os.environ.get("DOCKER_HOST")
    if host and not host.startswith("unix://"):
        raise ValueError("Remote Docker host prohibited")
    context = _run([
        "docker", "context", "inspect", "--format",
        "{{.Endpoints.docker.Host}}",
    ], 20).strip()
    if not context.startswith("unix://"):
        raise ValueError("Local Docker Unix socket required")

    original_id = _image_id()
    # An explicit private local path. Never remove or overwrite prior evidence.
    dest.mkdir(mode=0o700)
    marker = dest / INCOMPLETE
    marker.write_text("INCOMPLETE: no conclusions or release are authorized\n",
                      encoding="utf-8")
    os.chmod(marker, 0o600)

    sources = SOURCE_FILE.read_text(encoding="utf-8")
    if not sources.strip() or len(sources) > 100_000:
        raise ValueError("Local native source inspector missing/oversized")

    vuln_path = dest / FILES[0]
    bom_path = dest / FILES[1]
    _run([
        "trivy", "image", "--scanners", "vuln", "--format", "json",
        "--output", str(vuln_path), "--no-progress",
        "--image-src", "docker", IMAGE,
    ], 240)
    vulnerabilities = _read_json(vuln_path)
    _ensure_same(original_id)
    _run([
        "trivy", "image", "--scanners", "vuln", "--format", "cyclonedx",
        "--output", str(bom_path), "--no-progress",
        "--image-src", "docker", IMAGE,
    ], 240)
    bill = _read_json(bom_path)
    _ensure_same(original_id)

    native = _run([
        "docker", "run", "--rm", "--pull", "never",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--user", "65534:65534",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "4g", "--memory-swap", "4g",
        "--entrypoint", "python3", original_id,
        "-I", "-c", sources, "--mode", MODE,
    ], 90)
    try:
        native_report = json.loads(native)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid isolated native-source report") from error
    if not isinstance(native_report, dict):
        raise ValueError("Invalid native source report root")
    _save_json(dest / FILES[2], native_report)
    _ensure_same(original_id)

    # Reuse exactly the project-authoritative gate and advisory inventory.
    audit = evaluate_image_audit(vulnerabilities, bill, IMAGE, native_report)
    advisory = targeted_advisories(vulnerabilities, bill, IMAGE, native_report)
    if advisory["status"] != audit["status"]:
        raise ValueError("Advisory and audit gates disagree")
    _save_json(dest / FILES[3], advisory)
    _ensure_same(original_id)

    if not isinstance(audit["high"], int) or not isinstance(audit["unknown"], int):
        raise ValueError("Incomplete security summary")
    report = {
        "status": "candidate_snapshot_evidence_release_blocked",
        "image_tag": IMAGE,
        "immutable_local_image_id": original_id,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "native_inspector_sha256": hashlib.sha256(
            sources.encode("utf-8")
        ).hexdigest(),
        "source_version_in_image": "not_claimed_from_tag",
        "audit_gate": audit,
        "advisories": {
            "selected_blocking": advisory["selected_blocking"],
            "selected_cve_total": advisory["native_selected_cve_count"],
            "source_built_coverage_verified": advisory[
                "source_built_coverage_verified"
            ],
        },
        "four_util_linux_cves": summarize_cve_findings(vulnerabilities),
        "evidence_sha256": {
            name: _sha256(dest / name) for name in FILES[:-1]
        },
        "candidate_selected_by_mutable_tag_only_for_read": True,
        "native_inventory_execution_uid_gid": "65534:65534",
        "image_tag_stable_across_scan": True,
        "image_push_or_deployment_executed": False,
        "vex": "not_issued",
        "security_gate": "blocked",
        "release_authorized": False,
    }
    _save_json(dest / FILES[-1], report)
    # The final identity check precedes the removal of the UNVERIFIED marker.
    _ensure_same(original_id)
    marker.unlink()
    return report


def verify_snapshot(folder: Path) -> dict:
    """Independently rehash and reevaluate the retained reports without Docker."""
    if (not folder.is_absolute() or folder.parent != Path("/tmp")
            or folder.is_symlink() or not folder.is_dir()
            or not re.fullmatch(r"folio-r140-[a-z0-9_-]{4,80}", folder.name)
            or stat.S_IMODE(folder.stat().st_mode) != 0o700
            or {p.name for p in folder.iterdir()} != set(FILES)):
        raise ValueError("Snapshot is incomplete or not a private fixed set")
    for name in FILES:
        item = folder / name
        if (item.is_symlink() or not item.is_file()
                or stat.S_IMODE(item.stat().st_mode) != 0o600):
            raise ValueError("Snapshot file is not a safe immutable candidate")
    report = _read_json(folder / FILES[-1])
    if (report.get("status") != "candidate_snapshot_evidence_release_blocked"
            or report.get("image_tag") != IMAGE
            or not isinstance(report.get("immutable_local_image_id"), str)
            or not IMAGE_SHA.fullmatch(report["immutable_local_image_id"])
            or report.get("release_authorized") is not False
            or report.get("security_gate") != "blocked"
            or report.get("vex") != "not_issued"
            or report.get("image_push_or_deployment_executed") is not False
            or report.get("image_tag_stable_across_scan") is not True
            or report.get("native_inventory_execution_uid_gid") != "65534:65534"):
        raise ValueError("Research snapshot release state or image ID changed")
    hashes = report.get("evidence_sha256")
    if (not isinstance(hashes, dict)
            or set(hashes) != set(FILES[:-1])
            or any(not isinstance(sha, str)
                   or not re.fullmatch("[a-f0-9]{64}", sha)
                   or _sha256(folder / name) != sha
                   for name, sha in hashes.items())):
        raise ValueError("Raw Trivy or native report hashes do not match")
    if report.get("native_inspector_sha256") != _sha256(SOURCE_FILE):
        raise ValueError("Native inspector implementation no longer matches")
    vulnerabilities = _read_json(folder / FILES[0])
    bill = _read_json(folder / FILES[1])
    native = _read_json(folder / FILES[2])
    diagnostic = _read_json(folder / FILES[3])
    independently_audited = evaluate_image_audit(
        vulnerabilities, bill, IMAGE, native
    )
    independently_diagnosed = targeted_advisories(
        vulnerabilities, bill, IMAGE, native
    )
    if (report.get("audit_gate") != independently_audited
            or diagnostic != independently_diagnosed
            or report.get("advisories") != {
                "selected_blocking": diagnostic["selected_blocking"],
                "selected_cve_total": diagnostic["native_selected_cve_count"],
                "source_built_coverage_verified": diagnostic[
                    "source_built_coverage_verified"
                ],
            }
            or report.get("four_util_linux_cves") !=
            summarize_cve_findings(vulnerabilities)):
        raise ValueError("Snapshot totals or advisory classifications diverge")
    return {
        "status": "independently_verified_research_release_blocked",
        "image_id": report["immutable_local_image_id"],
        "report_sha256": _sha256(folder / FILES[-1]),
        "audit_gate_status": independently_audited["status"],
        "blocking_count": sum(independently_audited[k]
                              for k in ("critical", "high", "unknown")),
        "release_authorized": False,
        "security_gate": "blocked",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_only:
            verified = verify_snapshot(args.output_dir)
            print(json.dumps(verified, sort_keys=True))
            return 2
        report = capture_snapshot(args.output_dir)
    except (ValueError, OSError, TypeError, KeyError):
        print(json.dumps({
            "status": "error", "reason": "candidate_snapshot_unverified",
            "security_gate": "blocked", "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps({
        "status": report["status"],
        "image_id": report["immutable_local_image_id"],
        "audit_status": report["audit_gate"]["status"],
        "high": report["audit_gate"]["high"],
        "critical": report["audit_gate"]["critical"],
        "unknown": report["audit_gate"]["unknown"],
        "native_unassessed": report["audit_gate"]["source_components_unassessed"],
        "four_cve_package_counts": {
            cve: len(rows) for cve, rows in
            report["four_util_linux_cves"]["scanner_findings"].items()
        },
        "evidence_sha256": report["evidence_sha256"],
        "release_authorized": False,
    }, sort_keys=True))
    return 2  # Complete research evidence is NOT an authorization.


if __name__ == "__main__":
    raise SystemExit(main())
