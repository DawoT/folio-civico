"""R1.41: attest Tesseract 5.5.4 source security-patch *postimages*, no release.

Pins Debian's upstream tarball SHA-256 and 14 fixed upstream Git commit
patch SHA-256 receipts. The isolated worker fetches these ONLY via HTTPS in
a disposable non-root Docker container, with no bind mounts. Every C/C++
source hunk's postimage (context + additions) is compared with actual lines
in the hash-admitted source archive. Partial matches remain UNRESOLVED.

This is source-only, not compiled-ELF attestation, an exploit regression, VEX,
a vulnerability exception, or complete security advisory coverage.
Success of evidence capture exits 2 and ALWAYS leaves G2 BLOCKED.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
from urllib.request import Request, urlopen

SOURCE_VERSION = "5.5.4"
SOURCE_TARBALL_SHA256 = "a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4"
SOURCE_URL = (
    "https://deb.debian.org/debian/pool/main/t/tesseract/"
    "tesseract_5.5.4.orig.tar.gz"
)
PINNED_COMMITS = {
    "CVE-2026-119341": (
        "614e971036d2b95d521057ff63d68d6612429b23",
        "6e93bb69ae3ab141eb19b5f86f3d92530ac9cb294b4be767f0986163c67788b1",
    ),
    "CVE-2026-119340": (
        "048e92378f1a34dcdaf94bc515c7552ac01f08ef",
        "403e460a2a9dcc8b15bbda0ba22c60b12c8c9a0551b528d04e97a802c39ba9f9",
    ),
    "CVE-2026-119339": (
        "c053424327352b9d5180aa7540c1f9e67c64f27e",
        "647fd496013b6980186b71bacc89878d0923e70e17f1312e5c96260abbba8399",
    ),
    "CVE-2026-119338": (
        "fa52414ff1fd13ae4b00048d2498f9141b0bc2eb",
        "ce65072e307541f7596fa3dd5676ea5b211104fbba6389e94698491d5792ce1f",
    ),
    "CVE-2026-88054": (
        "552771236b0d80cbdb0c7dd856120fa21a4672e5",
        "ca37052968d23df294029148d082f57b6287849303e24688dbb7057df11cbeea",
    ),
    "CVE-2026-88053": (
        "8b0574680f3b22f246ade6a4c8e3029104255c63",
        "1b80580e4d3e33f9f4d31e3f88cddbf2a7ede75408d2ccc4159ece6acbcd4b46",
    ),
    "CVE-2026-88052": (
        "2d04d640db2e8c7e3bab2369d599343b5a8b8443",
        "8bfd76c5dbe80249ad48152d286fc87fcefd8a57129099413a70476321cb7feb",
    ),
    "CVE-2026-88051": (
        "56e09ca12e751623fe796ce1554ce704bffd2ef0",
        "fe931cd9ccc6787ef22076d9b12507b6429043e0f7792272bdbc8e3c47cacf41",
    ),
    "CVE-2026-88050": (
        "c94a5532ee04db5a4919542832fd94caee5ea58f",
        "b474e6f65e613143df005f92170e049f08f09144bd64bf1babb548a524d54dbb",
    ),
    "CVE-2026-88049": (
        "b494ac18925f9d9aff9ef5815475de9943ab19bf",
        "b6860ee415aa0f7a5a73d79e8de115f99c09fa66fc010dd7cb7469f4eb10963f",
    ),
    "CVE-2026-88048": (
        "103dc134eb36411ddc6833ec20aa2c76795bd0ff",
        "21af537b323ccfd44501ec07b54476580c8132499de2bd5014ddbff46cc114dd",
    ),
    "CVE-2026-88047": (
        "1bda5079b1c8a7e25f523486837426903d29ce84",
        "81cfeadb66eaaa62215963f4eb613212da3b153cac3685e1c8b8b6d19a9e6980",
    ),
    "CVE-2026-73067": (
        "55287a94b8044c05ce3fd10f5aca6ebbd238e518",
        "6131e3be7c0d8e789c425fbbb31cc5c9108c002cc3dc661645bc787f0eb364e0",
    ),
    "CVE-2026-73066": (
        "2f4d2f4bf45c363785d7bf1da29b6628f8939a72",
        "3c9d471d9c261ed641697bceb1ca10280016c8c3d48e624013d6c2254696e27e",
    ),
}
MAX_TAR = 8_000_000
MAX_PATCH = 800_000
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_HASH = re.compile(r"^[0-9a-f]{40}$")
IMAGE = "python:3.12-slim"


def validate_manifest() -> None:
    from native_advisory_ledger import SOURCE_CVES
    if set(PINNED_COMMITS) != set(SOURCE_CVES["tesseract"]):
        raise ValueError("Tesseract CVE manifest not identical to G2 backlog")
    if len(PINNED_COMMITS) != 14 or len({
        x[0] for x in PINNED_COMMITS.values()
    }) != 14:
        raise ValueError("CVE commit coverage is incomplete or ambiguous")
    if any(not GIT_HASH.fullmatch(commit) or not SHA256.fullmatch(sha)
           for commit, sha in PINNED_COMMITS.values()):
        raise ValueError("Invalid upstream patch hashes")


def archive_sources(content: bytes) -> dict[str, tuple[str, ...]]:
    """Read only bounded regular C/C++ files directly; do not extract archive."""
    if (len(content) > MAX_TAR
            or hashlib.sha256(content).hexdigest() != SOURCE_TARBALL_SHA256):
        raise ValueError("Source tarball hash not pinned to Dockerfile")
    source: dict[str, tuple[str, ...]] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
            for member in tar.getmembers():
                prefix = "tesseract-5.5.4/"
                if not member.name.startswith(prefix):
                    continue
                name = member.name[len(prefix):]
                if (not name.startswith("src/")
                        or not name.endswith((".cpp", ".h", ".cc", ".c"))
                        or not member.isfile()):
                    continue
                if member.size > 2_000_000 or name in source:
                    raise ValueError("Oversized or repeated Tesseract source")
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise ValueError("Missing archived source stream")
                source[name] = tuple(
                    extracted.read().decode("utf-8").splitlines()
                )
    except (tarfile.TarError, UnicodeError) as error:
        raise ValueError("Malformed Tesseract source archive") from error
    if len(source) < 100:
        raise ValueError("Incomplete upstream 5.5.4 source archive")
    return source


def patch_hunks(patch: str) -> list[tuple[str, tuple[str, ...]]]:
    """Parse source-code postimages; omit makefile/test changes, not missing src hunks."""
    file: str | None = None
    current: list[str] = []
    added = 0
    removed = 0
    rows: list[tuple[str, tuple[str, ...]]] = []

    def flush() -> None:
        if file is not None and file.startswith("src/") and removed and not added:
            rows.append((file, ()))  # explicit unresolved deletion-only hunk
        if file is not None and file.startswith("src/") and added:
            if len(current) < 2:
                raise ValueError("Security patch hunk is too short to attribute")
            rows.append((file, tuple(current)))

    for line in patch.splitlines():
        if line.startswith("-- "):
            break  # git-format-patch trailer is not part of the last hunk
        if line.startswith("diff --git "):
            flush()
            fields = line.split(" b/")
            if len(fields) != 2:
                raise ValueError("Invalid patch file header")
            file = fields[1]
            if (file.startswith("/") or ".." in file.split("/")
                    or "\x00" in file):
                raise ValueError("Unsafe upstream patch file")
            current = []
            added = 0
            removed = 0
        elif line.startswith("@@ "):
            flush()
            current = []
            added = 0
            removed = 0
        elif line.startswith((" ", "+")) and not line.startswith("+++"):
            current.append(line[1:])
            added += line[0] == "+"
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    flush()
    if not rows or len(rows) > 120:
        raise ValueError("No bounded upstream security patch source hunks")
    return rows


def probe_postimages(
    sources: dict[str, tuple[str, ...]], patch_text: str,
) -> dict:
    results = []
    for name, hunk in patch_hunks(patch_text):
        source = sources.get(name)
        if source is None:
            raise ValueError("Expected source file absent from pinned tarball")
        found = bool(hunk) and any(source[i:i+len(hunk)] == hunk
                    for i in range(len(source) - len(hunk) + 1))
        results.append({"file": name, "postimage_exact": found,
                        "deletion_only": not bool(hunk)})
    matched = sum(x["postimage_exact"] for x in results)
    return {
        "source_hunks": len(results),
        "exact_postimage_hunks": matched,
        "status": "all_source_postimages_exact"
                  if matched == len(results) else "partial_unresolved",
        "unresolved_paths": sorted({
            x["file"] for x in results if not x["postimage_exact"]
        }),
    }


def _fetch(url: str, limit: int) -> bytes:
    # Only the pinned Debian source and 14 fixed-commit GitHub patch URLs.
    if not (url == SOURCE_URL or url.startswith(
            "https://github.com/tesseract-ocr/tesseract/commit/"
    ) and url.endswith(".patch")):
        raise ValueError("Unapproved source download URL")
    with urlopen(Request(url, headers={
        "User-Agent": "FolioCivicoTesseractSourceR141/1.0"
    }), timeout=35) as stream:
        result = stream.read(limit+1)
    if len(result) > limit or not result:
        raise ValueError("Oversized or unavailable upstream source")
    return result


def worker() -> dict:
    data = _fetch(SOURCE_URL, MAX_TAR)
    sources = archive_sources(data)
    rows = {}
    for cve, (commit, expected) in sorted(PINNED_COMMITS.items()):
        url = (
            "https://github.com/tesseract-ocr/tesseract/commit/"
            + commit + ".patch"
        )
        content = _fetch(url, MAX_PATCH)
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise ValueError("Git patch bytes differ from pinned receipt")
        patch = content.decode("utf-8")
        if not patch.startswith("From "+commit+" "):
            raise ValueError("Git patch content is not the requested commit")
        details = probe_postimages(sources, patch)
        rows[cve] = {
            "upstream_commit": commit,
            "upstream_commit_patch_sha256": expected,
            **details,
        }
    exact = sum(x["status"] == "all_source_postimages_exact"
                for x in rows.values())
    return {
        "status": "source_hunks_research_release_blocked",
        "source_version": SOURCE_VERSION,
        "source_tarball_sha256": SOURCE_TARBALL_SHA256,
        "source_url": SOURCE_URL,
        "cve_results": rows,
        "cves_with_all_source_hunks_exact": exact,
        "cves_partially_unresolved": sorted(
            x for x in rows if rows[x]["status"] !=
            "all_source_postimages_exact"
        ),
        "patch_files_signed_by_vendor": False,
        "compiled_elf_bound_to_source_by_build_attestation": False,
        "full_cve_runtime_exploit_tests": False,
        "complete_source_advisory_coverage": False,
        "scanner_findings_suppressed": False,
        "vex": "not_issued",
        "security_gate": "blocked",
        "release_authorized": False,
    }


def _command(argv: list[str], timeout: int = 300,
             expected: tuple[int, ...] = (0,)) -> str:
    try:
        result = subprocess.run(
            argv, text=True, capture_output=True, check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Source research subprocess failed") from error
    if result.returncode not in expected:
        raise ValueError("Source research subprocess returned an unexpected code")
    return result.stdout


def host_probe() -> dict:
    validate_manifest()
    if os.geteuid() == 0:
        raise ValueError("Host root prohibited")
    remote = os.environ.get("DOCKER_HOST", "")
    if remote and not remote.startswith("unix://"):
        raise ValueError("Remote Docker endpoint forbidden")
    context = _command([
        "docker", "context", "inspect", "--format",
        "{{.Endpoints.docker.Host}}"
    ], 20).strip()
    if not context.startswith("unix://"):
        raise ValueError("Local Docker socket required")
    id = _command([
        "docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"
    ], 20).strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", id):
        raise ValueError("No pinned local Python image")
    source = Path(__file__).read_text(encoding="utf-8")
    output = _command([
        "docker", "run", "--rm", "--pull", "never",
        "--network", "bridge", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--pids-limit", "32", "--cpus", "1", "--memory", "512m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--entrypoint", "python", id, "-I", "-c", source, "--worker",
    ], 600, expected=(2,))
    try:
        report = json.loads(output)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Isolated report is invalid") from error
    if not isinstance(report, dict):
        raise ValueError("Isolated report must be an object")
    if (set(report.get("cve_results", {})) != set(PINNED_COMMITS)
            or report.get("source_tarball_sha256") != SOURCE_TARBALL_SHA256
            or report.get("security_gate") != "blocked"
            or report.get("release_authorized") is not False):
        raise ValueError("Isolated report claims unsupported security state")
    for key, (commit, sha) in PINNED_COMMITS.items():
        row = report["cve_results"][key]
        if row.get("upstream_commit") != commit or row.get(
                "upstream_commit_patch_sha256") != sha:
            raise ValueError("CVE commit receipts mismatch")
    report["isolation_container_image_id"] = id
    report["source_probe_script_sha256"] = hashlib.sha256(
        source.encode("utf-8")
    ).hexdigest()
    return report


def verify_report(report: dict) -> dict:
    """Recompute every count and pinned receipt; never infer exploit safety."""
    validate_manifest()
    if not isinstance(report, dict) or set(report.get(
            "cve_results", {})) != set(PINNED_COMMITS):
        raise ValueError("Research report does not cover all 14 CVEs")
    fixed = {
        "status": "source_hunks_research_release_blocked",
        "source_version": SOURCE_VERSION,
        "source_tarball_sha256": SOURCE_TARBALL_SHA256,
        "source_url": SOURCE_URL,
        "patch_files_signed_by_vendor": False,
        "compiled_elf_bound_to_source_by_build_attestation": False,
        "full_cve_runtime_exploit_tests": False,
        "complete_source_advisory_coverage": False,
        "scanner_findings_suppressed": False,
        "vex": "not_issued",
        "security_gate": "blocked",
        "release_authorized": False,
    }
    for field, expected in fixed.items():
        if report.get(field) != expected:
            raise ValueError("Research evidence overstates release or CVE coverage")
    exact = 0
    unresolved = []
    for cve, (commit, sha) in PINNED_COMMITS.items():
        row = report["cve_results"][cve]
        if not isinstance(row, dict) or row.get(
                "upstream_commit") != commit or row.get(
                "upstream_commit_patch_sha256") != sha:
            raise ValueError("An official CVE or patch receipt was changed")
        total = row.get("source_hunks")
        match = row.get("exact_postimage_hunks")
        if (type(total) is not int or not 1 <= total <= 120
                or type(match) is not int or not 0 <= match <= total):
            raise ValueError("Invalid patch hunk counts")
        paths = row.get("unresolved_paths")
        if (not isinstance(paths, list) or
                len(paths) > total or
                len(paths) != len(set(paths)) or
                any(not isinstance(p, str) or
                    not p.startswith("src/") or
                    len(p) > 200 for p in paths)):
            raise ValueError("Invalid unresolved source paths")
        is_exact = match == total
        if row.get("status") != (
                "all_source_postimages_exact" if is_exact
                else "partial_unresolved"):
            raise ValueError("Patch status contradicts hunk measurements")
        if (is_exact and paths) or (not is_exact and not paths):
            raise ValueError("Postimage mismatch is not accounted for")
        exact += bool(is_exact)
        if not is_exact:
            unresolved.append(cve)
    if (report.get("cves_with_all_source_hunks_exact") != exact
            or report.get("cves_partially_unresolved") != sorted(unresolved)):
        raise ValueError("Summary does not match individual CVE evidence")
    return {
        "status": "pinned_source_research_verified_release_blocked",
        "source_tarball_sha256": SOURCE_TARBALL_SHA256,
        "cves_with_all_source_hunks_exact": exact,
        "cves_partially_unresolved": sorted(unresolved),
        "release_authorized": False,
        "security_gate": "blocked",
    }


def verify_private_report(path: Path) -> dict:
    if (path.parent != Path("/tmp") or
            not re.fullmatch(
                r"folio-r141-tesseract-[a-z0-9_-]{4,80}\.json",
                path.name,
            ) or path.is_symlink() or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != 0o600
            or path.stat().st_size > 100_000):
        raise ValueError("Research evidence missing or not private")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid private source advisory evidence") from error
    if not isinstance(data, dict):
        raise ValueError("Source report is not a JSON object")
    result = verify_report(data)
    source = Path(__file__).read_text(encoding="utf-8")
    if (data.get("source_probe_script_sha256") != hashlib.sha256(
            source.encode("utf-8")
        ).hexdigest()
            or not re.fullmatch(
                r"sha256:[a-f0-9]{64}", data.get(
                    "isolation_container_image_id", ""
                ))):
        raise ValueError("Source research tooling identity changed")
    result["report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.worker:
            result = worker()
        elif args.verify_only is not None:
            result = verify_private_report(args.verify_only)
        else:
            result = host_probe()
            verify_report(result)
            if args.output is not None:
                path = args.output
                if (path.parent != Path("/tmp") or
                        not re.fullmatch(
                            r"folio-r141-tesseract-[a-z0-9_-]{4,80}\.json",
                            path.name,
                        ) or path.exists() or path.is_symlink()):
                    raise ValueError("Unsafe private /tmp research output")
                fd = os.open(
                    path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                with os.fdopen(fd, "w", encoding="utf-8") as out:
                    json.dump(result, out, sort_keys=True, indent=2)
                    out.write("\n")
    except (ValueError, OSError, UnicodeError, TypeError, KeyError):
        print(json.dumps({
            "status": "tesseract_source_evidence_unverified",
            "release_authorized": False, "security_gate": "blocked",
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
