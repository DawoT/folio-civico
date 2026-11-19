"""Offline, SHA-pinned *textual* backport compatibility check for Debian Poppler.

The two inputs must be provided by an operator. No network, PDF processing,
package installation, source changes or native-image builds occur here.

A clean patch --dry-run is NOT evidence of CVE remediation, binary equivalence
or a backport suitable for release. All such decisions remain unassessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

from poppler_source_patch_probe import (
    ARCHIVE_NAMES,
    CVE_SOURCE_PATHS,
    inspect_archives,
)

# SHA-256 of the 7 exact patch files published in Debian's 26.07.0-4 quilt.
# These are *research inputs*, NOT validated 25.03.0 security backports.
FIX_REFERENCE_VERSION = "26.07.0-4"
FIX_PATCH_SHA256 = {
    "CVE-2026-102620": "cfff904cfed96fb47975fb236eba0f4940bc1aaa2bb2cc5a78b32782c8653f34",
    "CVE-2026-102621": "8d33455999b9d49906c9e109accab4a1bcda6ec6215f3db2b36f4c7d4d6d9b41",
    "CVE-2026-93311": "43c10135f98931c28def154de201fecd4e51c57f2b349fe0a4807415d0f7524a",
    "CVE-2026-93312": "0bc3ce062218e3d111cfbed5b475a7e9fa6b352a03f7ace667db515534b76299",
    "CVE-2026-93313": "2a6d8fb05bb1c49cfa287f849db15260a8f582275a4618a30b3f8ef26471ae88",
    "CVE-2026-93314": "f317b24cbe18193903093a03c5308fe873f04f8cce3cddac8351799cabf4c3a4",
    "CVE-2026-107705": "6cdbfa5e7611ac5870de95275f8dd72a2e72d6225087566d8dbd159a6bafe68e",
}
FIX_UNASSESSED = ("CVE-2026-93653", "CVE-2019-9545", "CVE-2019-9543")
MAX_PATCH_BYTES = 64 * 1024


def _validate_patches(
    patches: dict[str, bytes], expected_hashes: dict[str, str],
) -> dict[str, str]:
    if (set(patches) != set(FIX_PATCH_SHA256)
            or set(expected_hashes) != set(FIX_PATCH_SHA256)
            or set(FIX_PATCH_SHA256) | set(FIX_UNASSESSED) != set(CVE_SOURCE_PATHS)):
        raise ValueError("Patch inventory does not match selected Poppler advisories")
    fingerprints = {}
    for cve in sorted(FIX_PATCH_SHA256):
        raw, expected = patches[cve], expected_hashes[cve]
        if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PATCH_BYTES
                or not re.fullmatch(r"[a-f0-9]{64}", expected)):
            raise ValueError("Invalid patch artifact")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError("Debian fix patch SHA-256 mismatch")
        text = raw.decode("utf-8", errors="strict")
        target = CVE_SOURCE_PATHS[cve]
        touched = re.findall(r"(?m)^diff --git a/(\S+) b/(\S+)$", text)
        old_paths = re.findall(r"(?m)^--- (.+)$", text)
        new_paths = re.findall(r"(?m)^\+\+\+ (.+)$", text)
        # Debian backports may omit the optional 'diff --git' header.
        # Both canonical unified-diff file headers remain mandatory.
        if (touched not in ([], [(target, target)])
                or old_paths != ["a/" + target]
                or new_paths != ["b/" + target]
                or not re.search(r"(?m)^@@ -\d+", text)):
            raise ValueError("Patch identity or source target differs")
        fingerprints[cve] = actual
    return fingerprints


def _extract_source(
    sources: dict[str, bytes], root: Path, runner: Callable,
) -> Path:
    for name in ARCHIVE_NAMES.values():
        (root / name).write_bytes(sources[name])
    destination = root / "source"
    try:
        result = runner(
            ["dpkg-source", "-x", str(root / ARCHIVE_NAMES["dsc"]), str(destination)],
            cwd=root, capture_output=True, text=True, timeout=90, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Source extraction unavailable") from error
    if result.returncode != 0:
        raise ValueError("Pinned Poppler source extraction failed")
    return destination


def _check_tree_unchanged(root: Path, expected: dict[str, str]) -> None:
    for relative, digest in expected.items():
        file = root / relative
        if (not file.is_file() or file.is_symlink()
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            raise ValueError("Patched Poppler source identity changed")


def inspect_backport_feasibility(
    sources: dict[str, bytes],
    patches: dict[str, bytes],
    *,
    expected_source_hashes: dict[str, str] | None = None,
    expected_patch_hashes: dict[str, str] | None = None,
    extract_runner: Callable = subprocess.run,
    patch_runner: Callable = subprocess.run,
) -> dict:
    """Run 7 independent, zero-fuzz patch dry-runs on the exact source baseline.

    Overrides and runners exist solely for negative unit tests. The CLI uses
    SHA-pinned constants and real dpkg-source/patch tools.
    """
    baseline = inspect_archives(
        sources, expected_hashes=expected_source_hashes, runner=extract_runner,
    )
    hashes = _validate_patches(
        patches, FIX_PATCH_SHA256 if expected_patch_hashes is None else expected_patch_hashes
    )
    outcomes = {}
    with tempfile.TemporaryDirectory(prefix="folio-poppler-backport-check-") as tmp:
        root = Path(tmp)
        source = _extract_source(sources, root, extract_runner)
        _check_tree_unchanged(source, baseline["source_sha256"])
        for cve in sorted(FIX_PATCH_SHA256):
            path = root / (cve + ".patch")
            path.write_bytes(patches[cve])
            args = [
                "patch", "--dry-run", "--batch", "--forward", "--fuzz=0",
                "-p1", "-i", str(path),
            ]
            try:
                completed = patch_runner(
                    args, cwd=source, capture_output=True, text=True,
                    timeout=30, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError("Offline patch check unavailable") from error
            if completed.returncode not in (0, 1):
                raise ValueError("Patch check execution failed")
            output = completed.stdout + completed.stderr
            if (f"checking file {CVE_SOURCE_PATHS[cve]}" not in output
                    or (completed.returncode == 0 and re.search(
                        r"(?i)(failed|skipping patch|reversed|malformed)", output,
                    ))
                    or (completed.returncode == 1 and not re.search(
                        r"(?m)^Hunk #\d+ FAILED at \d+\.?$", output,
                    ))):
                raise ValueError("Patch output cannot support compatibility conclusion")
            outcomes[cve] = {
                "patch_sha256": hashes[cve],
                "target_source": CVE_SOURCE_PATHS[cve],
                "dry_run_exit": completed.returncode,
                "result": (
                    "textually_applicable_without_fuzz" if completed.returncode == 0
                    else "requires_manual_backport_review"
                ),
                "fix_verified": False,
            }
            _check_tree_unchanged(source, baseline["source_sha256"])
    return {
        "status": "backport_feasibility_only",
        "base_source_version": baseline["version"],
        "fix_reference_debian_version": FIX_REFERENCE_VERSION,
        "patches_checked": len(outcomes),
        "textually_applicable_count": sum(
            row["dry_run_exit"] == 0 for row in outcomes.values()
        ),
        "requires_manual_review_count": sum(
            row["dry_run_exit"] == 1 for row in outcomes.values()
        ),
        "patches": outcomes,
        "selected_without_fix_patch": list(FIX_UNASSESSED),
        "binary_equivalence_verified": False,
        "selected_cve_fixes_verified": False,
        "backport_approved": False,
        "complete_source_advisory_coverage": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-directory", required=True, type=Path)
    parser.add_argument("--fix-directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        sources = {}
        for name in ARCHIVE_NAMES.values():
            path = args.source_directory / name
            if not path.is_file() or path.is_symlink():
                raise ValueError("Source artifact unavailable")
            sources[name] = path.read_bytes()
        patches = {}
        for cve in FIX_PATCH_SHA256:
            path = args.fix_directory / (cve + ".patch")
            if (not path.is_file() or path.is_symlink()
                    or not 0 < path.stat().st_size <= MAX_PATCH_BYTES):
                raise ValueError("Fix patch unavailable")
            patches[cve] = path.read_bytes()
        result = inspect_backport_feasibility(sources, patches)
    except (ValueError, TypeError, OSError, UnicodeError):
        print(json.dumps({
            "status": "error", "reason": "poppler_backport_evidence_incomplete",
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
