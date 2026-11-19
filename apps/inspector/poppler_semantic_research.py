"""R1.13: verify *research-only* source adaptations on exact Debian Poppler.

All changes are applied solely inside an ephemeral copy of SHA-pinned source.
This deliberately does NOT compile or release a container, prove CVE fixes,
approve backports or alter the real inspector's security gate.
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

from poppler_backport_feasibility import FIX_PATCH_SHA256, _validate_patches
from poppler_source_patch_probe import (
    ARCHIVE_NAMES, CVE_SOURCE_PATHS, inspect_archives,
)

DIRECT_FIXES = ("CVE-2026-102620", "CVE-2026-93311")
RESEARCH_PROTOTYPES = {
    "CVE-2026-102621": "f86222d7269e66bb1a333722bf334c778f2e76eb2ef74a5594f4e34390c60aec",
    "CVE-2026-93312": "d7dbe7b47a048406f9598497602445db918721ace181f8bf7f4f80a5a4440d04",
    "CVE-2026-93313": "09b19f6115253993a51ed4695d5b643c8d341892b484ee49018f7e70b977fb66",
}
RESEARCH_FILENAMES = {
    cve: cve + "-trixie-prototype.patch" for cve in RESEARCH_PROTOTYPES
}
MAX_PATCH_BYTES = 64 * 1024
CHANGED_PATHS = frozenset(CVE_SOURCE_PATHS[cve] for cve in
                          (*DIRECT_FIXES, *RESEARCH_PROTOTYPES))


def validate_research_patches(
    patches: dict[str, bytes], expected: dict[str, str] | None = None,
) -> dict[str, str]:
    hashes = RESEARCH_PROTOTYPES if expected is None else expected
    if set(patches) != set(RESEARCH_PROTOTYPES) or set(hashes) != set(RESEARCH_PROTOTYPES):
        raise ValueError("Incomplete or unexpected research patch set")
    result = {}
    for cve, expected_digest in hashes.items():
        raw = patches[cve]
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PATCH_BYTES:
            raise ValueError("Invalid research patch")
        actual = hashlib.sha256(raw).hexdigest()
        if not re.fullmatch(r"[a-f0-9]{64}", expected_digest) or actual != expected_digest:
            raise ValueError("Research patch digest mismatch")
        target = CVE_SOURCE_PATHS[cve]
        value = raw.decode("utf-8", errors="strict")
        if (re.findall(r"(?m)^--- (.+)$", value) != ["a/" + target]
                or re.findall(r"(?m)^\+\+\+ (.+)$", value) != ["b/" + target]
                or not re.search(r"(?m)^@@ -\d+", value)):
            raise ValueError("Research patch targets another file")
        result[cve] = actual
    return result


def semantic_markers(source: dict[str, str]) -> dict[str, bool]:
    """Narrow postconditions, not exploitability or formal fix verification."""
    fofi = source["fofi/FoFiTrueType.cc"]
    function = source["poppler/Function.cc"]
    splash = source["splash/SplashClip.cc"]
    jbig2 = source["poppler/JBIG2Stream.cc"]
    return {
        "bit_width_range_1_to_32": bool(re.search(
            r"sampleBits\s*<\s*1\s*\|\|\s*sampleBits\s*>\s*32", function)),
        "bitmask_shift_64bit": (
            "bitMask = static_cast<unsigned int>((1ULL << sampleBits) - 1);" in function
            and "bitMask = (1 << sampleBits) - 1;" not in function
        ),
        "glyph_length_checked_add": (
            "checkedAdd(length, locaTable[j].len, &length)" in fofi
            and "length += locaTable[j].len;" not in fofi
        ),
        "glyph_alignment_still_unchecked": (
            "length += 4 - (length & 3);" in fofi
        ),
        "splash_ymin_checked_multiply": (
            "checkedMultiply(yMinI, splashAASize, &yMinAA)" in splash
            and "return splashErrGeneric;" in splash
            and "yMinAA = yMinI * splashAASize;" not in splash
        ),
        "splash_ymax_still_unchecked": (
            "yMaxAA = (yMaxI + 1) * splashAASize - 1;" in splash
        ),
        "jbig2_reset_checks_bitmap": (
            "bool JBIG2Stream::reset()" in jbig2
            and "if (pageBitmap && pageBitmap->isOk()) {" in jbig2
        ),
        "jbig2_low_value_checked_subtraction": (
            "checkedSubtraction(lowVal, 1, &lowValMinusOne)" in jbig2
            and "huffTab[i].val = lowValMinusOne;" in jbig2
            and "huffTab[i].val = lowVal - 1;" not in jbig2
        ),
        "jbig2_rewind_symbol_absent": "JBIG2Stream::rewind" not in jbig2,
    }


REQUIRED_MARKERS = frozenset((
    "bit_width_range_1_to_32", "bitmask_shift_64bit",
    "glyph_length_checked_add", "splash_ymin_checked_multiply",
    "jbig2_reset_checks_bitmap", "jbig2_low_value_checked_subtraction",
))
UNRESOLVED_MARKERS = frozenset((
    "glyph_alignment_still_unchecked", "splash_ymax_still_unchecked",
    "jbig2_rewind_symbol_absent",
))


def _run(command: list[str], cwd: Path, runner: Callable, timeout: int) -> subprocess.CompletedProcess:
    try:
        completed = runner(
            command, cwd=cwd, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Local source tooling failed") from error
    if completed.returncode != 0:
        raise ValueError("Local source operation failed")
    return completed


def inspect_semantic_prototypes(
    sources: dict[str, bytes],
    debian_fixes: dict[str, bytes],
    research_patches: dict[str, bytes],
    *,
    source_hashes: dict[str, str] | None = None,
    fix_hashes: dict[str, str] | None = None,
    research_hashes: dict[str, str] | None = None,
    runner: Callable = subprocess.run,
) -> dict:
    """Validate inputs and stage 5 changes in temporary source only."""
    baseline = inspect_archives(
        sources, expected_hashes=source_hashes, runner=runner,
    )
    _validate_patches(
        debian_fixes, FIX_PATCH_SHA256 if fix_hashes is None else fix_hashes,
    )
    prototype_digests = validate_research_patches(research_patches, research_hashes)
    original = baseline["source_sha256"]
    post = {}
    with tempfile.TemporaryDirectory(prefix="folio-r113-semantic-source-") as temporary:
        root = Path(temporary)
        for name, data in sources.items():
            (root / name).write_bytes(data)
        tree = root / "poppler"
        _run(["dpkg-source", "-x", str(root / ARCHIVE_NAMES["dsc"]), str(tree)],
             root, runner, 90)
        for path, original_digest in original.items():
            if hashlib.sha256((tree / path).read_bytes()).hexdigest() != original_digest:
                raise ValueError("Extracted source differs from pinned baseline")
        order = (
            [(cve, debian_fixes[cve]) for cve in DIRECT_FIXES]
            + [(cve, research_patches[cve]) for cve in RESEARCH_PROTOTYPES]
        )
        for cve, blob in order:
            patchfile = root / (cve + ".patch")
            patchfile.write_bytes(blob)
            result = _run(
                ["patch", "--batch", "--forward", "--fuzz=0", "-p1",
                 "-i", str(patchfile)], tree, runner, 30,
            )
            output = result.stdout + result.stderr
            # Never silently accept fuzz, skipped hunks or already-applied patches.
            if (f"patching file {CVE_SOURCE_PATHS[cve]}" not in output
                    or re.search(r"(?i)(fuzz|failed|reversed|skipping|malformed)", output)):
                raise ValueError("Patch result is not strict")
        text = {}
        for path, original_digest in original.items():
            file = tree / path
            if not file.is_file() or file.is_symlink():
                raise ValueError("Patched source path invalid")
            data = file.read_bytes()
            new_digest = hashlib.sha256(data).hexdigest()
            if (path in CHANGED_PATHS and new_digest == original_digest
                    or path not in CHANGED_PATHS and new_digest != original_digest):
                raise ValueError("Unexpected source mutation after patching")
            post[path] = new_digest
            if path in CHANGED_PATHS:
                text[path] = data.decode("utf-8", errors="strict")
        markers = semantic_markers(text)
        if not all(markers[k] for k in REQUIRED_MARKERS | UNRESOLVED_MARKERS):
            raise ValueError("Semantic evidence unexpected or unresolved risks concealed")
    return {
        "status": "research_source_prototypes_only",
        "base_source_version": baseline["version"],
        "upstream_debian_version": "26.07.0-4",
        "direct_debian_patches_applied_to_temporary_source": list(DIRECT_FIXES),
        "manual_prototypes_applied_to_temporary_source": list(RESEARCH_PROTOTYPES),
        "research_patch_sha256": dict(sorted(prototype_digests.items())),
        "baseline_sha256": original,
        "prototype_source_sha256": dict(sorted(post.items())),
        "semantic_markers": markers,
        "unresolved_issues": [
            "glyph_alignment_arithmetic_requires_review",
            "splash_ymax_arithmetic_requires_review",
            "jbig2_reset_semantics_need_review",
            "source_binary_equivalence_not_demonstrated",
            "remaining_poppler_cves_and_runtime_findings",
        ],
        "all_selected_cve_fixes_verified": False,
        "cve_remediation_claimed": False,
        "runtime_compilation_verified": False,
        "binary_equivalence_verified": False,
        "backports_approved": False,
        "complete_source_advisory_coverage": False,
        "release_authorized": False,
    }


def _read_exact(directory: Path, filenames: dict[str, str], limit: int) -> dict[str, bytes]:
    data = {}
    for key, name in filenames.items():
        path = directory / name
        if (not path.is_file() or path.is_symlink()
                or not 0 < path.stat().st_size <= limit):
            raise ValueError("Missing or untrusted research input")
        data[key] = path.read_bytes()
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-directory", required=True, type=Path)
    parser.add_argument("--fix-directory", required=True, type=Path)
    parser.add_argument("--prototype-directory", type=Path,
                        default=Path(__file__).resolve().parent / "research_patches")
    args = parser.parse_args()
    try:
        sources = _read_exact(
            args.source_directory, {n: n for n in ARCHIVE_NAMES.values()},
            8 * 1024 * 1024,
        )
        debian_fixes = _read_exact(
            args.fix_directory, {cve: cve + ".patch" for cve in FIX_PATCH_SHA256},
            MAX_PATCH_BYTES,
        )
        research = _read_exact(
            args.prototype_directory, RESEARCH_FILENAMES, MAX_PATCH_BYTES,
        )
        report = inspect_semantic_prototypes(sources, debian_fixes, research)
    except (ValueError, OSError, UnicodeError, TypeError):
        print(json.dumps({
            "status": "error",
            "reason": "poppler_semantic_source_evidence_incomplete",
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
