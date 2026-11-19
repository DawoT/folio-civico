"""Verify the EXACT Debian-patched Poppler source package, with no network.

This reads three SHA-pinned Debian source artifacts from an operator-supplied
directory. dpkg-source extracts the complete Debian quilt patch stack into a
temporary directory, then we fingerprint source files for selected CVEs.

This is SOURCE provenance only. It does NOT prove a byte-reproducible native ELF,
that the selected CVEs are fixed, or that the image may be deployed.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from typing import Callable

VERSION = "25.03.0-5+deb13u4"
ARCHIVE_NAMES = {
    "dsc": f"poppler_{VERSION}.dsc",
    "orig": "poppler_25.03.0.orig.tar.xz",
    "debian": f"poppler_{VERSION}.debian.tar.xz",
}
# SHA-256 measured against the Debian pool files and the signed .dsc
# Checksum-Sha256 values on 2026-11-19. Build input APT is signed separately.
ARCHIVE_HASHES = {
    ARCHIVE_NAMES["dsc"]: "b895e1e28568a486523f93dd5a8707ecb16767c5f134a6e23510b0597114c628",
    ARCHIVE_NAMES["orig"]: "97da4ff88517a6bbd729529f195f85c8d7a0c3bb4a3d57cb0c685cbb052fe837",
    ARCHIVE_NAMES["debian"]: "2605b5d7e6ce17a307d067048386deedfc41fdac6f75f81ad76050f517fc0de4",
}
PATCH_SERIES = (
    "CVE-2025-32364.patch",
    "CVE-2025-32365.patch",
    "CVE-2025-43903.patch",
    "CVE-2025-52886.patch",
    "CVE-2025-50420.patch",
    "SplashOutputDev-Fix-integer-overflow-in-tilingPatter.patch",
    "Make-sure-regex-doesn-t-stack-overflow-by-limiting-i.patch",
    "Check-for-duplicate-entries.patch",
    "malformed-moddate.patch",
)
RELATED_PATCH = "SplashOutputDev-Fix-integer-overflow-in-tilingPatter.patch"
RELATED_CVE = "CVE-2026-10118"
RELATED_PATCH_GUARD = "checkedMultiply(surface_width, repeatX, &result_width)"
CVE_SOURCE_PATHS = {
    "CVE-2026-107705": "poppler/Decrypt.cc",
    "CVE-2026-102621": "splash/SplashClip.cc",
    "CVE-2026-102620": "fofi/FoFiTrueType.cc",
    "CVE-2026-93653": "poppler/SplashOutputDev.cc",
    "CVE-2026-93314": "fofi/FoFiTrueType.cc",
    "CVE-2026-93313": "poppler/JBIG2Stream.cc",
    "CVE-2026-93312": "poppler/JBIG2Stream.cc",
    "CVE-2026-93311": "poppler/Function.cc",
    "CVE-2019-9545": "poppler/JBIG2Stream.cc",
    "CVE-2019-9543": "poppler/JBIG2Stream.cc",
}
CODE_SYMBOLS = {
    "poppler/Decrypt.cc": ("revision6Hash",),
    "splash/SplashClip.cc": ("SplashClip::clipToPath",),
    "fofi/FoFiTrueType.cc": ("cvtSfnts", "mapCodeToGID"),
    "poppler/SplashOutputDev.cc": ("tilingPatternFill",),
    "poppler/JBIG2Stream.cc": (
        "readCodeTableSeg", "readTextRegion", "readGenericBitmap",
    ),
    "poppler/Function.cc": ("SampledFunction::SampledFunction",),
}
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024
SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _validate_archives(
    sources: dict[str, bytes], expected_hashes: dict[str, str]
) -> dict[str, str]:
    if (set(sources) != set(ARCHIVE_NAMES.values())
            or set(expected_hashes) != set(ARCHIVE_NAMES.values())):
        raise ValueError("Debian source archive set is incomplete")
    hashes = {}
    for name in ARCHIVE_NAMES.values():
        data, expected = sources[name], expected_hashes[name]
        if (not isinstance(data, bytes) or not 0 < len(data) <= MAX_ARCHIVE_BYTES
                or not isinstance(expected, str) or not SHA256.fullmatch(expected)):
            raise ValueError("Untrusted Debian source archive")
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ValueError("Debian source archive digest mismatch")
        hashes[name] = actual

    signed = sources[ARCHIVE_NAMES["dsc"]].decode("utf-8", errors="strict")
    if (not signed.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n")
            or not re.search(r"(?m)^Source: poppler$", signed)
            or not re.search(r"(?m)^Format: 3\.0 \(quilt\)$", signed)
            or not re.search(r"(?m)^Version: " + re.escape(VERSION) + r"$", signed)):
        raise ValueError("Source package metadata is not the pinned Debian version")
    lines = signed.splitlines()
    try:
        start = lines.index("Checksums-Sha256:") + 1
    except ValueError as error:
        raise ValueError("Debian descriptor has no source SHA-256 inventory") from error
    entries: dict[str, tuple[str, int]] = {}
    for line in lines[start:]:
        if not line.startswith((" ", "\t")):
            break
        words = line.split()
        if len(words) != 3 or words[2] in entries:
            raise ValueError("Malformed Debian descriptor checksum")
        try:
            size = int(words[1])
        except ValueError as error:
            raise ValueError("Malformed Debian descriptor file size") from error
        entries[words[2]] = (words[0], size)
    if set(entries) != {ARCHIVE_NAMES["orig"], ARCHIVE_NAMES["debian"]}:
        raise ValueError("Debian descriptor source components differ")
    for name in entries:
        digest, size = entries[name]
        if digest != hashes[name] or size != len(sources[name]):
            raise ValueError("Debian descriptor source hash or size differs")
    return hashes


def _inspect_quilt(data: bytes) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
            members = archive.getmembers()
            for name in ("debian/patches/series", *(
                    f"debian/patches/{patch}" for patch in PATCH_SERIES)):
                matching = [m for m in members if m.name == name]
                if len(matching) != 1 or not matching[0].isfile() or matching[0].size > 256*1024:
                    raise ValueError("Pinned Debian quilt file is absent or nonregular")
            def read(name: str) -> str:
                member = next(m for m in members if m.name == name)
                opened = archive.extractfile(member)
                if opened is None:
                    raise ValueError("Unable to read Debian quilt file")
                return opened.read(256*1024 + 1).decode("utf-8", errors="strict")
            listed = tuple(line for line in read("debian/patches/series").splitlines()
                           if line.strip() and not line.lstrip().startswith("#"))
            if listed != PATCH_SERIES:
                raise ValueError("Debian quilt patch ordering differs")
            patch = read("debian/patches/" + RELATED_PATCH)
            if (f"tracker/{RELATED_CVE}" not in patch
                    or RELATED_PATCH_GUARD not in patch
                    or "poppler/SplashOutputDev.cc" not in patch):
                raise ValueError("Related Poppler patch has unexpected identity")
    except (tarfile.TarError, UnicodeError, OSError) as error:
        raise ValueError("Cannot validate Debian quilt archive") from error


def inspect_archives(
    sources: dict[str, bytes], *,
    expected_hashes: dict[str, str] | None = None,
    runner: Callable = subprocess.run,
) -> dict:
    """Prove a bounded set of patched source symbols, NEVER CVE remediation.

    expected_hashes is only overridable by unit-test callers; the CLI always
    uses the constant expected hashes measured from Debian source archives.
    """
    hashes = _validate_archives(
        sources, ARCHIVE_HASHES if expected_hashes is None else expected_hashes
    )
    _inspect_quilt(sources[ARCHIVE_NAMES["debian"]])
    if set(CVE_SOURCE_PATHS.values()) != set(CODE_SYMBOLS):
        raise ValueError("Selected CVE source-path inventory is incomplete")
    with tempfile.TemporaryDirectory(prefix="folio-poppler-source-review-") as temporary:
        root = Path(temporary)
        for name, data in sources.items():
            (root / name).write_bytes(data)
        tree = root / "unpacked"
        try:
            completed = runner(
                ["dpkg-source", "-x", str(root / ARCHIVE_NAMES["dsc"]), str(tree)],
                cwd=root, timeout=90, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Debian source extraction tool unavailable") from error
        if completed.returncode != 0:
            raise ValueError("Debian quilt application failed")
        source_hashes = {}
        jbig2_rewind_symbol_observed = None
        for path, markers in CODE_SYMBOLS.items():
            file = tree / path
            if not file.is_file() or file.is_symlink():
                raise ValueError("Patched Poppler source file missing or linked")
            if not 0 < file.stat().st_size <= MAX_SOURCE_BYTES:
                raise ValueError("Patched Poppler source file is empty or oversized")
            data = file.read_bytes()
            code = data.decode("utf-8",errors="strict")
            if any(marker not in code for marker in markers):
                raise ValueError("Selected Poppler source symbol missing")
            source_hashes[path] = hashlib.sha256(data).hexdigest()
            if path == "poppler/JBIG2Stream.cc":
                jbig2_rewind_symbol_observed = "JBIG2Stream::rewind" in code
        if RELATED_PATCH_GUARD not in (tree / "poppler/SplashOutputDev.cc").read_text(
            encoding="utf-8"
        ):
            raise ValueError("Debian checked multiplication patch was not applied")
    return {
        "status": "debian_source_evidence_partial",
        "version": VERSION,
        "archives_sha256": dict(sorted(hashes.items())),
        "patch_count": len(PATCH_SERIES),
        "quilt_application_verified": True,
        "distinct_related_fix_cve": RELATED_CVE,
        "related_fix_present_in_extracted_source": True,
        "source_sha256": dict(sorted(source_hashes.items())),
        "selected_cve_sources": dict(sorted(CVE_SOURCE_PATHS.items())),
        # Source-level observation only. Absence of a literal method name
        # does not establish that CVE-2026-93312 cannot affect this version.
        "jbig2_rewind_symbol_observed": jbig2_rewind_symbol_observed,
        "selected_cve_fixes_verified": False,
        "binary_equivalence_verified": False,
        "dsc_signature_verified_by_probe": False,
        "complete_source_advisory_coverage": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        sources = {}
        for name in ARCHIVE_NAMES.values():
            path = args.directory / name
            if (not path.is_file() or path.is_symlink()
                    or not 0 < path.stat().st_size <= MAX_ARCHIVE_BYTES):
                raise ValueError("Source archive unavailable")
            sources[name] = path.read_bytes()
        result = inspect_archives(sources)
    except (ValueError, TypeError, OSError, UnicodeError):
        print(json.dumps({
            "status": "error",
            "reason": "poppler_source_evidence_incomplete",
        }))
        return 3
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
