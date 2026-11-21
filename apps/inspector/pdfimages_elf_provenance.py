"""R1.51: additive, fail-closed ELF proof for Poppler's sixth scanner CLI.

The R1.40/R1.42 "folio-local-elf-provenance-v1" evidence is SHA-pinned.
Do NOT mutate or relabel it: measure pdfimages alongside the unmodified
five-utility native inventory in one immutable, local, offline research image.
This is not vendor signing, source-to-ELF reproduction, a CVE waiver or release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

from audit_image import verify_native_source_inventory
from source_inventory import (
    POPPLER_METADATA, inventory as original_inventory, sha256_elf,
)

SOURCE = "folio-r151-pdfimages-elf-provenance-v1"
# R1.40/R1.42 receipts bind to these exact legacy script bytes.
# New native tools require additive evidence; never silently redefine v1.
LEGACY_V1_SCRIPT_SHA256 = "6effc14e9267f507e1d54b6fab71b2709737414eba952e812133c460de772d2c"
PINNED_IMAGE_ID = (
    "sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a"
)
EXPERIMENT_IMAGE = "folio-civico-inspector:poppler-experiment"
RELATIVE = "opt/folio-poppler/bin/pdfimages"
POPPLER_LIBRARY = "/opt/folio-poppler/lib/libpoppler.so.147"
VERSION_LINE = re.compile(r"^pdfimages version 25\.03\.0\r?\n")
POPPLER_LINK_LINE = re.compile(
    r"^[ \t]*libpoppler\.so\.147 => "
    r"/opt/folio-poppler/lib/libpoppler\.so\.147 \(0x[0-9a-f]+\)$",
    re.MULTILINE,
)
FORBIDDEN_LIBRARIES = (
    "libcurl", "libgssapi", "libkrb5", "libk5crypto",
    "libgpgme", "libnss3",
)


def checked(argv: list[str]) -> str:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=12, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Offline pdfimages ELF probe unavailable") from error
    if result.returncode != 0:
        raise ValueError("Offline pdfimages ELF probe rejected")
    return result.stdout + result.stderr


def inspect(root: Path = Path("/"), *, image_id: str) -> dict:
    if image_id != PINNED_IMAGE_ID or not isinstance(root, Path):
        raise ValueError("Only the exact pinned research image is supported")

    # The v1 native evidence is deliberately recalculated without changes.
    # Its five utility digests, Poppler SONAME, OCR models, and the explicit
    # outstanding CVE assessment must remain independently valid.
    legacy_source_path = Path(__file__).with_name("source_inventory.py")
    if not legacy_source_path.is_file() or legacy_source_path.is_symlink():
        raise ValueError("Untrusted legacy inventory implementation")
    legacy_script_sha256 = hashlib.sha256(legacy_source_path.read_bytes()).hexdigest()
    if legacy_script_sha256 != LEGACY_V1_SCRIPT_SHA256:
        raise ValueError("Legacy inventory script SHA mismatch")
    native = original_inventory("experiment", root=root)
    if verify_native_source_inventory(native, EXPERIMENT_IMAGE) != 2:
        raise ValueError("Legacy native provenance is incomplete")
    if native.get("source_cve_coverage") != "unassessed":
        raise ValueError("The source review gate must remain blocked")
    poppler = next(
        (entry for entry in native["components"] if entry["name"] == "poppler"),
        None,
    )
    if poppler is None or poppler["version"] != POPPLER_METADATA["debian_source_version"]:
        raise ValueError("Source-built Poppler identity unavailable")

    binary = root / RELATIVE
    try:
        state = binary.lstat()
    except OSError as error:
        raise ValueError("Required pdfimages utility absent") from error
    if (not stat.S_ISREG(state.st_mode)
            or stat.S_IMODE(state.st_mode) != 0o755
            or state.st_nlink != 1 or not 4096 <= state.st_size <= 64 * 1024 * 1024):
        raise ValueError("pdfimages must be a bounded, regular, immutable CLI")

    digest = sha256_elf(root, RELATIVE)
    version = checked([str(binary), "-v"])
    if not VERSION_LINE.match(version):
        raise ValueError("Unexpected pdfimages version from source-built Poppler")

    links = checked(["ldd", str(binary)])
    if ("not found" in links or any(name in links for name in FORBIDDEN_LIBRARIES)
            or len(POPPLER_LINK_LINE.findall(links)) != 1
            or len(re.findall(r"^[ \t]*libpoppler\.so\.147 =>", links, re.MULTILINE)) != 1):
        raise ValueError("pdfimages dependencies do not resolve to the measured Poppler")
    # The legacy native inventory computes the SHA256 of this same exact
    # SONAME in this very root; ldd must resolve to that file, not Debian's.
    expected_library = root / POPPLER_LIBRARY.lstrip("/")
    if not expected_library.is_file():
        raise ValueError("Custom Poppler library is missing")
    # The SONAME symlink is installed by CMake; resolve it ONLY inside the
    # image-owned library prefix, and reject a mutable or external target.
    resolved = expected_library.resolve(strict=True)
    trusted_libs = (root / "opt/folio-poppler/lib").resolve(strict=True)
    meta = resolved.stat()
    if (not resolved.is_relative_to(trusted_libs)
            or not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o022):
        raise ValueError("Custom Poppler library link is unsafe")
    if sha256_elf(root, POPPLER_LIBRARY.lstrip("/")) != poppler["library_sha256"]:
        raise ValueError("pdfimages linked Poppler library identity changed")

    return {
        "source": SOURCE,
        "status": "verified_local_elf_identity_release_blocked",
        "image_id": image_id,
        "legacy_source": native["source"],
        "legacy_inventory_script_sha256": legacy_script_sha256,
        "poppler_version": poppler["version"],
        "pdfimages_path": "/" + RELATIVE,
        "pdfimages_sha256": digest,
        "other_poppler_tools_sha256": poppler["tool_sha256"],
        "poppler_library_sha256": poppler["library_sha256"],
        "poppler_provenance_sha256": poppler["provenance_sha256"],
        "same_poppler_library_link_verified": True,
        "source_cve_coverage": "unassessed",
        "source_to_elf_reproducible_build_attested": False,
        "scanner_gate": "blocked",
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    try:
        report = inspect(image_id=args.image_id)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        # Do not disclose arbitrary paths or untrusted loader output.
        print(json.dumps({
            "status": "pdfimages_elf_provenance_incomplete",
            "scanner_gate": "blocked", "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 2  # Valid research evidence, never release approval.


if __name__ == "__main__":
    raise SystemExit(main())
