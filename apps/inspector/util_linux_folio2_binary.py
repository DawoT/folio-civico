"""R1.37: fail-closed experimental Debian 13 folio2 binary provenance gate.

Never install/publish the candidate .deb, authorize release, suppress CVEs or
claim ABI validation. The source descriptor is local and UNSIGNED: immutable
SHA256 pins prevent confusing these outputs with Debian-maintained packages.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from util_linux_versioned_quilt_source import (
    VERSIONED_SOURCE_VERSION, VERSIONED_MANIFEST_NAME, VERSIONED_SERIES,
    PATCHED_IDMAP_SHA256, BUILD_PATCH_SHA256, SOURCE_DATE_EPOCH
)
from util_linux_trixie_binary_experiment import IMAGE_DIGEST
from util_linux_source_candidate import TAR_SHA256

SOURCE_VERSION = VERSIONED_SOURCE_VERSION
SOURCE_MANIFEST_NAME = VERSIONED_MANIFEST_NAME
SOURCE_HASHES = {
    "util-linux_2.41.6.orig.tar.xz":
        TAR_SHA256,
    f"util-linux_{SOURCE_VERSION}.debian.tar.xz":
        "204326e759e7b81b03b23eae8b43a65567512eccaf862dcf2426212c05145288",
    f"util-linux_{SOURCE_VERSION}.dsc":
        "a0301270ca8ca6f9000bf48097f0b51a29aa07b9d7dc0182f486f59fe85439b6",
}
SOURCE_FILES = tuple(SOURCE_HASHES)

# Complete package-set contract observed in the two independent R1.35 Debian
# 13.7 builds (including the four packages with special Debian epochs).
EXPECTED_PACKAGES = frozenset((
    "bsdextrautils", "bsdextrautils-dbgsym", "bsdutils", "bsdutils-dbgsym",
    "eject", "eject-dbgsym", "fdisk", "fdisk-dbgsym", "lastlog2",
    "lastlog2-dbgsym", "libblkid-dev", "libblkid1", "libblkid1-dbgsym",
    "libfdisk-dev", "libfdisk1", "libfdisk1-dbgsym", "liblastlog2-2",
    "liblastlog2-2-dbgsym", "liblastlog2-dev", "libmount-dev", "libmount1",
    "libmount1-dbgsym", "libpam-lastlog2", "libpam-lastlog2-dbgsym",
    "libsmartcols-dev", "libsmartcols1", "libsmartcols1-dbgsym",
    "libuuid1", "libuuid1-dbgsym", "login", "login-dbgsym", "mount",
    "mount-dbgsym", "rfkill", "rfkill-dbgsym", "util-linux",
    "util-linux-dbgsym", "util-linux-extra", "util-linux-extra-dbgsym",
    "util-linux-locales", "uuid-dev", "uuid-runtime", "uuid-runtime-dbgsym",
))
assert len(EXPECTED_PACKAGES) == 43


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(block)
    return sha.hexdigest()


def expected_binary_version(package: str) -> str:
    if package not in EXPECTED_PACKAGES:
        raise ValueError("Unexpected util-linux Debian binary package")
    if package in ("login", "login-dbgsym"):
        return "1:4.16.0-2+really" + SOURCE_VERSION
    if package in ("bsdutils", "bsdutils-dbgsym"):
        return "1:" + SOURCE_VERSION
    return SOURCE_VERSION


def _private_folder(path: Path) -> None:
    if (not path.is_absolute() or ".." in path.parts or not path.is_dir()
            or path.is_symlink() or path.resolve(strict=True) != path
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError("Candidate folder must be canonical, private and absolute")


def validate_source(source: Path) -> dict:
    """Validate the *exact* R1.36 source handoff, not merely its JSON claims."""
    if os.geteuid() == 0:
        raise ValueError("Non-root operator required")
    _private_folder(source)
    if {p.name for p in source.iterdir()} != set(SOURCE_FILES) | {SOURCE_MANIFEST_NAME}:
        raise ValueError("Unexpected or missing Debian source files")
    manifest = source / SOURCE_MANIFEST_NAME
    if (manifest.is_symlink() or not manifest.is_file()
            or stat.S_IMODE(manifest.stat().st_mode) != 0o600
            or manifest.stat().st_size > 8192):
        raise ValueError("Versioned source manifest missing or unsafe")
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("Versioned source manifest is invalid") from error
    required = {
        "status": "unsigned_versioned_debian_source_roundtrip_release_blocked",
        "versioned_debian_source_version": SOURCE_VERSION,
        "versioned_dsc_signed": False,
        "source_roundtrip_verified": True,
        "release_authorized": False,
        "security_gate": "blocked",
        "cve_remediated": False,
        "debian_binary_packages_built": False,
        "quilt_patch_count": len(VERSIONED_SERIES),
        "additional_quilt_patch_sha256": BUILD_PATCH_SHA256,
        "patched_idmap_sha256": PATCHED_IDMAP_SHA256,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "vex": "not_issued",
    }
    if (not isinstance(document, dict)
            or any(document.get(k) != v for k, v in required.items())
            or document.get("source_sha256") != SOURCE_HASHES):
        raise ValueError("Source provenance or release state did not match R1.36")
    for name, expected in SOURCE_HASHES.items():
        file = source / name
        if (file.is_symlink() or not file.is_file()
                or stat.S_IMODE(file.stat().st_mode) != 0o600
                or digest(file) != expected):
            raise ValueError("Source archive has changed from verified SHA-256")
    return {
        "status": "folio2_binary_source_admitted_release_blocked",
        "source_version": SOURCE_VERSION,
        "source_sha256": dict(SOURCE_HASHES),
        "source_roundtrip_verified": True,
        "builder_image_digest": IMAGE_DIGEST,
        "source_quilt_patch_count": len(VERSIONED_SERIES),
        "patched_idmap_sha256": PATCHED_IDMAP_SHA256,
        "debian_binary_packages_built": False,
        "debian_trixie_abi_validated": False,
        "cve_remediated": False,
        "runtime_image_replaced": False,
        "vex": "not_issued",
        "release_authorized": False,
        "security_gate": "blocked",
    }


def _field(path: Path, key: str) -> str:
    try:
        result = subprocess.run(
            ["dpkg-deb", "--field", str(path), key],
            capture_output=True, text=True, check=False, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Cannot read experimental Debian metadata") from error
    if result.returncode:
        raise ValueError("Invalid Debian package payload")
    return result.stdout.strip()


def validate_binary_inventory(folder: Path, source_report: dict) -> dict:
    """Check exactly 43 expected folio2 packages; cannot approve runtime."""
    _private_folder(folder)
    if (source_report.get("source_sha256") != SOURCE_HASHES
            or source_report.get("release_authorized") is not False):
        raise ValueError("Binary inventory has untrusted source admission")
    entries = list(folder.iterdir())
    allowed = {
        "NOT_FOR_RELEASE.txt", "BINARY_RESEARCH_ONLY.txt",
        "QUILT_SOURCE_SHA256.txt",
    }
    allowed_ext = {".deb", ".changes", ".buildinfo"}
    for item in entries:
        if (item.is_symlink() or not item.is_file()
                or (item.name not in allowed and item.suffix not in allowed_ext)
                or (item.name not in allowed and
                    stat.S_IMODE(item.stat().st_mode) != 0o600)):
            raise ValueError("Unexpected binary output or unsafe permissions")
    patch_proof = folder / "QUILT_SOURCE_SHA256.txt"
    if (not patch_proof.is_file() or patch_proof.is_symlink()
            or patch_proof.read_text(encoding="utf-8")
            != PATCHED_IDMAP_SHA256 + "  libmount/src/hook_idmap.c\n"):
        raise ValueError("Build did not preserve the versioned quilt source bytes")
    debs = [p for p in entries if p.suffix == ".deb"]
    if len(debs) != len(EXPECTED_PACKAGES):
        raise ValueError("Incomplete or expanded experimental package inventory")
    found: dict[str, dict] = {}
    for deb in sorted(debs):
        pkg = _field(deb, "Package")
        if pkg not in EXPECTED_PACKAGES or pkg in found:
            raise ValueError("Duplicate or unexpected Debian package name")
        version = _field(deb, "Version")
        arch = _field(deb, "Architecture")
        src = _field(deb, "Source")
        if (version != expected_binary_version(pkg)
                or arch != ("all" if pkg == "util-linux-locales" else "amd64")
                or src not in ("util-linux", f"util-linux ({SOURCE_VERSION})")
                and not (pkg == "util-linux" and not src)):
            raise ValueError("Debian binary does not match versioned quilt source")
        found[pkg] = {
            "name": pkg, "version": version, "architecture": arch,
            "sha256": digest(deb), "file": deb.name,
        }
    if set(found) != EXPECTED_PACKAGES:
        raise ValueError("Debian binary inventory differs from pinned set")

    report = {
        **source_report,
        "status": "folio2_debian13_binary_research_release_blocked",
        "debian_binary_packages_built": True,
        "binary_package_count": len(found),
        "packages": [found[name] for name in sorted(found)],
        "debian_trixie_abi_validated": False,
        "cve_remediated": False,
        "runtime_image_replaced": False,
        "release_authorized": False,
        "security_gate": "blocked",
    }
    target = folder / "UNSIGNED_FOLIO2_BINARY_RESEARCH_ONLY.json"
    if target.exists() or target.is_symlink():
        raise ValueError("Refusing to overwrite a binary provenance manifest")
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                      encoding="utf-8")
    os.chmod(target, 0o600)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--binary-dir", type=Path)
    args = parser.parse_args()
    try:
        result = validate_source(args.source_dir)
        if args.binary_dir is not None:
            result = validate_binary_inventory(args.binary_dir, result)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError,
            subprocess.TimeoutExpired):
        print(json.dumps({
            "status": "error", "reason": "folio2_binary_provenance_unverified",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2  # Even a valid binary build does not authorize a release.


if __name__ == "__main__":
    raise SystemExit(main())
