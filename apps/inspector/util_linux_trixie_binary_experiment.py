"""R1.35: fail-closed admission of an unsigned R1.34 source bundle.

Research-only. This never installs Debian packages, creates a Docker image,
issues VEX, suppresses CVEs, or authorizes release. All binaries are candidate
outputs until separately validated against Debian 13 ABI and scanner evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from util_linux_debian_source_overlay import (
    EXPERIMENT_VERSION, SOURCE_DATE_EPOCH, VERSION, TAR_SHA256
)

# Exact Debian 13.7/amd64 OCI base pulled and inspected on 2026-11-20.
# It is pinned to the registry manifest, not a mutable 'trixie' tag.
IMAGE_DIGEST = "sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
IMAGE = "docker.io/library/debian@" + IMAGE_DIGEST
# Reproducible source-package hashes from independently verified R1.33.
PINNED_DSC_SHA256 = "ec1d158d4b8a17d74e31dafccbe9a755a323497d6cc4bef88ccc599c9bfbc752"
PINNED_DEBIAN_TAR_SHA256 = "8449886af6bd4d2cf9c4753596719c380ba951e7d220e27610aa6c881426a5e7"

NAMES = (
    f"util-linux_{VERSION}.orig.tar.xz",
    f"util-linux_{EXPERIMENT_VERSION}.dsc",
    f"util-linux_{EXPERIMENT_VERSION}.debian.tar.xz",
)
PINNED = (TAR_SHA256, PINNED_DSC_SHA256, PINNED_DEBIAN_TAR_SHA256)
MANIFEST_NAME = "UNSIGNED_SOURCE_ONLY.json"
LOGIN_VERSION = "1:4.16.0-2+really" + EXPERIMENT_VERSION
LOGIN_PACKAGES = ("login", "login-dbgsym")
BSDUTILS_VERSION = "1:" + EXPERIMENT_VERSION
BSDUTILS_PACKAGES = ("bsdutils", "bsdutils-dbgsym")
BUILD_PATCH = Path(__file__).resolve().parent / "research_patches/util-linux-2.41.6-r135-openat2-include.patch"
BUILD_PATCH_SHA256 = "cf8166e6d0cc5472bf7e78753f81e7c6b68f43a5784668c1a748baed4508a179"
PATCHED_IDMAP_SHA256 = "e12678246515279507185598710821dc23387b08b84b4eeb9b4977e733e391c1"


def _sha256(file: Path) -> str:
    digest = hashlib.sha256()
    with file.open("rb") as inp:
        for chunk in iter(lambda: inp.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_handoff(source: Path) -> dict:
    """Strict source-only input admission before creating any container."""
    if os.geteuid() == 0:
        raise ValueError("A non-root operator is required")
    if (not source.is_absolute() or not source.is_dir()
            or source.is_symlink() or source.resolve(strict=True) != source
            or stat.S_IMODE(source.stat().st_mode) != 0o700):
        raise ValueError("Source handoff must be a private, real, absolute directory")
    # Build-only portability fix is separately SHA-pinned; the vendor tar and
    # R1.34 unsigned source descriptor remain byte-for-byte unchanged.
    if (not BUILD_PATCH.is_file() or BUILD_PATCH.is_symlink()
            or _sha256(BUILD_PATCH) != BUILD_PATCH_SHA256):
        raise ValueError("Unverified additional experimental build patch")
    names = set(NAMES)
    if {p.name for p in source.iterdir()} != names | {MANIFEST_NAME}:
        raise ValueError("The source handoff has missing or unapproved files")
    manifest = source / MANIFEST_NAME
    if (manifest.is_symlink() or not manifest.is_file()
            or stat.S_IMODE(manifest.stat().st_mode) != 0o600
            or manifest.stat().st_size > 8192):
        raise ValueError("The private unsigned manifest is absent or unsafe")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    exact = {
        "status": "unsigned_source_only_handoff_release_blocked",
        "experimental_debian_version": EXPERIMENT_VERSION,
        "source_roundtrip_verified": True,
        "upstream_signatures_verified": True,
        "debian_original_dsc_signed": True,
        "experimental_dsc_signed": False,
        "debian_binary_packages_built": False,
        "runtime_image_replaced": False,
        "vex": "not_issued",
        "release_authorized": False,
        "source_date_epoch": SOURCE_DATE_EPOCH,
    }
    if (not isinstance(data, dict)
            or any(data.get(k) != v for k, v in exact.items())):
        raise ValueError("Source handoff is not a blocked R1.34 provenance record")
    expected = dict(zip(NAMES, PINNED))
    if data.get("sha256") != expected:
        raise ValueError("Source manifest hashes are not the pinned R1.33 outputs")
    for name, digest in expected.items():
        file = source / name
        if (file.is_symlink() or not file.is_file()
                or stat.S_IMODE(file.stat().st_mode) != 0o600
                or _sha256(file) != digest):
            raise ValueError("Source bytes or filesystem permissions changed")
    return {
        "status": "debian_trixie_binary_research_input_admitted_release_blocked",
        "debian_version_required": "13",
        "architecture_required": "amd64",
        "builder_image_digest": IMAGE_DIGEST,
        "source_version": EXPERIMENT_VERSION,
        "source_sha256": expected,
        "experimental_build_only_patch_sha256": BUILD_PATCH_SHA256,
        "source_roundtrip_verified": True,
        "debian_binary_packages_built": False,
        "runtime_image_replaced": False,
        "cve_remediated": False,
        "vex": "not_issued",
        "release_authorized": False,
    }


def verify_binary_inventory(folder: Path, input_report: dict) -> dict:
    """Inventory source-matched .deb files; *never* affirm ABI or CVE closure."""
    if (not folder.is_absolute() or not folder.is_dir() or folder.is_symlink()
            or folder.resolve(strict=True) != folder
            or stat.S_IMODE(folder.stat().st_mode) != 0o700):
        raise ValueError("Experimental package folder must be private and real")
    existing = list(folder.iterdir())
    allowed = {"NOT_FOR_RELEASE.txt", "BINARY_RESEARCH_ONLY.txt",
               "BUILD_ONLY_OPENAT2_SOURCE_SHA256.txt"}
    idmap_proof = folder / "BUILD_ONLY_OPENAT2_SOURCE_SHA256.txt"
    if (not idmap_proof.is_file() or idmap_proof.is_symlink()
            or idmap_proof.read_text(encoding="utf-8") !=
                PATCHED_IDMAP_SHA256 + "  libmount/src/hook_idmap.c\n"):
        raise ValueError("Missing or mismatched build-only source patch evidence")
    debs = sorted(x for x in existing if x.suffix == ".deb")
    if not debs:
        raise ValueError("No Debian binary candidates produced")
    for file in existing:
        if (file.is_symlink() or not file.is_file()
                or (file.name not in allowed
                    and file.suffix not in (".deb", ".changes", ".buildinfo"))
                or (file.suffix in (".deb", ".changes", ".buildinfo")
                    and not file.name.startswith("util-linux_")
                    and file.suffix != ".deb")):
            raise ValueError("Unexpected output in experimental package folder")
    packages = []
    for deb in debs:
        def field(key: str) -> str:
            result = subprocess.run(
                ["dpkg-deb", "--field", str(deb), key],
                capture_output=True, text=True, check=False, timeout=20
            )
            if result.returncode != 0:
                raise ValueError("Debian binary package cannot be inspected")
            return result.stdout.strip()
        package = field("Package")
        version = field("Version")
        source = field("Source")
        arch = field("Architecture")
        expected_version = (
            LOGIN_VERSION if package in LOGIN_PACKAGES
            else BSDUTILS_VERSION if package in BSDUTILS_PACKAGES
            else EXPERIMENT_VERSION
        )
        if (not package or version != expected_version
                or arch not in ("amd64", "all")
                or not (source == "util-linux"
                        or source == f"util-linux ({EXPERIMENT_VERSION})"
                        or (package == "util-linux" and not source))):
            raise ValueError("Binary version, architecture or source is unexpected")
        packages.append({
            "name": package,
            "version": version,
            "arch": arch,
            "sha256": _sha256(deb),
        })
    if not any(p["name"] == "util-linux" for p in packages):
        raise ValueError("The essential util-linux package was not built")
    report = {
        **input_report,
        "status": "experimental_debian_13_binary_inventory_release_blocked",
        "debian_binary_packages_built": True,
        "binary_package_count": len(packages),
        "debian_login_binary_version": LOGIN_VERSION,
        "debian_bsdutils_binary_version": BSDUTILS_VERSION,
        "packages": packages,
        "debian_trixie_abi_validated": False,
        "experimental_build_only_patch_sha256": BUILD_PATCH_SHA256,
        "experimental_patched_idmap_sha256": PATCHED_IDMAP_SHA256,
        "cve_remediated": False,
        "runtime_image_replaced": False,
        "security_gate": "blocked",
        "release_authorized": False,
    }
    manifest = folder / "UNSIGNED_BINARY_RESEARCH_ONLY.json"
    if manifest.exists() or manifest.is_symlink():
        raise ValueError("Refusing to overwrite an experimental binary manifest")
    manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    os.chmod(manifest, 0o600)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--binary-dir", type=Path)
    args = parser.parse_args()
    try:
        report = validate_handoff(args.source_dir)
        if args.binary_dir is not None:
            report = verify_binary_inventory(args.binary_dir, report)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, json.JSONDecodeError,
            subprocess.TimeoutExpired):
        print(json.dumps({
            "status": "error", "reason": "binary_source_handoff_unverified",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 2  # Valid source still does not authorize a binary build's release.


if __name__ == "__main__":
    raise SystemExit(main())
