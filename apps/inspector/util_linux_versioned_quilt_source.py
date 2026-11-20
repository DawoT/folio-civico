"""R1.36: rebuild a distinct unsigned Debian 3.0 (quilt) source package.

Source-only, non-root and fail-closed. Incorporate the separately pinned R1.35
openat2 header fix as quilt PATCH 11, keeping all R1.34 CVE and Debian patches.
Never install packages, publish images, grant VEX or authorize a release.
A valid result deliberately exits 2 (release blocked); errors exit 3.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from util_linux_debian_source_overlay import (
    EXPERIMENT_VERSION, EXPECTED_OVERLAY_SERIES, SOURCE_DATE_EPOCH,
    VERSION, TAR_SHA256, _normalize_debian_mtimes,
)
from util_linux_source_candidate import (
    PATCHED_NSENTER_SHA256, REQUIRED_SOURCES, _assert_cve_source_semantics,
)
from util_linux_trixie_binary_experiment import (
    BUILD_PATCH, BUILD_PATCH_SHA256, PATCHED_IDMAP_SHA256, validate_handoff,
)

VERSIONED_SOURCE_VERSION = "2.41.6-0+folio2~deb13u1"
VERSIONED_PATCH_NAME = "upstream/folio-r136-openat2-header.patch"
VERSIONED_SERIES = (*EXPECTED_OVERLAY_SERIES, VERSIONED_PATCH_NAME)
VERSIONED_MANIFEST_NAME = "UNSIGNED_VERSIONED_SOURCE_ONLY.json"
UNPATCHED_IDMAP_SHA256 = "f6fc59c0ffa7e4d1a9adfc2b0811e64e9c146dc7f625297031fa9666523ab374"
CHANGELOG_DATE = "Fri, 20 Nov 2026 11:00:00 -0500"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(argv: list[str], cwd: Path, *, timeout: int = 180) -> str:
    try:
        process = subprocess.run(
            argv, cwd=cwd, text=True, capture_output=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Debian versioned source operation failed") from error
    if process.returncode:
        raise ValueError("Debian versioned source verification failed")
    return process.stdout


def validate_output_path(source: Path, dest: Path) -> Path:
    """Refuse pre-existing, symlinked, relative or overlapping output paths."""
    if (not source.is_absolute() or not dest.is_absolute()
            or ".." in dest.parts or dest in (Path("/"), Path("/tmp"))
            or dest.exists() or dest.is_symlink()
            or not dest.parent.is_dir() or dest.parent.is_symlink()
            or dest.parent.resolve(strict=True) != dest.parent):
        raise ValueError("Source export output must be a new canonical private path")
    if dest == source or source in dest.parents or dest in source.parents:
        raise ValueError("Source export cannot overlap its input")
    return dest


def _source_changelog(previous: str) -> str:
    if not previous.startswith(
        f"util-linux ({EXPERIMENT_VERSION}) UNRELEASED; urgency=low\n"
    ):
        raise ValueError("Prior versioned source changelog is unexpected")
    return (
        f"util-linux ({VERSIONED_SOURCE_VERSION}) UNRELEASED; urgency=low\n\n"
        "  * Folio Civico local Debian 13 source research only (NOT A RELEASE).\n"
        "  * Include the audited R1.35 openat2 header fix as an 11th quilt patch.\n"
        "  * Preserve the 10 source patches and CVE-2026-78408 follow-up.\n\n"
        f" -- Folio Civico Local Lab <noreply@invalid>  {CHANGELOG_DATE}\n\n"
        + previous
    )


def validate_quilt_tree(tree: Path) -> None:
    """Verify exact final quilt order, version and both fixed source bytes."""
    if not tree.is_dir() or tree.is_symlink():
        raise ValueError("Missing unpacked versioned source tree")
    series = tree / "debian/patches/series"
    changelog = tree / "debian/changelog"
    idmap = tree / "libmount/src/hook_idmap.c"
    nsenter = tree / "sys-utils/nsenter.c"
    patch = tree / "debian/patches" / VERSIONED_PATCH_NAME
    if any(not item.is_file() or item.is_symlink()
           for item in (series, changelog, idmap, nsenter, patch)):
        raise ValueError("Versioned Debian source lost a required file")
    if series.read_text(encoding="utf-8").splitlines() != list(VERSIONED_SERIES):
        raise ValueError("Versioned quilt source patch list/order changed")
    if not changelog.read_text(encoding="utf-8").startswith(
        f"util-linux ({VERSIONED_SOURCE_VERSION}) UNRELEASED; urgency=low\n"
    ):
        raise ValueError("Versioned source must remain explicitly UNRELEASED")
    if digest(patch) != BUILD_PATCH_SHA256:
        raise ValueError("Versioned quilt patch changed after verification")
    if digest(idmap) != PATCHED_IDMAP_SHA256:
        raise ValueError("Versioned openat2 fix not present in source bytes")
    if digest(nsenter) != PATCHED_NSENTER_SHA256:
        raise ValueError("CVE-2026-78408 backport not preserved in source bytes")


def validate_versioned_dsc(content: str, expected: dict[str, tuple[str, int]]) -> dict:
    """Compare unsigned .dsc identity and SHA-256 file inventory to actual bytes."""
    if "-----BEGIN PGP" in content or not isinstance(expected, dict):
        raise ValueError("Source descriptor is signed or has invalid inventory")
    fields: dict[str, str] = {}
    for line in content.splitlines():
        match = re.fullmatch(r"(Format|Source|Version): (.+)", line)
        if match:
            key, value = match.groups()
            if key in fields:
                raise ValueError("Duplicated descriptor identity metadata")
            fields[key] = value
    if fields != {
        "Format": "3.0 (quilt)",
        "Source": "util-linux",
        "Version": VERSIONED_SOURCE_VERSION,
    }:
        raise ValueError("Debian source descriptor impersonates another package")
    lines = content.splitlines()
    if lines.count("Checksums-Sha256:") != 1:
        raise ValueError("Unsigned descriptor lacks unique SHA-256 inventory")
    index = lines.index("Checksums-Sha256:") + 1
    listing: dict[str, tuple[str, int]] = {}
    while index < len(lines) and lines[index].startswith((" ", "\t")):
        match = re.fullmatch(r"\s+([a-f0-9]{64}) ([0-9]+) (\S+)", lines[index])
        if match is None:
            raise ValueError("Malformed SHA-256 descriptor row")
        checksum, size, filename = match.groups()
        if filename in listing or int(size) <= 0:
            raise ValueError("Duplicated or invalid descriptor payload")
        listing[filename] = (checksum, int(size))
        index += 1
    if listing != expected:
        raise ValueError("Source descriptor SHA-256 metadata differs from bytes")
    return {"version": VERSIONED_SOURCE_VERSION, "sha256": listing}


def _verify_cve_semantics(tree: Path) -> None:
    source: dict[str, str] = {}
    for relative in REQUIRED_SOURCES:
        path = tree / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("Signed vendor CVE source file missing")
        source[relative] = path.read_text(encoding="utf-8", errors="strict")
    _assert_cve_source_semantics(source)


def build_versioned_source(source: Path, dest: Path) -> dict:
    """Build and export an unsigned, independently versioned source-only handoff."""
    if os.geteuid() == 0:
        raise ValueError("Non-root source-only build required")
    validate_output_path(source, dest)
    admitted = validate_handoff(source)
    if admitted.get("release_authorized") is not False:
        raise ValueError("Versioned source input must be release-blocked")
    if (not BUILD_PATCH.is_file() or BUILD_PATCH.is_symlink()
            or digest(BUILD_PATCH) != BUILD_PATCH_SHA256):
        raise ValueError("The additional openat2 source patch was modified")

    orig_name = f"util-linux_{VERSION}.orig.tar.xz"
    dsc_name = f"util-linux_{VERSIONED_SOURCE_VERSION}.dsc"
    tar_name = f"util-linux_{VERSIONED_SOURCE_VERSION}.debian.tar.xz"
    names = (orig_name, dsc_name, tar_name)

    with tempfile.TemporaryDirectory(prefix="folio-ul-r136-quilt-", dir="/tmp") as tmp:
        work = Path(tmp)
        tree = work / "overlay"
        _run([
            "dpkg-source", "--no-check", "-x",
            str(source / f"util-linux_{EXPERIMENT_VERSION}.dsc"), str(tree)
        ], work, timeout=120)
        original_series = tree / "debian/patches/series"
        if original_series.read_text(encoding="utf-8").splitlines() != list(
            EXPECTED_OVERLAY_SERIES
        ):
            raise ValueError("Original source quilt series is not R1.34")
        idmap = tree / "libmount/src/hook_idmap.c"
        nsenter = tree / "sys-utils/nsenter.c"
        if (not idmap.is_file() or idmap.is_symlink()
                or digest(idmap) != UNPATCHED_IDMAP_SHA256
                or not nsenter.is_file() or nsenter.is_symlink()
                or digest(nsenter) != PATCHED_NSENTER_SHA256):
            raise ValueError("R1.34 source before openat2 quilt fix was changed")
        _verify_cve_semantics(tree)

        # Require a forward-only patch. No --batch or auto-reverse patch tool.
        _run(["git", "apply", "--check", str(BUILD_PATCH)], tree, timeout=25)
        reverse = subprocess.run(
            ["git", "apply", "--reverse", "--check", str(BUILD_PATCH)],
            cwd=tree, capture_output=True, timeout=25, check=False,
        )
        if reverse.returncode == 0:
            raise ValueError("Portability patch is already present or reversed")

        patch_dest = tree / "debian/patches" / VERSIONED_PATCH_NAME
        patch_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BUILD_PATCH, patch_dest)
        if digest(patch_dest) != BUILD_PATCH_SHA256:
            raise ValueError("Copied quilt patch bytes were modified")
        original_series.write_text(
            "\n".join(VERSIONED_SERIES) + "\n", encoding="utf-8"
        )
        changelog = tree / "debian/changelog"
        changelog.write_text(
            _source_changelog(changelog.read_text(encoding="utf-8")),
            encoding="utf-8",
        )

        shutil.copyfile(source / orig_name, work / orig_name)
        if digest(work / orig_name) != TAR_SHA256:
            raise ValueError("Vendor upstream signed tar changed")
        _normalize_debian_mtimes(tree / "debian")
        env = os.environ.copy()
        env["SOURCE_DATE_EPOCH"] = str(SOURCE_DATE_EPOCH)

        def run_build(argv: list[str], cwd: Path, timeout: int = 180) -> None:
            try:
                result = subprocess.run(
                    argv, cwd=cwd, env=env,
                    capture_output=True, text=True, timeout=timeout,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError("Quilt source build timed out or could not run") from error
            if result.returncode:
                raise ValueError("Quilt source roundtrip failed")

        run_build(["dpkg-source", "--before-build", str(tree)], work)
        validate_quilt_tree(tree)
        _verify_cve_semantics(tree)
        run_build(["dpkg-source", "-b", str(tree)], work, timeout=180)
        if not (work / dsc_name).is_file() or not (work / tar_name).is_file():
            raise ValueError("Versioned Debian 3.0 (quilt) outputs not created")
        expected = {
            name: (digest(work / name), (work / name).stat().st_size)
            for name in (orig_name, tar_name)
        }
        validate_versioned_dsc(
            (work / dsc_name).read_text(encoding="utf-8"), expected
        )
        roundtrip = work / "roundtrip"
        run_build([
            "dpkg-source", "--no-check", "-x", str(work / dsc_name),
            str(roundtrip)
        ], work)
        validate_quilt_tree(roundtrip)
        _verify_cve_semantics(roundtrip)
        if list(work.rglob("*.deb")) or list(work.rglob("*.udeb")):
            raise ValueError("Versioned source-only stage built binary packages")

        sums = {name: digest(work / name) for name in names}
        report = {
            "status": "unsigned_versioned_debian_source_roundtrip_release_blocked",
            "previous_source_version": EXPERIMENT_VERSION,
            "versioned_debian_source_version": VERSIONED_SOURCE_VERSION,
            "vendor_upstream_sha256": TAR_SHA256,
            "source_date_epoch": SOURCE_DATE_EPOCH,
            "source_sha256": sums,
            "quilt_patch_count": len(VERSIONED_SERIES),
            "additional_quilt_patch": VERSIONED_PATCH_NAME,
            "additional_quilt_patch_sha256": BUILD_PATCH_SHA256,
            "patched_idmap_sha256": PATCHED_IDMAP_SHA256,
            "cve_78408_source_semantics_verified": True,
            "debian_original_dsc_signed": True,
            "versioned_dsc_signed": False,
            "source_roundtrip_verified": True,
            "debian_binary_packages_built": False,
            "debian_trixie_abi_validated": False,
            "cve_remediated": False,
            "runtime_image_replaced": False,
            "vex": "not_issued",
            "release_authorized": False,
            "security_gate": "blocked",
        }
        validate_output_path(source, dest)
        dest.mkdir(mode=0o700)
        try:
            os.chmod(dest, 0o700)
            for name in names:
                target = dest / name
                shutil.copyfile(work / name, target)
                os.chmod(target, 0o600)
                if digest(target) != sums[name]:
                    raise ValueError("Versioned source changed during private export")
            marker = dest / VERSIONED_MANIFEST_NAME
            marker.write_text(
                json.dumps(report, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            os.chmod(marker, 0o600)
        except Exception:
            shutil.rmtree(dest)
            raise
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build_versioned_source(args.source_dir, args.output_dir)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError,
            subprocess.TimeoutExpired, json.JSONDecodeError):
        print(json.dumps({
            "status": "error",
            "reason": "versioned_quilt_source_unverified",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 2  # Valid source-only proof does NOT authorize release.


if __name__ == "__main__":
    raise SystemExit(main())
