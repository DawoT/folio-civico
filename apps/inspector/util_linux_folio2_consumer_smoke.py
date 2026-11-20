"""R1.38: read-only nonprivileged Debian 13 consumer smoke using folio2 DSOs.

Runs stock Debian consumers with candidate shared libraries in an ephemeral
tmpfs. Never installs a .deb, performs mount/namespace actions, changes a
runtime image, issues a VEX or authorizes a release. Success exits 2.
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

from util_linux_folio2_binary import (
    EXPECTED_PACKAGES, SOURCE_HASHES, SOURCE_VERSION, _private_folder,
    expected_binary_version,
)
from util_linux_trixie_binary_experiment import IMAGE

PINNED_DEBS = {
    "libuuid1": "811ebda0609b334ca359e39dc9dc1c3f366e6b69f584ec2c69045b2cf8d2a155",
    "libblkid1": "c9a66ba4240baf50d0b861817c9efc940facbd9dc8d35b762723a73a760177a1",
    "libmount1": "12b47b934c0561dd120879b4b7f8a849558ec4c23b0ab546d4a3b7ff5f7e8c59",
    "libsmartcols1": "0a1f7ac40f3f6a7d783f43883e8259a1d12b0e72ed1d76718bde42615d235513",
    "libfdisk1": "14837fe404d7771aee1ba89598ce154f928ef0cf3a0c0bd74b9aef0c223b5cbd",
}
MANIFEST_NAME = "UNSIGNED_FOLIO2_BINARY_RESEARCH_ONLY.json"
# Exact Debian 13.7 2.41.5 stock consumer/auxiliary package bytes downloaded
# via signed APT indexes, NOT installed on the host or inspector.
STOCK_PINS = {
    "fdisk_2.41.5-0+deb13u1_amd64.deb":
        "7f37094ca3f63c3a07b4431532b0bcc4aa64291e75c48cabebf41bf42ad706b1",
    "uuid-runtime_2.41.5-0+deb13u1_amd64.deb":
        "826690419ef231e93d3d756ab19835ebd0fe3029bb1314987fd8f76fd04c6983",
    "libreadline8t64_8.2-6_amd64.deb":
        "eeadf2b5e755c9f183883feea2d9b5b28560284275d5f54d3e55d0923b1d0967",
    "libncursesw6_6.5+20250216-2_amd64.deb":
        "47baa2e11579583654583a066b69bd5a5d2f22423081f707ed6c0c3ba6d538b7",
}
# Read-only operations only. The host's installed Debian 2.41.5 commands
# dynamically load the candidate 2.41.6 DSOs via a private LD_LIBRARY_PATH.
STOCK_CONSUMERS = ("lsblk", "findmnt", "blkid", "mount", "umount")
PROVEN_LOADED_DSOS = ("libmount1", "libblkid1", "libsmartcols1")

SMOKE_SCRIPT = r"""
set -eu
for pkg in libuuid1 libblkid1 libmount1 libsmartcols1 libfdisk1; do
  f="$(find /artifacts -maxdepth 1 -name "$pkg"'_*.deb' -print -quit)"
  test -n "$f"
  mkdir -p "/scratch/$pkg"
  dpkg-deb -x "$f" "/scratch/$pkg"
done
export LD_LIBRARY_PATH="/scratch/libuuid1/usr/lib/x86_64-linux-gnu:/scratch/libblkid1/usr/lib/x86_64-linux-gnu:/scratch/libmount1/usr/lib/x86_64-linux-gnu:/scratch/libsmartcols1/usr/lib/x86_64-linux-gnu:/scratch/libfdisk1/usr/lib/x86_64-linux-gnu"
/usr/bin/lsblk --version
/usr/bin/findmnt --version
/usr/sbin/blkid --version
/usr/bin/mount --version
/usr/bin/umount --version
# Safe, non-mutating calls against kernel-provided read-only metadata.
/usr/bin/lsblk -J -o NAME,TYPE >/dev/null
/usr/bin/findmnt --kernel -n -o TARGET >/dev/null
LD_DEBUG=libs /usr/bin/findmnt --version >/dev/null 2>/scratch/findmnt-linker.log
LD_DEBUG=libs /usr/bin/lsblk --version >/dev/null 2>/scratch/lsblk-linker.log
grep -q '/scratch/libmount1/.*libmount.so.1' /scratch/findmnt-linker.log
grep -q '/scratch/libblkid1/.*libblkid.so.1' /scratch/findmnt-linker.log
grep -q '/scratch/libsmartcols1/.*libsmartcols.so.1' /scratch/lsblk-linker.log
echo 'folio2_stock_debian_consumers_and_three_dynamic_library_loads=pass'
"""

STOCK_SCRIPT = r"""
mkdir /scratch/stock
for pkg in fdisk uuid-runtime libreadline8t64 libncursesw6; do
  f="$(find /stock -maxdepth 1 -name "$pkg"'_*.deb' -print -quit)"
  test -n "$f"
  dpkg-deb -x "$f" /scratch/stock
done
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/scratch/stock/usr/lib/x86_64-linux-gnu"
/scratch/stock/usr/bin/uuidgen --version
/scratch/stock/usr/sbin/fdisk --version
LD_DEBUG=libs /scratch/stock/usr/bin/uuidgen --version >/dev/null 2>/scratch/uuidgen-linker.log
LD_DEBUG=libs /scratch/stock/usr/sbin/fdisk --version >/dev/null 2>/scratch/fdisk-linker.log
grep -q '/scratch/libuuid1/.*libuuid.so.1' /scratch/uuidgen-linker.log
grep -q '/scratch/libfdisk1/.*libfdisk.so.1' /scratch/fdisk-linker.log
echo 'folio2_stock_fdisk_uuidgen_two_more_library_loads=pass'
"""


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            sha.update(block)
    return sha.hexdigest()


def verify_binary_handoff(folder: Path) -> dict:
    """Read-only admission of the existing, already inventoried R1.37 build."""
    if os.geteuid() == 0:
        raise ValueError("Cannot run consumer research as host root")
    if os.geteuid() == 0:
        raise ValueError("Non-root consumer research required")
    _private_folder(folder)
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(folder)):
        raise ValueError("Unsafe Docker mount source path")
    manifest = folder / MANIFEST_NAME
    if (not manifest.is_file() or manifest.is_symlink()
            or stat.S_IMODE(manifest.stat().st_mode) != 0o600
            or manifest.stat().st_size > 32000):
        raise ValueError("Unsigned research inventory missing or unsafe")
    try:
        doc = json.loads(manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("Unsigned research manifest invalid") from error
    expected = {
        "status": "folio2_debian13_binary_research_release_blocked",
        "source_version": SOURCE_VERSION,
        "source_sha256": SOURCE_HASHES,
        "binary_package_count": 43,
        "debian_binary_packages_built": True,
        "debian_trixie_abi_validated": False,
        "cve_remediated": False,
        "release_authorized": False,
        "security_gate": "blocked",
    }
    if (not isinstance(doc, dict)
            or any(doc.get(key) != value for key, value in expected.items())):
        raise ValueError("Cannot admit package inventory or release state")
    packages = doc.get("packages")
    if (not isinstance(packages, list) or len(packages) != 43
            or len({x.get("name") for x in packages
                    if isinstance(x, dict)}) != 43):
        raise ValueError("Missing or duplicate Debian package entries")
    entries = {x["name"]: x for x in packages}
    if set(entries) != EXPECTED_PACKAGES:
        raise ValueError("Experimental package identity set was altered")
    for package, expected_sha in PINNED_DEBS.items():
        if package not in entries:
            raise ValueError("Required candidate library missing")
        row = entries[package]
        expected_filename = f"{package}_{SOURCE_VERSION}_amd64.deb"
        item = folder / expected_filename
        if (row.get("file") != expected_filename
                or row.get("version") != expected_binary_version(package)
                or row.get("architecture") != "amd64"
                or row.get("sha256") != expected_sha
                or not item.is_file() or item.is_symlink()
                or stat.S_IMODE(item.stat().st_mode) != 0o600
                or item.stat().st_size > 64 * 1024 * 1024
                or digest(item) != expected_sha):
            raise ValueError("Candidate library does not match verified R1.37")
    return {
        "status": "pinned_folio2_debian_consumers_admitted_release_blocked",
        "source_version": SOURCE_VERSION,
        "image": IMAGE,
        "pinned_dso_packages": list(PINNED_DEBS),
        "pinned_dso_sha256": dict(PINNED_DEBS),
        "stock_consumers": list(STOCK_CONSUMERS),
        "release_authorized": False,
        "cve_remediated": False,
    }


def verify_stock_packages(folder: Path) -> dict:
    _private_folder(folder)
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(folder)):
        raise ValueError("Unsafe Debian stock consumer bind path")
    if {item.name for item in folder.iterdir()} != set(STOCK_PINS):
        raise ValueError("Unapproved Debian reference consumer packages")
    for filename, checksum in STOCK_PINS.items():
        path = folder / filename
        if (not path.is_file() or path.is_symlink()
                or stat.S_IMODE(path.stat().st_mode) != 0o600
                or path.stat().st_size > 10 * 1024 * 1024
                or digest(path) != checksum):
            raise ValueError("Debian consumer not from signed APT SHA pins")
    return {"stock_consumer_sha256": dict(STOCK_PINS)}


def _command(argv: list[str], timeout: int) -> str:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Isolated Debian consumer test failed") from error
    if result.returncode:
        raise ValueError("Isolated Debian consumer contract did not pass")
    return result.stdout


def run_consumer_smoke(folder: Path, stock_dir: Path | None = None) -> dict:
    report = verify_binary_handoff(folder)
    stock_report = verify_stock_packages(stock_dir) if stock_dir is not None else {}
    endpoint = os.environ.get("DOCKER_HOST")
    if endpoint and not endpoint.startswith("unix://"):
        raise ValueError("Remote Docker endpoint forbidden")
    context = _command([
        "docker", "context", "inspect", "--format",
        "{{.Endpoints.docker.Host}}",
    ], timeout=20).strip()
    if not context.startswith("unix://"):
        raise ValueError("Docker research must use a local Unix socket")
    _command(["docker", "image", "inspect", IMAGE], timeout=20)
    docker_args = [
        "docker", "run", "--rm", "--pull", "never",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--pids-limit", "64", "--cpus", "1", "--memory", "1g",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--tmpfs", "/scratch:rw,nosuid,nodev,exec,size=256m,mode=1777",
        "--mount", f"type=bind,src={folder},dst=/artifacts,readonly",
    ]
    if stock_dir is not None:
        docker_args.extend([
            "--mount", f"type=bind,src={stock_dir},dst=/stock,readonly"
        ])
    docker_args.extend([
        IMAGE, "sh", "-euc",
        SMOKE_SCRIPT + (STOCK_SCRIPT if stock_dir is not None else ""),
    ])
    output = _command(docker_args, timeout=120)
    if "folio2_stock_debian_consumers_and_three_dynamic_library_loads=pass" not in output:
        raise ValueError("Debian consumer evidence marker missing")
    if (stock_dir is not None and
            "folio2_stock_fdisk_uuidgen_two_more_library_loads=pass" not in output):
        raise ValueError("Debian fdisk/uuidgen evidence marker missing")
    return {
        **report,
        "status": "nonprivileged_folio2_stock_debian_consumer_smoke_release_blocked",
        "consumer_process_exit_zero": True,
        "candidate_libraries_proven_loaded": (
            list(PROVEN_LOADED_DSOS) +
            (["libuuid1", "libfdisk1"] if stock_dir is not None else [])
        ),
        "consumer_abi_coverage": (
            "seven_stock_debian_commands_five_candidate_dsos_only"
            if stock_dir is not None
            else "five_stock_debian_commands_three_candidate_dsos_only"
        ),
        **stock_report,
        "debian_trixie_abi_validated": False,
        "runtime_cve_regressions_passed": False,
        "runtime_image_replaced": False,
        "vex": "not_issued",
        "release_authorized": False,
        "security_gate": "blocked",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--stock-dir", type=Path)
    args = parser.parse_args()
    try:
        result = run_consumer_smoke(args.binary_dir, args.stock_dir)
    except (ValueError, OSError, TypeError, UnicodeError):
        print(json.dumps({
            "status": "debian_consumer_contract_unverified",
            "release_authorized": False,
            "security_gate": "blocked",
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2  # Valid consumer evidence remains UNAPPROVED for release.


if __name__ == "__main__":
    raise SystemExit(main())
