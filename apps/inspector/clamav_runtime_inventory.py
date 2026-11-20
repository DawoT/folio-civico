"""Read-only SHA-256 inventory of installed vendor ClamAV native code.

Must run inside an already-pinned experimental image without network, mounts
or privileges. No signature or VEX claims are made by this module.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess

VERSION = "1.5.5-1"
CODE_ROOTS = ("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/lib/")
SHA = re.compile(r"^[a-f0-9]{64}$")


def _run(argv: list[str], *, timeout: int = 20) -> str:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Runtime ClamAV native inventory probe unavailable") from error
    if p.returncode:
        raise ValueError("Runtime ClamAV native inventory command failed")
    return p.stdout


def _code_digest(handle, name: str) -> str | None:
    first = handle.read(8)
    if not (first.startswith(b"\x7fELF") or
            (name.endswith(".a") and first == b"!<arch>\n")):
        return None
    digest = hashlib.sha256()
    digest.update(first)
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def inventory() -> dict:
    if _run(["dpkg-query", "-W", "-f=${Version}", "clamav"], timeout=10).strip() != VERSION:
        raise ValueError("Installed ClamAV package differs from signed vendor version")
    if _run(["dpkg", "--print-architecture"], timeout=10).strip() != "amd64":
        raise ValueError("Unexpected ClamAV architecture")
    if _run(["clamscan", "--version"], timeout=10).strip() != "ClamAV 1.5.5":
        raise ValueError("ClamAV runtime engine differs from vendor package")
    if _run(["dpkg", "-V", "clamav"], timeout=30).strip():
        raise ValueError("Installed Debian package manifest verification failed")

    # dpkg-query --listfiles is the installed package's owning-file manifest,
    # not a filesystem glob that could accidentally include unrelated code.
    listing = _run(["dpkg-query", "-L", "clamav"], timeout=15)
    files: dict[str,str] = {}
    for name in listing.splitlines():
        if not any(name.startswith(root) for root in CODE_ROOTS):
            continue
        path = Path(name)
        try:
            info = path.lstat()
        except OSError as error:
            raise ValueError("Debian-owned native code inventory incomplete") from error
        if stat.S_ISLNK(info.st_mode) or stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise ValueError("Mutable or nonregular ClamAV native payload")
        with path.open("rb") as handle:
            digest = _code_digest(handle, name)
        if digest is None:
            continue
        if name in files:
            raise ValueError("Duplicate native code entry")
        files[name] = digest
        if len(files) > 200:
            raise ValueError("Unexpected installed native code count")

    for expected in (
        "/usr/local/bin/clamscan",
        "/usr/local/sbin/clamd",
        "/usr/local/lib/libclamav.so.12.1.0",
        "/usr/local/lib/libclamav_rust.a",
    ):
        if expected not in files:
            raise ValueError("Required installed Talos code is missing")
    # The real clamscan dynamically loads the very libclamav that we hash.
    links = _run(["ldd", "/usr/local/bin/clamscan"], timeout=12)
    marker = "libclamav.so.12 => /usr/local/lib/libclamav.so.12"
    link = Path("/usr/local/lib/libclamav.so.12").resolve(strict=True)
    if (marker not in links or "not found" in links or
            str(link) != "/usr/local/lib/libclamav.so.12.1.0" or
            str(link) not in files):
        raise ValueError("ClamAV runtime library linkage cannot be reconciled")

    return {
        "source": "folio-clamav-installed-native-v1",
        "package": "clamav",
        "package_version": VERSION,
        "architecture": "amd64",
        "clamscan_version": "ClamAV 1.5.5",
        "dpkg_verify_clean": True,
        "shared_library_linked": True,
        "files": [{"path": name, "sha256": digest}
                  for name,digest in sorted(files.items())],
        "release_authorized": False,
    }


def main() -> int:
    try:
        result = inventory()
    except (OSError, TypeError, ValueError, subprocess.TimeoutExpired):
        print(json.dumps({"status": "error", "reason": "runtime_clamav_native_inventory_invalid"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
