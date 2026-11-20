"""Attest retained ClamAV native files and the EXACT expected .deb removals.

The minimal runtime deliberately deletes 10 unnecessary package-owned CLIs.
dpkg -V is thus expected to report precisely these missing files; any other
missing/modified file is a fail-closed error. This is NOT a valid upstream .deb
installation claim or a release waiver.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

DENY = (
    "/usr/local/bin/clamav-config",
    "/usr/local/bin/clambc",
    "/usr/local/bin/clamconf",
    "/usr/local/bin/clamdscan",
    "/usr/local/bin/clamdtop",
    "/usr/local/bin/clamsubmit",
    "/usr/local/bin/freshclam",
    "/usr/local/bin/sigtool",
    "/usr/local/sbin/clamd",
    "/usr/local/sbin/clamonacc",
)
KEEP = "/usr/local/bin/clamscan"
VERSION = "1.5.5-1"
CODE_ROOTS = ("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/lib/")


def _run(args: list[str], *, timeout: int = 30, permitted: tuple[int, ...] = (0,)):
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Installed ClamAV inventory unavailable") from error
    if p.returncode not in permitted:
        raise ValueError("Unexpected Debian ClamAV inventory failure")
    return p


def _digest(path: Path) -> str | None:
    result = hashlib.sha256()
    with path.open("rb") as file:
        head = file.read(8)
        if not (head.startswith(b"\x7fELF") or
                (str(path).endswith(".a") and head == b"!<arch>\n")):
            return None
        result.update(head)
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def inventory() -> dict:
    if _run(["dpkg-query", "-W", "-f=${Version}", "clamav"]).stdout.strip() != VERSION:
        raise ValueError("Wrong ClamAV package version")
    if _run(["dpkg", "--print-architecture"]).stdout.strip() != "amd64":
        raise ValueError("Wrong native architecture")
    if _run(["clamscan", "--version"]).stdout.strip() != "ClamAV 1.5.5":
        raise ValueError("ClamAV required scanner unavailable")

    for name in DENY:
        if os.path.lexists(name):
            raise ValueError("Unnecessary ClamAV CLI survived in image")
    if not Path(KEEP).is_file() or stat.S_IMODE(Path(KEEP).stat().st_mode) != 0o755:
        raise ValueError("Clamscan executable was removed or disabled")

    # Explicitly inspect dpkg's expected missing list. A clean package
    # manifest is NOT claimed after these deliberate physical deletions.
    verify = _run(["dpkg", "-V", "clamav"], timeout=50, permitted=(0, 1))
    missing = []
    for line in verify.stdout.splitlines():
        match = re.fullmatch(r"missing\s+(/\S+)", line.strip())
        if not match:
            raise ValueError("Unexpected ClamAV package file mutation")
        missing.append(match.group(1))
    if sorted(missing) != sorted(DENY):
        raise ValueError("dpkg verification did not report exactly ten removed CLIs")
    if verify.stderr.strip():
        raise ValueError("Unrecognized dpkg verification diagnostic")

    listing = _run(["dpkg-query", "-L", "clamav"]).stdout.splitlines()
    package_clis = sorted(
        name for name in listing
        if name.startswith(("/usr/local/bin/", "/usr/local/sbin/"))
    )
    if package_clis != sorted((KEEP, *DENY)):
        raise ValueError("ClamAV package-owned CLI manifest changed")

    files: list[dict] = []
    for name in listing:
        if not name.startswith(CODE_ROOTS):
            continue
        if not os.path.lexists(name):
            if name in DENY:
                continue
            raise ValueError("Unapproved missing package-owned file")
        path = Path(name)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or stat.S_ISDIR(info.st_mode):
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022
                or info.st_uid != 0):
            raise ValueError("Unexpected installed ClamAV native code type")
        digest = _digest(path)
        if digest:
            files.append({"path": name, "sha256": digest})
    files.sort(key=lambda entry: entry["path"])
    if not files or len(files) > 200:
        raise ValueError("Unexpected retained native manifest size")
    for expected in (
        KEEP, "/usr/local/lib/libclamav.so.12.1.0",
        "/usr/local/lib/libclamav_rust.a",
    ):
        if expected not in {x["path"] for x in files}:
            raise ValueError("Required signed ClamAV runtime library removed")

    links = _run(["ldd", KEEP], timeout=12).stdout
    link = Path("/usr/local/lib/libclamav.so.12").resolve(strict=True)
    if ("libclamav.so.12 => /usr/local/lib/libclamav.so.12" not in links
            or "not found" in links
            or str(link) != "/usr/local/lib/libclamav.so.12.1.0"):
        raise ValueError("Required scanned-library linkage was changed")

    return {
        "source": "folio-clamav-minimal-native-v1",
        "package": "clamav", "package_version": VERSION,
        "architecture": "amd64",
        "clamscan_version": "ClamAV 1.5.5",
        "expected_absent": sorted(DENY),
        "dpkg_verified_expected_removals": True,
        "shared_library_linked": True,
        "files": files, "release_authorized": False,
    }


def main() -> int:
    try:
        report = inventory()
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "error",
                          "reason": "clamav_minimal_package_integrity_invalid"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
