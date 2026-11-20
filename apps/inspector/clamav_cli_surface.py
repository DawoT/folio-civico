"""R1.27: physically remove unused ClamAV CLI programs from runtime.

chmod 0644 is insufficient: ld-linux (or sh for scripts) can load readable
non-executable files. This fail-closed experiment therefore UNLINKS the ten
unused commands in a throwaway build stage and flattens into a new FROM scratch
runtime. Only clamscan is retained. The original signed package is untouched.

No CVE is declared fixed; all installed package metadata remains in Trivy.
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

KEEP = "/usr/local/bin/clamscan"
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
CLI_PATHS = tuple(sorted((KEEP, *DENY)))
PACKAGE_VERSION = "1.5.5-1"
SOURCE = "folio-clamav-cli-mode-v2"
PATH_ALLOWED = re.compile(r"^/usr/local/(?:s?bin)/[a-z0-9_-]+$")


def _package_paths() -> list[str]:
    try:
        version = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", "clamav"],
            capture_output=True, text=True, check=False, timeout=12,
        )
        listed = subprocess.run(
            ["dpkg-query", "-L", "clamav"],
            capture_output=True, text=True, check=False, timeout=12,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("ClamAV Debian package ownership unavailable") from error
    if version.returncode or version.stdout.strip() != PACKAGE_VERSION or listed.returncode:
        raise ValueError("Unverified ClamAV package version or manifest")
    return listed.stdout.splitlines()


def _sha256(file: Path) -> str:
    digest = hashlib.sha256()
    with file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(
    root: Path = Path("/"), *,
    listed_paths: tuple[str, ...] | list[str] | None = None,
    package_version: str = PACKAGE_VERSION,
) -> dict:
    root = Path(root).resolve(strict=True)
    if package_version != PACKAGE_VERSION:
        raise ValueError("Unsupported ClamAV package version")
    listing = list(listed_paths) if listed_paths is not None else _package_paths()
    owned = [
        p for p in listing
        if isinstance(p, str) and
        p.startswith(("/usr/local/bin/", "/usr/local/sbin/"))
    ]
    if sorted(owned) != list(CLI_PATHS) or any(
        not PATH_ALLOWED.fullmatch(p) for p in owned
    ):
        raise ValueError("Installed ClamAV package command manifest changed")
    files: list[dict] = []
    absent: list[str] = []
    for name in CLI_PATHS:
        file = root / name.lstrip("/")
        if not os.path.lexists(file):
            absent.append(name)
            continue
        info = file.lstat()
        # Non-root isolated unit test fixtures retain their own owner, but
        # real runtime inventory and gate require root ownership.
        if (not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or (root == Path("/") and info.st_uid != 0)
                or stat.S_IMODE(info.st_mode) != 0o755):
            raise ValueError("ClamAV package-owned executable is untrusted")
        files.append({
            "path": name, "mode": "0755", "uid": info.st_uid,
            "sha256": _sha256(file),
        })
    if not absent:
        state = "baseline"
    elif absent == sorted(DENY) and [r["path"] for r in files] == [KEEP]:
        state = "limited"
    else:
        raise ValueError("Partial/ambiguous deletion of ClamAV CLI entrypoints")
    return {
        "source": SOURCE, "scan_complete": True, "state": state,
        "package": "clamav", "package_version": PACKAGE_VERSION,
        "absent": absent, "files": files,
    }


def harden(
    root: Path = Path("/"), *,
    listed_paths: tuple[str, ...] | list[str] | None = None,
    package_version: str = PACKAGE_VERSION,
) -> dict:
    root = Path(root).resolve(strict=True)
    before = inventory(root, listed_paths=listed_paths, package_version=package_version)
    if before["state"] != "baseline":
        raise ValueError("Cannot remove ClamAV CLI programs from already modified source")
    keep_hash = next(row["sha256"] for row in before["files"] if row["path"] == KEEP)
    # Delete regular, root-owned files only. No symlink-following, chmod,
    # file rewriting, or executable shadow copies in final OCI layer.
    for name in DENY:
        (root / name.lstrip("/")).unlink()
    after = inventory(root, listed_paths=listed_paths, package_version=package_version)
    if (after["state"] != "limited" or after["absent"] != sorted(DENY)
            or after["files"][0]["sha256"] != keep_hash):
        raise ValueError("ClamAV CLI removal or retained scanner failed")
    return after


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        result = harden() if args.apply else inventory()
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "error", "reason": "clamav_cli_presence_invalid"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
