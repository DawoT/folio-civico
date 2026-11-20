"""Measure and remove unneeded SUID/SGID and namespace/mount launchers.

R1.24 is a NON-DEPLOYABLE security experiment. The scanner must continue to
show every CVE in the Debian packages. chmod never alters executable bytes.
All paths are exact and failure means no partial entitlement to a release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

PRIVILEGED = (
    "/usr/bin/chage", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/expiry", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/newgrp", "/usr/bin/passwd", "/usr/bin/su",
    "/usr/bin/umount", "/usr/sbin/unix_chkpwd",
)
NAMESPACE_TOOLS = (
    "/usr/bin/nsenter", "/usr/bin/unshare", "/usr/bin/setpriv",
)
GUARDED = tuple(sorted(PRIVILEGED + NAMESPACE_TOOLS))
EXCLUDED = {"proc", "sys", "dev", "run", "tmp", "mnt", "media"}
TAG = "folio-runtime-privilege-inventory-v1"


def _walk_special(root: Path) -> list[str]:
    found: list[str] = []
    def reject_walk_error(error: OSError) -> None:
        raise ValueError("Cannot enumerate complete filesystem for privileged bits") from error

    for directory, dirs, files in os.walk(
        root, topdown=True, followlinks=False, onerror=reject_walk_error,
    ):
        # Container runtime pseudo-FS may be mounted; never traverse them.
        location = Path(directory).relative_to(root)
        if location == Path("."):
            dirs[:] = [x for x in dirs if x not in EXCLUDED]
        for name in files:
            path = Path(directory) / name
            try:
                info = path.lstat()
            except OSError as error:
                raise ValueError("Incomplete privileged mode inventory") from error
            if stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o6000:
                found.append("/" + str(path.relative_to(root)))
    return sorted(found)


def inventory(root: Path = Path("/")) -> dict:
    root = Path(root).resolve(strict=True)
    records: list[dict] = []
    for name in GUARDED:
        target = root / name.lstrip("/")
        # Never follow attacker-controlled symlinks or unusual file types.
        try:
            mode = target.lstat().st_mode
        except OSError as error:
            raise ValueError("Mandatory restricted executable missing") from error
        if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
            raise ValueError("Restricted executable was replaced with a link")
        digest = hashlib.sha256()
        with target.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise ValueError("Non-ELF executable in critical privileged path")
            stream.seek(0)
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        records.append({
            "path": name,
            "mode": format(stat.S_IMODE(mode), "04o"),
            "sha256": digest.hexdigest(),
        })
    return {
        "source": TAG,
        "scan_complete": True,
        "guarded": records,
        "special": _walk_special(root),
    }


def harden(root: Path = Path("/")) -> dict:
    root = Path(root).resolve(strict=True)
    before = inventory(root)
    if set(before["special"]) != set(PRIVILEGED) or any(
        row["mode"] == "0644" for row in before["guarded"]
    ):
        raise ValueError("Unexpected pre-hardening privileged surface")
    for name in GUARDED:
        target = root / name.lstrip("/")
        target.chmod(0o644, follow_symlinks=False)
    after = inventory(root)
    if after["special"] or any(
        row["mode"] != "0644" for row in after["guarded"]
    ) or [
        row["sha256"] for row in before["guarded"]
    ] != [
        row["sha256"] for row in after["guarded"]
    ]:
        raise ValueError("Privileged binary hardening was incomplete")
    return after


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        report = harden() if args.apply else inventory()
    except (OSError, ValueError, TypeError):
        print(json.dumps({"status": "error", "reason": "privilege_inventory_invalid"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
