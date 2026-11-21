"""R1.48: complete read-only filesystem identity for a local research container.

Read under a disposable isolated container; hashes only, never exports file
contents. Excludes Docker-injected /etc host files and pseudo filesystems.
Any unreadable regular file invalidates the evidence (no silent blind spot).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

EXCLUDED_TOP_LEVEL = frozenset(("/dev", "/proc", "/sys", "/tmp", "/run"))
DOCKER_INJECTED = frozenset((
    "/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
))


def snapshot(root: Path = Path("/")) -> dict:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Filesystem root is not a real directory")
    records: dict[str, dict] = {}

    def add(path: Path) -> None:
        suffix = path.relative_to(root).as_posix()
        relative = "/" if suffix == "." else "/" + suffix
        if relative in DOCKER_INJECTED or relative in EXCLUDED_TOP_LEVEL:
            return
        info = path.lstat()
        mode = oct(stat.S_IMODE(info.st_mode))
        if stat.S_ISLNK(info.st_mode):
            row = {"kind": "symlink", "mode": mode,
                   "target": os.readlink(path)}
        elif stat.S_ISDIR(info.st_mode):
            row = {"kind": "directory", "mode": mode}
        elif stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            row = {"kind": "file", "mode": mode, "sha256": digest.hexdigest()}
        else:
            raise ValueError("Unexpected special file in immutable root: " + relative)
        if relative in records:
            raise ValueError("Duplicated root filesystem path")
        records[relative] = row

    add(root)
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if current_path == root:
            dirs[:] = [d for d in dirs if ("/" + d) not in EXCLUDED_TOP_LEVEL]
        for d in sorted(dirs):
            path = current_path / d
            # os.walk does not recurse through directory symlinks, but they
            # still need to be accounted for as one inode.
            add(path)
        for f in sorted(files):
            add(current_path / f)
    return {
        "schema": "folio-r148-complete-runtime-filesystem-v1",
        "excluded_top_level": sorted(EXCLUDED_TOP_LEVEL),
        "excluded_docker_injected": sorted(DOCKER_INJECTED),
        "paths": records,
    }


if __name__ == "__main__":
    try:
        print(json.dumps(snapshot(), sort_keys=True))
    except (OSError, ValueError) as err:
        print(json.dumps({"status": "error", "reason": type(err).__name__}))
        raise SystemExit(3) from err
