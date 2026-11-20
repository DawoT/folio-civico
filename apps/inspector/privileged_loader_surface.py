"""R1.28: physically remove 14 unsafe privileged/namespace ELF entrypoints.

R1.24 chmod 0644 was insufficient: ld-linux can load readable ELF files.
Only a new scratch-flattened filesystem without these files closes this
entrypoint bypass. The Debian packages and their CVEs remain visible.
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

REMOVE = (
    "/usr/bin/chage", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/expiry", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/newgrp", "/usr/bin/nsenter", "/usr/bin/passwd",
    "/usr/bin/setpriv", "/usr/bin/su", "/usr/bin/umount",
    "/usr/bin/unshare", "/usr/sbin/unix_chkpwd",
)
OWNERS = {
    "/usr/bin/chage": "passwd",
    "/usr/bin/chfn": "passwd",
    "/usr/bin/chsh": "passwd",
    "/usr/bin/expiry": "passwd",
    "/usr/bin/gpasswd": "passwd",
    "/usr/bin/mount": "mount",
    "/usr/bin/newgrp": "login",
    "/usr/bin/nsenter": "util-linux",
    "/usr/bin/passwd": "passwd",
    "/usr/bin/setpriv": "util-linux",
    "/usr/bin/su": "util-linux",
    "/usr/bin/umount": "mount",
    "/usr/bin/unshare": "util-linux",
    "/usr/sbin/unix_chkpwd": "libpam-modules-bin",
}
SOURCE = "folio-privileged-loader-presence-v1"
SKIP_ROOTS = {"proc","sys","dev","run","tmp","mnt","media"}
SHA = re.compile(r"^[a-f0-9]{64}$")


def _owners() -> dict[str,str]:
    result={}
    for path in REMOVE:
        try:
            p=subprocess.run(["dpkg-query","-S",path],capture_output=True,
                             text=True,check=False,timeout=10)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ValueError("Cannot verify Debian package ownership") from exc
        if p.returncode or p.stdout.strip() != OWNERS[path] + ": " + path:
            raise ValueError("Expected package owner changed for sensitive executable")
        result[path]=OWNERS[path]
    return result


def _special_bits(root: Path) -> list[str]:
    found=[]
    def reject(e: OSError) -> None:
        raise ValueError("Unable to enumerate rootfs privilege bits") from e
    for directory, dirs, names in os.walk(
        root,topdown=True,followlinks=False,onerror=reject,
    ):
        relative=Path(directory).relative_to(root)
        if relative == Path("."):
            dirs[:]=[name for name in dirs if name not in SKIP_ROOTS]
        for name in names:
            path=Path(directory)/name
            try:info=path.lstat()
            except OSError as e:raise ValueError("Incomplete rootfs privilege inventory") from e
            if stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)&0o6000:
                found.append("/"+str(path.relative_to(root)))
    return sorted(found)


def _sha256(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError("Sensitive executable is not an ELF object")
        stream.seek(0)
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(
    root: Path=Path("/"), *,
    owned: dict[str,str]|None=None,
) -> dict:
    root=Path(root).resolve(strict=True)
    package_map=_owners() if owned is None else dict(owned)
    if package_map != OWNERS:
        raise ValueError("Unrecognized sensitive executable package ownership")
    records=[]
    missing=[]
    for path in REMOVE:
        file=root/path.lstrip("/")
        if not os.path.lexists(file):
            missing.append(path)
            continue
        try:info=file.lstat()
        except OSError as e:raise ValueError("Unreadable executable entrypoint") from e
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or stat.S_IMODE(info.st_mode)!=0o644
                or (root == Path("/") and info.st_uid != 0)):
            raise ValueError("Privileged ELF entrypoint mode or type changed")
        records.append({
            "path":path,"mode":"0644",
            "uid": info.st_uid if root==Path("/") else 0,
            "package":OWNERS[path],
            "sha256":_sha256(file),
        })
    if not missing:
        state="baseline"
    elif missing==list(REMOVE) and not records:
        state="removed"
    else:
        raise ValueError("Partially removed privileged ELF surface")
    special=_special_bits(root)
    if special:
        raise ValueError("Unexpected privileged SUID or SGID files")
    return {
        "source":SOURCE,"state":state,"scan_complete":True,
        "entries":records,"missing":missing,"special":special,
    }


def remove_entrypoints(
    root: Path=Path("/"),*,owned:dict[str,str]|None=None,
) -> dict:
    root=Path(root).resolve(strict=True)
    before=inventory(root,owned=owned)
    if before["state"] != "baseline":
        raise ValueError("Only the pre-audited R1.27 source may be reduced")
    for name in REMOVE:
        (root/name.lstrip("/")).unlink()
    after=inventory(root,owned=owned)
    if after["state"]!="removed" or after["missing"]!=list(REMOVE):
        raise ValueError("One or more sensitive ELF binaries survived")
    return after


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--remove",action="store_true")
    args=parser.parse_args()
    try:
        result=remove_entrypoints() if args.remove else inventory()
    except (OSError,ValueError,TypeError,KeyError):
        print(json.dumps({"status":"error",
                          "reason":"privileged_elf_surface_incomplete"}))
        return 3
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
