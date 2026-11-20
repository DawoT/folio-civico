"""R1.30: eliminate residual libblkid/libsmartcols and their ELF consumers.

The source is an immutable local R1.29 image. Exactly fifteen unneeded
programs, two compiled DSO objects and two SONAME aliases are removed in a
throwaway builder. A fresh FROM scratch image is independently scanned.

No CVE is declared fixed. This is an exact-file reduction, not an exhaustive
proof against computed dlopen names, JIT code or indirect library loading.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

BLKID_TOOLS=(
    "/usr/bin/partx", "/usr/sbin/blkdiscard", "/usr/sbin/blkid",
    "/usr/sbin/findfs", "/usr/sbin/mkswap", "/usr/sbin/swaplabel",
    "/usr/sbin/wipefs",
)
SMART_TOOLS=(
    "/usr/bin/lscpu", "/usr/bin/lsipc", "/usr/bin/lslogins",
    "/usr/bin/lsmem", "/usr/bin/partx", "/usr/bin/prlimit",
    "/usr/bin/wdctl", "/usr/sbin/losetup", "/usr/sbin/wipefs",
    "/usr/sbin/zramctl",
)
TOOLS=tuple(sorted(set((*BLKID_TOOLS,*SMART_TOOLS))))
DSO={
    "libblkid.so.1":"/usr/lib/x86_64-linux-gnu/libblkid.so.1.1.0",
    "libsmartcols.so.1":"/usr/lib/x86_64-linux-gnu/libsmartcols.so.1.1.0",
}
LINKS={
    "libblkid.so.1":"/usr/lib/x86_64-linux-gnu/libblkid.so.1",
    "libsmartcols.so.1":"/usr/lib/x86_64-linux-gnu/libsmartcols.so.1",
}
REFS={
    "libblkid.so.1":tuple(sorted((*BLKID_TOOLS,DSO["libblkid.so.1"]))),
    "libsmartcols.so.1":tuple(sorted((*SMART_TOOLS,DSO["libsmartcols.so.1"]))),
}
OWNERS={path:"util-linux" for path in TOOLS}
OWNERS["/usr/sbin/losetup"]="mount"
for path in (*DSO.values(),*LINKS.values()):
    OWNERS[path]="libblkid1" if "blkid" in path else "libsmartcols1"
KEEP_UUID=(
    "/usr/lib/x86_64-linux-gnu/libuuid.so.1.3.0",
    "/usr/local/lib/python3.12/lib-dynload/_uuid.cpython-312-x86_64-linux-gnu.so",
)
ALL=tuple(sorted(OWNERS))
SOURCE="folio-utility-dso-reduction-v1"


def _owners() -> dict[str,str]:
    observed={}
    for name in ALL:
        try:
            result=subprocess.run(["dpkg-query","-S",name],capture_output=True,
                                  text=True,check=False,timeout=10)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ValueError("Debian binary ownership unavailable") from exc
        rows=result.stdout.strip().splitlines()
        if result.returncode or len(rows)!=1 or ": " not in rows[0]:
            raise ValueError("Unexpected Debian package owner count")
        pkg, entry=rows[0].split(": ",1)
        pkg=pkg.split(":",1)[0]
        if entry!=name or pkg!=OWNERS[name]:
            raise ValueError("Untrusted util-linux package file ownership")
        observed[name]=pkg
    return observed


def _hash(path:Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        if stream.read(4)!=b"\x7fELF":
            raise ValueError("Expected ELF is no longer an ELF file")
        stream.seek(0)
        for chunk in iter(lambda: stream.read(1024*1024),b""):
            digest.update(chunk)
    return digest.hexdigest()


def _elf_refs(root:Path) -> dict[str,list[str]]:
    if root==Path("/"):
        for name,target in (("/bin","/usr/bin"),("/lib","/usr/lib"),
                            ("/sbin","/usr/sbin")):
            if os.path.realpath(name)!=target:
                raise ValueError("Non-Debian usrmerge root layout")
    hits={name:[] for name in REFS}
    for prefix in ("usr","opt"):
        directory=root/prefix
        if not directory.exists():
            continue
        def fail(error:OSError) -> None:
            raise ValueError("Incomplete ELF filesystem traversal") from error
        for folder,_,filenames in os.walk(directory,followlinks=False,onerror=fail):
            for filename in filenames:
                path=Path(folder)/filename
                try:
                    info=path.lstat()
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    with path.open("rb") as stream:
                        if stream.read(4)!=b"\x7fELF":
                            continue
                        stream.seek(0)
                        body=stream.read()
                    for soname in REFS:
                        if soname.encode("ascii") in body:
                            hits[soname].append("/"+str(path.relative_to(root)))
                except OSError as exc:
                    raise ValueError("Unreadable ELF; cannot assess native code") from exc
    return {name:sorted(paths) for name,paths in hits.items()}


def _uuid(root:Path) -> list[dict[str,str]]:
    files=[]
    for name in KEEP_UUID:
        path=root/name.lstrip("/")
        info=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or (root==Path("/") and info.st_uid!=0)):
            raise ValueError("Required libuuid/Python UUID extension changed")
        files.append({"path":name,"sha256":_hash(path)})
    return files


def inventory(root:Path=Path("/"),*,owned:dict[str,str]|None=None) -> dict:
    root=Path(root).resolve(strict=True)
    if (dict(owned) if owned is not None else _owners())!=OWNERS:
        raise ValueError("Unrecognized four util-linux Debian package owners")
    entries=[]
    absent=[]
    for name in ALL:
        path=root/name.lstrip("/")
        if not os.path.lexists(path):
            absent.append(name)
            continue
        info=path.lstat()
        if name in LINKS.values():
            expected=name.split("/")[-1]+".1.0"
            if not stat.S_ISLNK(info.st_mode) or os.readlink(path)!=expected:
                raise ValueError("Untrusted DSO ABI symlink")
            entries.append({"path":name,"package":OWNERS[name],
                            "kind":"symlink","target":expected})
        else:
            mode="0644" if name in DSO.values() else "0755"
            if (not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode)!=int(mode,8)
                    or (root==Path("/") and info.st_uid!=0)):
                raise ValueError("Unexpected native utility file mode/owner")
            entries.append({"path":name,"package":OWNERS[name],
                            "kind":"elf","mode":mode,"sha256":_hash(path)})
    refs=_elf_refs(root)
    if not absent:
        state="baseline"
        if refs!={name:list(paths) for name,paths in REFS.items()}:
            raise ValueError("Unrecognized ELF reverse dependency on utility DSO")
    elif absent==list(ALL) and not entries:
        state="pruned"
        if any(refs.values()):
            raise ValueError("Retained executable still refers to pruned DSO")
    else:
        raise ValueError("Partial/unsafe native libblkid/libsmartcols removal")
    return {"source":SOURCE,"state":state,"scan_complete":True,
            "entries":entries,"missing":absent,"references":refs,
            "retained_uuid":_uuid(root)}


def remove_unneeded_utilities(root:Path=Path("/"),*,owned:dict[str,str]|None=None) -> dict:
    root=Path(root).resolve(strict=True)
    before=inventory(root,owned=owned)
    if before["state"]!="baseline":
        raise ValueError("Unexpected premodified source utility filesystem")
    for name in ALL:
        (root/name.lstrip("/")).unlink()
    after=inventory(root,owned=owned)
    if after["state"]!="pruned" or before["retained_uuid"]!=after["retained_uuid"]:
        raise ValueError("Unexpected changes to retained Python UUID dependency")
    return after


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--remove",action="store_true")
    args=parser.parse_args()
    try:
        report=remove_unneeded_utilities() if args.remove else inventory()
    except (OSError,ValueError,TypeError,KeyError):
        print(json.dumps({"status":"error","reason":"residual_utility_elf_proof_incomplete"}))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
