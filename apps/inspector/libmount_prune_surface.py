"""R1.29 fail-closed libmount runtime reduction, never a util-linux CVE waiver.

The sole libmount ELF is referenced by nine residual filesystem-admin tools.
The inspector does not call them. Remove both DSO paths and all nine consumers
from a disposable builder, then COPY into a FROM scratch runtime.

The check conservatively scans every retained regular ELF in /usr and /opt
for the byte string "libmount.so.1". It does NOT establish dynamic reachability
against constructed/obfuscated dlopen calls or resolve all security CVEs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

TOOL_PATHS=(
    "/usr/bin/findmnt",
    "/usr/bin/lsblk",
    "/usr/bin/lslocks",
    "/usr/bin/lsns",
    "/usr/bin/mountpoint",
    "/usr/sbin/fsck",
    "/usr/sbin/fstrim",
    "/usr/sbin/swapoff",
    "/usr/sbin/swapon",
)
DSO_LINK="/usr/lib/x86_64-linux-gnu/libmount.so.1"
DSO_FILE="/usr/lib/x86_64-linux-gnu/libmount.so.1.1.0"
OWNERS={**{p:"util-linux" for p in TOOL_PATHS},
        DSO_LINK:"libmount1",DSO_FILE:"libmount1"}
for _path in ("/usr/sbin/swapon","/usr/sbin/swapoff"):
    OWNERS[_path]="mount"
ALL=tuple(sorted(OWNERS))
REFS=tuple(sorted((*TOOL_PATHS,DSO_FILE)))
SOURCE="folio-libmount-prune-v1"
SONAME=b"libmount.so.1"


def _owners() -> dict[str,str]:
    owners={}
    for path in ALL:
        try:
            p=subprocess.run(["dpkg-query","-S",path],capture_output=True,
                             text=True,check=False,timeout=10)
        except (OSError,subprocess.TimeoutExpired) as e:
            raise ValueError("Cannot verify libmount Debian owner") from e
        rows=p.stdout.strip().splitlines()
        if p.returncode or len(rows)!=1 or ": " not in rows[0]:
            raise ValueError("Ambiguous dpkg ownership for libmount payload")
        rawowner,entry=rows[0].split(": ",1)
        package=rawowner.split(":")[0]
        if entry!=path or package!=OWNERS[path]:
            raise ValueError("Unexpected Debian ownership for libmount ELF")
        owners[path]=package
    return owners


def _sha(path:Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as stream:
        if stream.read(4)!=b"\x7fELF":
            raise ValueError("Expected ELF binary was changed")
        stream.seek(0)
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def _elf_references(root:Path) -> list[str]:
    """Conservative full /usr+/opt ELF scan; reject unreadable members.

    /bin, /lib and /sbin are usrmerge symlinks to these same inodes in
    the real Debian image. This is validated before scanning the runtime.
    """
    if root == Path("/"):
        for alias,target in (("/bin","usr/bin"),("/lib","usr/lib"),
                             ("/sbin","usr/sbin")):
            if os.path.realpath(alias)!="/"+target:
                raise ValueError("Unexpected Debian usrmerge root layout")
    hits=[]
    for top in ("usr","opt"):
        directory=root/top
        if not directory.exists():
            continue
        def fail(error:OSError) -> None:
            raise ValueError("Incomplete ELF dependency scan") from error
        for folder,dirs,names in os.walk(
            directory,topdown=True,followlinks=False,onerror=fail,
        ):
            for name in names:
                path=Path(folder)/name
                try:
                    info=path.lstat()
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    with path.open("rb") as stream:
                        if stream.read(4)!=b"\x7fELF":
                            continue
                        # Conservative substring detection includes DT_NEEDED
                        # and explicit dlopen strings, not just dynamic imports.
                        stream.seek(0)
                        if SONAME in stream.read():
                            hits.append("/"+str(path.relative_to(root)))
                except OSError as e:
                    raise ValueError("Unreadable ELF image file") from e
    return sorted(hits)


def inventory(root:Path=Path("/"),*,owned:dict[str,str]|None=None) -> dict:
    root=Path(root).resolve(strict=True)
    if (dict(owned) if owned is not None else _owners())!=OWNERS:
        raise ValueError("Expected util-linux/mount/libmount ownership changed")
    entries=[]
    missing=[]
    for name in ALL:
        path=root/name.lstrip("/")
        if not os.path.lexists(path):
            missing.append(name)
            continue
        info=path.lstat()
        if name==DSO_LINK:
            if not stat.S_ISLNK(info.st_mode):
                raise ValueError("libmount ABI SONAME is not a symlink")
            target=os.readlink(path)
            if target!="libmount.so.1.1.0":
                raise ValueError("Untrusted libmount SONAME alias")
            entries.append({"path":name,"package":OWNERS[name],
                            "kind":"symlink","target":target})
            continue
        expected=0o644 if name==DSO_FILE else 0o755
        if (not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode)!=expected
                or (root==Path("/") and info.st_uid!=0)):
            raise ValueError("Unexpected libmount ELF owner or mode")
        entries.append({"path":name,"package":OWNERS[name],
                        "kind":"elf","mode":format(expected,"04o"),
                        "sha256":_sha(path)})
    refs=_elf_references(root)
    if not missing:
        state="baseline"
        if refs!=list(REFS):
            raise ValueError("Unexpected libmount reverse ELF consumer")
    elif missing==list(ALL) and not entries:
        state="removed"
        if refs:
            raise ValueError("Surviving ELF still references removed libmount")
    else:
        raise ValueError("Incomplete/ambiguous libmount runtime reduction")
    return {"source":SOURCE,"state":state,"scan_complete":True,
            "entries":entries,"missing":missing,"elf_references":refs}


def remove_libmount_surface(root:Path=Path("/"),*,owned:dict[str,str]|None=None) -> dict:
    root=Path(root).resolve(strict=True)
    before=inventory(root,owned=owned)
    if before["state"]!="baseline":
        raise ValueError("Source libmount was already changed")
    # Only fixed regular package-owned paths and a fixed verified symlink.
    for name in ALL:
        (root/name.lstrip("/")).unlink()
    after=inventory(root,owned=owned)
    if after["state"]!="removed" or after["elf_references"]:
        raise ValueError("An unsafe libmount reference survived")
    return after


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove",action="store_true")
    args=parser.parse_args()
    try:
        result=remove_libmount_surface() if args.remove else inventory()
    except (OSError,ValueError,TypeError,KeyError):
        print(json.dumps({"status":"error",
                          "reason":"libmount_full_elf_inventory_incomplete"}))
        return 3
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
