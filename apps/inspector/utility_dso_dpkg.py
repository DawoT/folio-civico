"""R1.30: exact missing-file delta across four still-installed Debian packages.

The previous runtime already pruned documentation. Require all historical
missing paths to persist unchanged and only 19 additional known files.
No dpkg 'clean' claim, no CVE suppression, no attempted VEX.
Self-contained for python3 -I -c inside the isolated container.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

TOOLS=(
    "/usr/bin/lscpu","/usr/bin/lsipc","/usr/bin/lslogins",
    "/usr/bin/lsmem","/usr/bin/partx","/usr/bin/prlimit",
    "/usr/bin/wdctl","/usr/sbin/blkdiscard","/usr/sbin/blkid",
    "/usr/sbin/findfs","/usr/sbin/losetup","/usr/sbin/mkswap",
    "/usr/sbin/swaplabel","/usr/sbin/wipefs","/usr/sbin/zramctl",
)
OWNERS={name:"util-linux" for name in TOOLS}
OWNERS["/usr/sbin/losetup"]="mount"
for name in (
    "/usr/lib/x86_64-linux-gnu/libblkid.so.1",
    "/usr/lib/x86_64-linux-gnu/libblkid.so.1.1.0",
): OWNERS[name]="libblkid1"
for name in (
    "/usr/lib/x86_64-linux-gnu/libsmartcols.so.1",
    "/usr/lib/x86_64-linux-gnu/libsmartcols.so.1.1.0",
): OWNERS[name]="libsmartcols1"
PACKAGES=tuple(sorted(set(OWNERS.values())))
SOURCE="folio-utility-dso-dpkg-v1"
VERSION="2.41.5-0+deb13u1"
LINE=re.compile(r"^missing\s+(/\S+)$")


def inventory() -> dict:
    packages={}
    for package in PACKAGES:
        try:
            p=subprocess.run(
                ["dpkg-query","-W","-f="+"$"+"{Version}",package],
                capture_output=True,text=True,timeout=15,check=False,
            )
            d=subprocess.run(["dpkg","-V",package],
                             capture_output=True,text=True,
                             timeout=45,check=False)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ValueError("Unavailable Debian package integrity report") from exc
        if (p.returncode!=0 or p.stdout.strip()!=VERSION or
                d.returncode not in (0,1) or d.stderr.strip()):
            raise ValueError("Debian package version or integrity changed")
        missing=[]
        for row in d.stdout.splitlines():
            match=LINE.fullmatch(row.strip())
            if not match:
                raise ValueError("Unauthorized modified Debian package file")
            missing.append(match.group(1))
        if len(set(missing))!=len(missing):
            raise ValueError("Duplicate missing-file Debian diagnostic")
        packages[package]={"version":VERSION,"missing":sorted(missing)}
    return {"source":SOURCE,"packages":packages}


def compare_delta(before:object,after:object) -> int:
    if (not isinstance(before,dict) or not isinstance(after,dict) or
            before.get("source")!=SOURCE or after.get("source")!=SOURCE):
        raise ValueError("Unexpected Debian inventory provenance")
    a,b=before.get("packages"),after.get("packages")
    if (not isinstance(a,dict) or not isinstance(b,dict) or
            set(a)!=set(PACKAGES) or set(b)!=set(PACKAGES)):
        raise ValueError("Changed Debian package coverage")
    added=[]
    for package in PACKAGES:
        x,y=a[package],b[package]
        if (not isinstance(x,dict) or not isinstance(y,dict) or
                set(x)!={"version","missing"} or
                set(y)!={"version","missing"} or
                x.get("version")!=VERSION or y.get("version")!=VERSION):
            raise ValueError("Debian version mismatch in exact-delta audit")
        old,new=x["missing"],y["missing"]
        for paths in (old,new):
            if (not isinstance(paths,list) or
                    paths!=sorted(set(paths)) or
                    any(not isinstance(k,str) or
                        not LINE.fullmatch("missing "+k) for k in paths)):
                raise ValueError("Malformed Debian missing paths")
        if set(old)-set(new):
            raise ValueError("Historical deleted Debian file reappeared")
        if set(old)&set(OWNERS):
            raise ValueError("Source image was already pruned")
        added.extend((p,package) for p in set(new)-set(old))
    if sorted(added)!=sorted((p,owner) for p,owner in OWNERS.items()):
        raise ValueError("Unexpected new missing file or wrong owning package")
    return len(OWNERS)


def main() -> int:
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--inventory",action="store_true")
    group.add_argument("--compare",action="store_true")
    parser.add_argument("--before",type=Path)
    parser.add_argument("--after",type=Path)
    args=parser.parse_args()
    try:
        if args.inventory:
            result=inventory();status=0
        else:
            if args.before is None or args.after is None:
                raise ValueError("Both immutable image observations required")
            count=compare_delta(
                json.loads(args.before.read_text(encoding="utf-8")),
                json.loads(args.after.read_text(encoding="utf-8")),
            )
            result={"status":"utility_dso_exact_debian_prune_release_blocked",
                    "new_expected_missing_files":count,
                    "release_authorized":False}
            status=2
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        print(json.dumps({"status":"error","reason":"utility_dso_dpkg_evidence_invalid"}))
        return 3
    print(json.dumps(result,sort_keys=True))
    return status


if __name__=="__main__":
    raise SystemExit(main())
