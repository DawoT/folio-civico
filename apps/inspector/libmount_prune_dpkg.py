"""R1.29 read-only Debian file-list differential, without any CVE suppression.

Self-contained for "python3 -I -c" inside immutable Docker images. Old
deliberately-pruned documentation is accepted only when in both snapshots.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess

OWNERS={
    "/usr/bin/findmnt":"util-linux",
    "/usr/bin/lsblk":"util-linux",
    "/usr/bin/lslocks":"util-linux",
    "/usr/bin/lsns":"util-linux",
    "/usr/bin/mountpoint":"util-linux",
    "/usr/sbin/fsck":"util-linux",
    "/usr/sbin/fstrim":"util-linux",
    "/usr/sbin/swapoff":"mount",
    "/usr/sbin/swapon":"mount",
    "/usr/lib/x86_64-linux-gnu/libmount.so.1":"libmount1",
    "/usr/lib/x86_64-linux-gnu/libmount.so.1.1.0":"libmount1",
}
PACKAGES=tuple(sorted(set(OWNERS.values())))
SOURCE="folio-libmount-dpkg-v1"
LINE=re.compile(r"^missing\s+(/\S+)$")


def inventory() -> dict:
    result={}
    for package in PACKAGES:
        try:
            version=subprocess.run(
                ["dpkg-query","-W","-f="+"$"+"{Version}",package],
                capture_output=True,text=True,timeout=15,check=False,
            )
            verify=subprocess.run(
                ["dpkg","-V",package],capture_output=True,
                text=True,timeout=60,check=False,
            )
        except (OSError,subprocess.TimeoutExpired) as err:
            raise ValueError("Missing Debian integrity evidence") from err
        if (version.returncode!=0 or
                version.stdout.strip()!="2.41.5-0+deb13u1" or
                verify.returncode not in (0,1) or verify.stderr.strip()):
            raise ValueError("Unrecognized pinned Debian package or verification")
        missing=[]
        for row in verify.stdout.splitlines():
            match=LINE.fullmatch(row.strip())
            if not match:
                raise ValueError("Changed Debian package bytes or metadata")
            missing.append(match.group(1))
        if len(missing)!=len(set(missing)):
            raise ValueError("Duplicated Debian missing-file report")
        result[package]={"version":version.stdout.strip(),
                         "missing":sorted(missing)}
    return {"source":SOURCE,"packages":result}


def delta(before:dict,after:dict) -> int:
    if (not isinstance(before,dict) or not isinstance(after,dict) or
            before.get("source")!=SOURCE or after.get("source")!=SOURCE):
        raise ValueError("Source/destination Debian reports missing")
    source=before.get("packages")
    target=after.get("packages")
    if (not isinstance(source,dict) or not isinstance(target,dict) or
            set(source)!=set(PACKAGES) or set(target)!=set(PACKAGES)):
        raise ValueError("Debian package coverage changed")
    observed=[]
    for package in PACKAGES:
        a,b=source[package],target[package]
        if (not isinstance(a,dict) or not isinstance(b,dict) or
                set(a)!={"version","missing"} or
                set(b)!={"version","missing"} or
                a.get("version")!="2.41.5-0+deb13u1" or
                b.get("version")!=a["version"]):
            raise ValueError("Package versions were replaced")
        old,new=a["missing"],b["missing"]
        for paths in (old,new):
            if (not isinstance(paths,list) or
                    paths!=sorted(set(paths)) or
                    any(not isinstance(x,str) or
                        not LINE.fullmatch("missing "+x)
                        for x in paths)):
                raise ValueError("Malformed dpkg integrity inventory")
        if set(old)-set(new):
            raise ValueError("Previously missing Debian file reappeared")
        if any(path in OWNERS for path in old):
            raise ValueError("Libmount source was already modified")
        observed.extend((path,package) for path in set(new)-set(old))
    if sorted(observed)!=sorted((p,owner) for p,owner in OWNERS.items()):
        raise ValueError("Unexpected libmount Debian file change")
    return len(OWNERS)


def main() -> int:
    parser=argparse.ArgumentParser()
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--inventory",action="store_true")
    mode.add_argument("--compare",action="store_true")
    parser.add_argument("--before",type=Path)
    parser.add_argument("--after",type=Path)
    args=parser.parse_args()
    try:
        if args.inventory:
            result=inventory();status=0
        else:
            if args.before is None or args.after is None:
                raise ValueError("Both snapshots required")
            count=delta(
                json.loads(args.before.read_text(encoding="utf-8")),
                json.loads(args.after.read_text(encoding="utf-8")),
            )
            result={"status":"libmount_expected_debian_prune_release_blocked",
                    "new_missing_files":count,"release_authorized":False}
            status=2
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        print(json.dumps({"status":"error","reason":"libmount_dpkg_delta_invalid"}))
        return 3
    print(json.dumps(result,sort_keys=True))
    return status


if __name__=="__main__":
    raise SystemExit(main())
