"""Compare Debian package integrity reports before/after R1.28.

Earlier pruning intentionally removed hundreds of documentation files, so
'dpkg -V clean' would be a false claim. Compare exact *new* missing paths
across five known package owners instead and reject any other difference.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess

# Kept self-contained for python3 -I -c inside immutable Docker images.
# Unit tests assert exact equality with privileged_loader_surface.OWNERS.
OWNERS={
    "/usr/bin/chage":"passwd",
    "/usr/bin/chfn":"passwd",
    "/usr/bin/chsh":"passwd",
    "/usr/bin/expiry":"passwd",
    "/usr/bin/gpasswd":"passwd",
    "/usr/bin/mount":"mount",
    "/usr/bin/newgrp":"login",
    "/usr/bin/nsenter":"util-linux",
    "/usr/bin/passwd":"passwd",
    "/usr/bin/setpriv":"util-linux",
    "/usr/bin/su":"util-linux",
    "/usr/bin/umount":"mount",
    "/usr/bin/unshare":"util-linux",
    "/usr/sbin/unix_chkpwd":"libpam-modules-bin",
}
REMOVE=tuple(sorted(OWNERS))

SOURCE="folio-privileged-loader-dpkg-v1"
PACKAGES=tuple(sorted(set(OWNERS.values())))
LINE=re.compile(r"^missing\s+(/\S+)$")


def inventory() -> dict:
    result={}
    for package in PACKAGES:
        try:
            meta=subprocess.run(
                ["dpkg-query","-W","-f=${Version}",package],
                capture_output=True,text=True,check=False,timeout=15,
            )
            check=subprocess.run(
                ["dpkg","-V",package],capture_output=True,
                text=True,check=False,timeout=60,
            )
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ValueError("Debian provenance inventory unavailable") from exc
        if (meta.returncode or not meta.stdout.strip()
                or check.returncode not in (0,1) or check.stderr.strip()):
            raise ValueError("Debian package verification unexpectedly failed")
        missing=[]
        for line in check.stdout.splitlines():
            match=LINE.fullmatch(line.strip())
            if not match:
                raise ValueError("Unexpected dpkg verification change")
            missing.append(match.group(1))
        if len(missing)!=len(set(missing)):
            raise ValueError("Duplicate missing file diagnostic")
        result[package]={"version":meta.stdout.strip(),"missing":sorted(missing)}
    return {"source":SOURCE,"packages":result}


def compare_missing(before:dict,after:dict) -> int:
    if (not isinstance(before,dict) or not isinstance(after,dict)
            or before.get("source")!=SOURCE or after.get("source")!=SOURCE):
        raise ValueError("Debian reports missing integrity source")
    old=before.get("packages")
    new=after.get("packages")
    if (not isinstance(old,dict) or not isinstance(new,dict)
            or set(old)!=set(PACKAGES) or set(new)!=set(PACKAGES)):
        raise ValueError("Debian security package set changed")
    observed=[]
    for package in PACKAGES:
        before_pkg=old[package]
        after_pkg=new[package]
        if (not isinstance(before_pkg,dict) or not isinstance(after_pkg,dict)
                or set(before_pkg)!={"version","missing"}
                or set(after_pkg)!={"version","missing"}
                or not isinstance(before_pkg["version"],str)
                or not before_pkg["version"]
                or before_pkg["version"] != after_pkg["version"]):
            raise ValueError("Debian package version changed")
        a=before_pkg["missing"]
        b=after_pkg["missing"]
        for data in (a,b):
            if (not isinstance(data,list) or
                    any(not isinstance(p,str) or
                        not LINE.fullmatch("missing "+p)
                        for p in data) or
                    data!=sorted(set(data))):
                raise ValueError("Malformed dpkg missing-file evidence")
        if set(a)-set(b):
            raise ValueError("Previously missing file unexpectedly reappeared")
        if any(p in REMOVE for p in a):
            raise ValueError("Sensitive ELF was already absent from source")
        observed.extend((path,package) for path in set(b)-set(a))
    expected=sorted((path,package) for path,package in OWNERS.items())
    if sorted(observed)!=expected:
        raise ValueError("New dpkg missing files not exactly 14 guarded ELF paths")
    return len(expected)


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
            result=inventory()
            code=0
        else:
            if not args.before or not args.after:
                raise ValueError("Source and target dpkg evidence required")
            amount=compare_missing(
                json.loads(args.before.read_text(encoding="utf-8")),
                json.loads(args.after.read_text(encoding="utf-8")),
            )
            result={"status":"privileged_dpkg_delta_accepted_no_release",
                    "additional_exact_missing_files":amount,
                    "release_authorized":False}
            code=2
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        print(json.dumps({"status":"error",
                          "reason":"privileged_dpkg_delta_invalid"}))
        return 3
    print(json.dumps(result,sort_keys=True))
    return code


if __name__=="__main__":
    raise SystemExit(main())
