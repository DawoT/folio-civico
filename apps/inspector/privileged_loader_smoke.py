"""Real negative control: no direct OR ELF-loader execution for 14 paths.

Runs inside the new runtime with UID 65534, no capabilities/network/new
privileges and a read-only filesystem. No real document is processed here.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import subprocess

TARGETS=(
    "/usr/bin/chage","/usr/bin/chfn","/usr/bin/chsh",
    "/usr/bin/expiry","/usr/bin/gpasswd","/usr/bin/mount",
    "/usr/bin/newgrp","/usr/bin/nsenter","/usr/bin/passwd",
    "/usr/bin/setpriv","/usr/bin/su","/usr/bin/umount",
    "/usr/bin/unshare","/usr/sbin/unix_chkpwd",
)


def main() -> None:
    if (os.geteuid(),os.getuid())!=(65534,65534):
        raise RuntimeError("Privileged inspector process identity")
    flags={}
    with open("/proc/self/status",encoding="ascii") as reader:
        for line in reader:
            if line.startswith(("CapEff:","NoNewPrivs:")):
                key,value=line.split(":",1)
                flags[key]=value.strip()
    if flags.get("CapEff")!="0000000000000000" or flags.get("NoNewPrivs")!="1":
        raise RuntimeError("Unexpected Linux privilege capabilities")
    if not (os.statvfs("/").f_flag & os.ST_RDONLY):
        raise RuntimeError("Root filesystem must be read-only")
    loader="/lib64/ld-linux-x86-64.so.2"
    if not os.path.isfile(loader):
        raise RuntimeError("System ELF dynamic loader unexpectedly missing")

    for executable in TARGETS:
        if os.path.lexists(executable):
            raise RuntimeError("Restricted ELF file still exists in runtime")
        try:
            subprocess.run([executable,"--version"],capture_output=True,
                           timeout=5,check=False)
        except FileNotFoundError as error:
            if error.errno!=errno.ENOENT:
                raise
        else:
            raise RuntimeError("Direct privileged exec was accepted")
        # Explicitly test the R1.24 bypass: ld-linux /usr/bin/mount --version.
        result=subprocess.run(
            [loader,executable,"--version"],
            capture_output=True,text=True,timeout=5,check=False,
        )
        if (result.returncode == 0 or executable not in result.stderr or
                "cannot open" not in result.stderr.lower()):
            raise RuntimeError("ELF-loader attempt unexpectedly succeeded")

    scan=subprocess.run(
        ["/usr/local/bin/clamscan","--version"],
        capture_output=True,text=True,timeout=10,check=True,
    )
    if scan.stdout.strip()!="ClamAV 1.5.5":
        raise RuntimeError("Required ClamAV binary affected by ELF pruning")
    print(json.dumps({
        "status":"privileged_loader_paths_physically_absent",
        "removed":len(TARGETS),
        "direct_exec_denied":len(TARGETS),
        "elf_loader_denied":len(TARGETS),
        "uid":os.getuid(),
        "capabilities":"none","read_only_root":True,
        "no_new_privileges":True,"release_authorized":False,
    },sort_keys=True))


if __name__=="__main__":
    main()
