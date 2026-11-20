"""R1.30: actual kernel/ld-linux/ctypes denial with Python UUID preserved.

Runtime remains UID 65534, read-only, no network/capabilities/new privileges.
No generated citizen document is accessed.
"""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import subprocess
import uuid

TOOLS=(
    "/usr/bin/lscpu","/usr/bin/lsipc","/usr/bin/lslogins",
    "/usr/bin/lsmem","/usr/bin/partx","/usr/bin/prlimit",
    "/usr/bin/wdctl","/usr/sbin/blkdiscard","/usr/sbin/blkid",
    "/usr/sbin/findfs","/usr/sbin/losetup","/usr/sbin/mkswap",
    "/usr/sbin/swaplabel","/usr/sbin/wipefs","/usr/sbin/zramctl",
)
ABSENT_DSOS=(
    "/usr/lib/x86_64-linux-gnu/libblkid.so.1",
    "/usr/lib/x86_64-linux-gnu/libblkid.so.1.1.0",
    "/usr/lib/x86_64-linux-gnu/libsmartcols.so.1",
    "/usr/lib/x86_64-linux-gnu/libsmartcols.so.1.1.0",
)


def main() -> None:
    if os.getuid()!=65534 or os.geteuid()!=65534:
        raise RuntimeError("Unexpected root/native scanner identity")
    flags={}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith(("CapEff:","NoNewPrivs:")):
            key,value=line.split(":",1)
            flags[key]=value.strip()
    if flags.get("CapEff")!="0000000000000000" or flags.get("NoNewPrivs")!="1":
        raise RuntimeError("Inspector Linux privileges not bounded")
    if not (os.statvfs("/").f_flag & os.ST_RDONLY):
        raise RuntimeError("Filesystem unexpectedly writable")
    for p in (*TOOLS,*ABSENT_DSOS):
        if os.path.lexists(p):
            raise RuntimeError("Unnecessary native filesystem code still present")
    loader="/lib64/ld-linux-x86-64.so.2"
    for p in TOOLS:
        try:
            subprocess.run([p,"--version"],capture_output=True,
                           timeout=5,check=False)
        except FileNotFoundError as exc:
            if exc.errno!=errno.ENOENT:
                raise
        else:
            raise RuntimeError("Unused executable still ran")
        result=subprocess.run([loader,p,"--version"],
                              capture_output=True,text=True,
                              timeout=5,check=False)
        if (result.returncode==0 or p not in result.stderr
                or "cannot open" not in result.stderr.lower()):
            raise RuntimeError("ELF-loader bypass unexpectedly succeeded")
    for lib in ("libblkid.so.1","libsmartcols.so.1"):
        try:
            ctypes.CDLL(lib)
        except OSError:
            pass
        else:
            raise RuntimeError("Removed util-linux native ABI still loadable")

    # Preservation is material: Python's _uuid native extension depends on
    # libuuid.so.1. Validate both the dynamic symbol provider and the module.
    native=ctypes.CDLL("libuuid.so.1")
    if native is None:
        raise RuntimeError("Python UUID native ABI was removed")
    import _uuid
    if len(_uuid.generate_time_safe()[0])!=16:
        raise RuntimeError("Python native UUID generation broke")
    if not isinstance(uuid.uuid4(),uuid.UUID):
        raise RuntimeError("Python UUID application functionality broke")
    engines=(
        "/usr/local/bin/clamscan",
        "/opt/folio-poppler/bin/pdfinfo",
        "/opt/folio-ocr/bin/tesseract",
    )
    for path in (*engines,"/usr/local/bin/python3"):
        if not os.path.isfile(path):
            raise RuntimeError("Inspector executable missing")
        run=subprocess.run(["ldd",path],capture_output=True,
                           text=True,check=False,timeout=12)
        if (run.returncode!=0 or "not found" in run.stdout or
                "libblkid.so" in run.stdout or
                "libsmartcols.so" in run.stdout):
            raise RuntimeError("Inspector native dependency broken")
    scan=subprocess.run(["clamscan","--version"],capture_output=True,
                        text=True,check=True,timeout=10)
    if scan.stdout.strip()!="ClamAV 1.5.5":
        raise RuntimeError("Required antivirus engine was affected")
    print(json.dumps({
        "status":"two_utility_dsos_and_unneeded_clients_absent",
        "removed_cli":len(TOOLS),
        "direct_exec_denied":len(TOOLS),
        "loader_denied":len(TOOLS),
        "dynamic_dso_load_denied":2,
        "preserved_libuuid":True,
        "native_uuid_smoked":True,
        "engines_ok":len(engines),
        "uid":os.getuid(),
        "read_only_root":True,
        "no_new_privileges":True,
        "capabilities":"none",
        "release_authorized":False,
    },sort_keys=True))


if __name__=="__main__":
    main()
