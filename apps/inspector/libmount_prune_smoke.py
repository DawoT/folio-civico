"""R1.29: kernel, ELF-loader and dynamic-library negative controls.

Runs UID 65534, no capabilities/network/new privileges, read-only.
"""
from __future__ import annotations
import ctypes
import errno
import json
import os
from pathlib import Path
import subprocess

REMOVED_TOOLS=(
    "/usr/bin/findmnt","/usr/bin/lsblk","/usr/bin/lslocks",
    "/usr/bin/lsns","/usr/bin/mountpoint","/usr/sbin/fsck",
    "/usr/sbin/fstrim","/usr/sbin/swapoff","/usr/sbin/swapon",
)
DSO=(
    "/usr/lib/x86_64-linux-gnu/libmount.so.1",
    "/usr/lib/x86_64-linux-gnu/libmount.so.1.1.0",
)

def main() -> None:
    if os.getuid()!=65534 or os.geteuid()!=65534:
        raise RuntimeError("Scanner UID is privileged")
    caps={}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith(("CapEff:","NoNewPrivs:")):
            k,v=line.split(":",1);caps[k]=v.strip()
    if caps.get("CapEff")!="0000000000000000" or caps.get("NoNewPrivs")!="1":
        raise RuntimeError("Unexpected Linux privileges")
    if not (os.statvfs("/").f_flag & os.ST_RDONLY):
        raise RuntimeError("Root filesystem unexpectedly writable")
    loader="/lib64/ld-linux-x86-64.so.2"
    for path in (*REMOVED_TOOLS,*DSO):
        if os.path.lexists(path):
            raise RuntimeError("Removed libmount ELF is still available")
    for executable in REMOVED_TOOLS:
        try:
            subprocess.run([executable,"--version"],capture_output=True,
                           timeout=5,check=False)
        except FileNotFoundError as exc:
            if exc.errno!=errno.ENOENT:
                raise
        else:
            raise RuntimeError("Removed system command still executes")
        result=subprocess.run([loader,executable,"--version"],
                              capture_output=True,text=True,timeout=5,check=False)
        if (result.returncode==0 or executable not in result.stderr or
                "cannot open" not in result.stderr.lower()):
            raise RuntimeError("ELF-loader bypass still works")
    try:
        ctypes.CDLL("libmount.so.1")
    except OSError:
        pass
    else:
        raise RuntimeError("Removed libmount ABI still loadable")
    for executable in (
        "/usr/local/bin/clamscan",
        "/opt/folio-poppler/bin/pdfinfo",
        "/opt/folio-ocr/bin/tesseract",
        "/usr/local/bin/python3",
    ):
        if not Path(executable).exists():
            raise RuntimeError("Inspector engine file missing")
        proc=subprocess.run(["ldd",executable],capture_output=True,
                            text=True,check=False,timeout=12)
        if (proc.returncode!=0 or "not found" in proc.stdout or
                "libmount.so" in proc.stdout):
            raise RuntimeError("Native inspector library missing")
    version=subprocess.run(["clamscan","--version"],capture_output=True,
                           text=True,check=True,timeout=10)
    if version.stdout.strip()!="ClamAV 1.5.5":
        raise RuntimeError("Required scanner changed")
    print(json.dumps({
        "status":"libmount_native_library_and_unused_commands_absent",
        "removed_executable_tools":len(REMOVED_TOOLS),
        "direct_exec_denied":len(REMOVED_TOOLS),
        "elf_loader_denied":len(REMOVED_TOOLS),
        "dynamic_dso_load_denied":True,
        "preserved_engines":3,
        "uid":os.getuid(),"capabilities":"none",
        "read_only_root":True,"no_new_privileges":True,
        "release_authorized":False,
    },sort_keys=True))

if __name__=="__main__":
    main()
