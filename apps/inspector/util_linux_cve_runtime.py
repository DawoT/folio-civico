"""R1.30 read-only, CVE-specific Linux runtime exposure inventory.

Run unprivileged inside the immutable R1.29 Docker image with:
--network none --read-only --cap-drop ALL --security-opt no-new-privileges.
Tests probe concrete known entrypoint prereqs. An absent entrypoint does NOT
constitute a source patch, a complete exploitability assessment, or VEX.

No network requests, writes, intentional mount/syscall attempts, payloads,
installation, package upgrades, or privilege escalation.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import re
import subprocess

SOURCE="folio-util-linux-cve-runtime-v1"
CVES=(
    "CVE-2026-76642",
    "CVE-2026-78408",
    "CVE-2026-78409",
    "CVE-2026-78410",
)
OWNED_PACKAGES={
    "bsdutils":"1:2.41.5-0+deb13u1",
    "libblkid1":"2.41.5-0+deb13u1",
    "liblastlog2-2":"2.41.5-0+deb13u1",
    "libmount1":"2.41.5-0+deb13u1",
    "libsmartcols1":"2.41.5-0+deb13u1",
    "libuuid1":"2.41.5-0+deb13u1",
    "login":"1:4.16.0-2+really2.41.5-0+deb13u1",
    "mount":"2.41.5-0+deb13u1",
    "util-linux":"2.41.5-0+deb13u1",
}
# Paths are deliberately explicit; /bin is usrmerge -> /usr/bin. Nine
# residual libmount consumers were physically removed in R1.29.
REQUIRED_ABSENT=tuple(sorted({
    "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/nsenter", "/usr/bin/unshare",
    "/bin/mount", "/bin/umount", "/bin/nsenter", "/bin/unshare",
    "/usr/lib/x86_64-linux-gnu/libmount.so.1",
    "/usr/lib/x86_64-linux-gnu/libmount.so.1.1.0",
    "/usr/bin/findmnt", "/usr/bin/lsblk", "/usr/bin/lslocks",
    "/usr/bin/lsns", "/usr/bin/mountpoint",
    "/usr/sbin/fsck", "/usr/sbin/fstrim",
    "/usr/sbin/swapoff", "/usr/sbin/swapon",
}))
RUNTIME_KEYS={
    "source","scan_complete","os","os_version","uid","euid",
    "cap_eff","no_new_privileges","read_only_root","network_interfaces",
    "packages","absent_paths","fstab_entries","cgroup_procs_fds",
    "libmount_load_rejected","clamscan_version","status","release_authorized",
}
PACKAGE_VERSION="2.41.5-0+deb13u1"


def _fstab(root:Path) -> list[str]:
    path=root/"etc/fstab"
    if not path.is_file() or path.is_symlink():
        raise ValueError("Missing or untrusted fstab")
    content=path.read_text(encoding="utf-8",errors="strict")
    if len(content)>1024*1024:
        raise ValueError("Unusually large fstab")
    return [line.strip() for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def validate_root_paths(root:Path) -> list[str]:
    root=Path(root).resolve(strict=True)
    for name in REQUIRED_ABSENT:
        if os.path.lexists(root/name.lstrip("/")):
            raise ValueError("Known mount or cgroup join executable/DSO resurfaced")
    # Reject alternate soname copies not protected by the exact package paths.
    for libdir in (
        "usr/lib/x86_64-linux-gnu", "usr/local/lib",
        "lib/x86_64-linux-gnu", "opt",
    ):
        directory=root/libdir
        if not directory.is_dir():
            continue
        # For opt recursively examine library filenames, not full file bytes.
        candidates=(directory.rglob("*libmount.so*")
                    if libdir=="opt" else directory.glob("*libmount.so*"))
        for candidate in candidates:
            if os.path.lexists(candidate):
                raise ValueError("Alternate libmount soname remains available")
    if _fstab(root):
        raise ValueError("Non-comment fstab entries require per-CVE review")
    return list(REQUIRED_ABSENT)


def _process_flags() -> tuple[str,bool]:
    status=Path("/proc/self/status").read_text(encoding="ascii")
    flags={}
    for line in status.splitlines():
        if line.startswith(("CapEff:","NoNewPrivs:")):
            name,value=line.split(":",1)
            flags[name]=value.strip()
    if set(flags)!={"CapEff","NoNewPrivs"}:
        raise ValueError("Incomplete process security flags")
    return flags["CapEff"],flags["NoNewPrivs"]=="1"


def _cgroup_procs_descriptors() -> list[str]:
    matches=[]
    for item in Path("/proc/self/fd").iterdir():
        try:
            target=os.readlink(item)
        except FileNotFoundError:
            # The directory listing fd can close between listing and readlink.
            continue
        if "cgroup.procs" in target:
            matches.append(target)
    return sorted(matches)


def _package_versions() -> dict[str,str]:
    rows={}
    for package in OWNED_PACKAGES:
        try:
            p=subprocess.run(
                ["dpkg-query","-W","-f="+"$"+"{Version}",package],
                capture_output=True,text=True,timeout=12,check=False,
            )
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ValueError("Debian package inventory unavailable") from exc
        if p.returncode!=0 or p.stderr.strip():
            raise ValueError("Debian package missing or query failure")
        rows[package]=p.stdout.strip()
    return rows


def validate_runtime_inventory(value:object) -> dict:
    if not isinstance(value,dict) or set(value)!=RUNTIME_KEYS:
        raise ValueError("Runtime report schema incomplete")
    if (
        value.get("source")!=SOURCE or
        value.get("scan_complete") is not True or
        value.get("os")!="debian" or
        value.get("os_version")!="13.7" or
        value.get("uid")!=65534 or
        value.get("euid")!=65534 or
        value.get("cap_eff")!="0000000000000000" or
        value.get("no_new_privileges") is not True or
        value.get("read_only_root") is not True or
        value.get("network_interfaces")!=["lo"] or
        value.get("packages")!=OWNED_PACKAGES or
        value.get("absent_paths")!=list(REQUIRED_ABSENT) or
        value.get("fstab_entries")!=[] or
        value.get("cgroup_procs_fds")!=[] or
        value.get("libmount_load_rejected") is not True or
        value.get("clamscan_version")!="ClamAV 1.5.5" or
        value.get("status")!="known_entrypoints_absent_package_still_vulnerable" or
        value.get("release_authorized") is not False
    ):
        raise ValueError("Measured util-linux runtime assumptions changed")
    return value


def inventory() -> dict:
    uid=os.getuid()
    euid=os.geteuid()
    cap_eff,no_new_privileges=_process_flags()
    readonly=bool(os.statvfs("/").f_flag & os.ST_RDONLY)
    interfaces=sorted(os.listdir("/sys/class/net"))
    absent=validate_root_paths(Path("/"))
    descriptor_paths=_cgroup_procs_descriptors()

    try:
        ctypes.CDLL("libmount.so.1")
    except OSError:
        dso_denied=True
    else:
        raise ValueError("Unpatched libmount DSO still dynamically accessible")

    os_release=Path("/etc/os-release").read_text(encoding="utf-8")
    if not re.search(r"(?m)^ID=debian$",os_release):
        raise ValueError("Source runtime distribution changed")
    os_version=Path("/etc/debian_version").read_text(
        encoding="ascii",
    ).strip()

    try:
        scan=subprocess.run(
            ["/usr/local/bin/clamscan","--version"],
            capture_output=True,text=True,timeout=12,check=False,
        )
    except (OSError,subprocess.TimeoutExpired) as err:
        raise ValueError("Inspector antivirus not executable") from err
    if scan.returncode or scan.stderr.strip():
        raise ValueError("Scanner functionality changed")

    report={
        "source":SOURCE,"scan_complete":True,"os":"debian",
        "os_version":os_version,"uid":uid,"euid":euid,
        "cap_eff":cap_eff,"no_new_privileges":no_new_privileges,
        "read_only_root":readonly,"network_interfaces":interfaces,
        "packages":_package_versions(),"absent_paths":absent,
        "fstab_entries":[],"cgroup_procs_fds":descriptor_paths,
        "libmount_load_rejected":dso_denied,
        "clamscan_version":scan.stdout.strip(),
        "status":"known_entrypoints_absent_package_still_vulnerable",
        "release_authorized":False,
    }
    return validate_runtime_inventory(report)


def main() -> int:
    try:
        report=inventory()
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):
        print(json.dumps({
            "status":"error","reason":"util_linux_cve_runtime_incomplete",
        }))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
