"""Negative kernel/loader control for physically deleted ClamAV commands.

No 'chmod 0644' security theater: the image must NOT contain the ten
unnecessary files in its final flattened rootfs, so even ld-linux or a shell
cannot read and execute them. Only clamscan remains.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import subprocess

KEEP = "/usr/local/bin/clamscan"
DENY = (
    "/usr/local/bin/clamav-config",
    "/usr/local/bin/clambc",
    "/usr/local/bin/clamconf",
    "/usr/local/bin/clamdscan",
    "/usr/local/bin/clamdtop",
    "/usr/local/bin/clamsubmit",
    "/usr/local/bin/freshclam",
    "/usr/local/bin/sigtool",
    "/usr/local/sbin/clamd",
    "/usr/local/sbin/clamonacc",
)


def main() -> None:
    if os.getuid() != 65534 or os.geteuid() != 65534:
        raise RuntimeError("Unexpected inspector identity")
    status = {}
    with open("/proc/self/status", encoding="ascii") as proc:
        for line in proc:
            if line.startswith(("CapEff:", "NoNewPrivs:")):
                key, value = line.split(":", 1)
                status[key] = value.strip()
    if status.get("CapEff") != "0000000000000000" or status.get("NoNewPrivs") != "1":
        raise RuntimeError("Runtime capabilities or new privileges enabled")
    if not (os.statvfs("/").f_flag & os.ST_RDONLY):
        raise RuntimeError("Runtime root filesystem is writable")
    if stat.S_IMODE(os.stat(KEEP).st_mode) != 0o755:
        raise RuntimeError("Required ClamAV scanner was disabled")

    for binary in DENY:
        if os.path.lexists(binary):
            raise RuntimeError("Unnecessary ClamAV program survived in runtime")
        try:
            subprocess.run([binary, "--version"], capture_output=True,
                           timeout=5, check=False)
        except FileNotFoundError as exc:
            if exc.errno != errno.ENOENT:
                raise
        else:
            raise RuntimeError("Unapproved ClamAV CLI direct exec succeeded")
        # A chmod-only defense fails here: directly invoke the ELF loader.
        # A missing path must be rejected before any program initialization.
        result = subprocess.run(
            ["/lib64/ld-linux-x86-64.so.2", binary, "--version"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode == 0 or binary not in result.stderr or (
            "cannot open" not in result.stderr.lower()
            and "failed to open" not in result.stderr.lower()
        ):
            raise RuntimeError("ELF loader did not confirm missing CLI file")

    version = subprocess.run(
        [KEEP, "--version"], capture_output=True, text=True,
        timeout=10, check=True,
    )
    if version.stdout.strip() != "ClamAV 1.5.5":
        raise RuntimeError("ClamAV scanner became unavailable")
    print(json.dumps({
        "status": "clamav_unnecessary_entrypoints_absent",
        "removed": len(DENY), "retained": "clamscan",
        "loader_bypass_tested": True, "uid": os.getuid(),
        "read_only_root": True, "capabilities": "none",
        "no_new_privileges": True, "release_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
