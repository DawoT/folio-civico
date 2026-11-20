"""Host-supplied, offline negative-control smoke for the non-privileged image.

Runs as UID 65534 with no Linux capabilities, no new privileges, no network,
no mounted documents and a read-only filesystem. Doesn't modify the image.
"""
import errno
import json
import os
import stat
import subprocess

RESTRICTED = (
    "/usr/bin/chage", "/usr/bin/chfn", "/usr/bin/chsh",
    "/usr/bin/expiry", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/newgrp", "/usr/bin/passwd", "/usr/bin/su",
    "/usr/bin/umount", "/usr/sbin/unix_chkpwd",
    "/usr/bin/nsenter", "/usr/bin/unshare", "/usr/bin/setpriv",
)


def main():
    if os.getuid() != 65534 or os.geteuid() != 65534:
        raise RuntimeError("Inspector must run without root identity")
    status = {}
    with open("/proc/self/status", encoding="ascii") as handle:
        for line in handle:
            if line.startswith(("CapEff:", "NoNewPrivs:")):
                key, value = line.split(":", 1)
                status[key] = value.strip()
    if status.get("CapEff") != "0000000000000000" or status.get("NoNewPrivs") != "1":
        raise RuntimeError("Unexpected capabilities or privilege-escalation switch")
    if not (os.statvfs("/").f_flag & os.ST_RDONLY):
        raise RuntimeError("Container root filesystem unexpectedly writable")
    for path in RESTRICTED:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644:
            raise RuntimeError("Forbidden executable permission persists")
    # Invoke --version ONLY after proving all commands are not executable.
    for path in ("/usr/bin/mount", "/usr/bin/umount", "/usr/bin/nsenter",
                 "/usr/bin/unshare", "/usr/bin/setpriv", "/usr/bin/su"):
        try:
            subprocess.run([path, "--version"], timeout=3,
                           capture_output=True, check=False)
        except PermissionError as error:
            if error.errno != errno.EACCES:
                raise
        else:
            raise RuntimeError("Privileged entrypoint was executable")
    print(json.dumps({
        "status": "privileged_entrypoints_denied",
        "uid": os.getuid(),
        "guarded": len(RESTRICTED),
        "suid_sgid_modes": 0,
        "capabilities": "none",
        "no_new_privileges": True,
        "read_only_root": True,
        "release_authorized": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
