"""R1.38: four CVE-specific source guard checks for unsigned util-linux folio2.

No mount/namespace operations, exploitation, package installations, VEX or
release. A missing protection means exit 3, never a security exception.
Present source guards do NOT prove runtime CVE remediation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from util_linux_folio2_binary import SOURCE_VERSION, validate_source

REQUIRED_CVES = (
    "CVE-2026-76642",  # post-mount hooks after failed helper
    "CVE-2026-78408",  # nsenter/unshare descriptor leak
    "CVE-2026-78409",  # detached X-mount.subdir intermediate symlink
    "CVE-2026-78410",  # restricted source pathname race
)
SOURCE_NAMES = (
    "libmount/src/context_mount.c",
    "sys-utils/nsenter.c",
    "sys-utils/unshare.c",
    "libmount/src/context.c",
    "libmount/src/hook_idmap.c",
    "libmount/src/hook_subdir.c",
    "libmount/src/hook_mount.c",
)


def _matches(source: str, expression: str) -> bool:
    return re.search(expression, source, flags=re.MULTILINE | re.DOTALL) is not None


def _protected_subdir_call(sources: dict[str, str]) -> bool:
    for filename in ("libmount/src/hook_subdir.c", "libmount/src/hook_mount.c"):
        source = sources[filename]
        for match in re.finditer(
            r"\bmnt_open_tree\s*\([^;]{0,900}\)\s*;", source,
            flags=re.DOTALL,
        ):
            call = match.group(0)
            if (re.search(r",\s*(?:subdir|api->subdir)\s*,", call)
                    and "RESOLVE_NO_SYMLINKS" in call
                    and "RESOLVE_BENEATH" in call):
                return True
    return False


def check_cve_source_guards(sources: dict[str, str]) -> dict[str, dict]:
    """Inspect explicit defensive branches. Fail closed for missing sources."""
    if set(sources) != set(SOURCE_NAMES):
        raise ValueError("Incomplete source files for CVE matrix")
    if any(not isinstance(value, str) or not value
           for value in sources.values()):
        raise ValueError("CVE source files invalid")

    cm = sources["libmount/src/context_mount.c"]
    ns = sources["sys-utils/nsenter.c"]
    un = sources["sys-utils/unshare.c"]
    cx = sources["libmount/src/context.c"]
    idmap = sources["libmount/src/hook_idmap.c"]
    subdir = sources["libmount/src/hook_subdir.c"]
    mount = sources["libmount/src/hook_mount.c"]

    c76642 = (
        _matches(cm, r"\bis_mount_stage_failed\s*\([^)]*\).*?"
                    r"mnt_context_get_helper_status\(cxt\)\s*!=\s*0")
        and _matches(cm, r"if\s*\(\s*res\s*==\s*0\s*&&\s*"
                         r"!is_mount_stage_failed\(cxt\)\s*\)\s*\{\s*"
                         r"rc\s*=\s*mnt_context_call_hooks\(cxt,\s*"
                         r"MNT_STAGE_MOUNT_POST\)")
    )
    c78408 = (
        _matches(ns, r"open\s*\(\s*fdpath\s*,\s*O_WRONLY\s*\|\s*"
                     r"O_APPEND\s*\|\s*O_CLOEXEC\s*\)")
        and _matches(ns, r"join_into_cgroup\s*\(\s*\)\s*;\s*"
                         r"close\s*\(\s*cgroup_procs_fd\s*\)\s*;\s*"
                         r"cgroup_procs_fd\s*=\s*-1\s*;")
        and _matches(un, r"open\s*\(\s*file\s*,\s*O_WRONLY\s*\|\s*O_CLOEXEC")
        and _matches(un, r"openat\s*\(\s*dirfd\s*,\s*\"register\"\s*,\s*"
                         r"O_WRONLY\s*\|\s*O_CLOEXEC")
    )
    c78410 = (
        _matches(cx, r"mnt_open_tree\s*\(\s*AT_FDCWD\s*,\s*path\s*,\s*"
                     r"oflg\s*,\s*mnt_context_is_restricted\(cxt\)\s*\?\s*"
                     r"RESOLVE_NO_SYMLINKS\s*:\s*0\s*\)")
        and _matches(cx, r"if\s*\(\s*mnt_context_is_restricted\(cxt\)\s*\)"
                         r"\s*\{[\s\S]{0,650}?"
                         r"if\s*\(\s*ul_startswith\(src,\s*\"/dev/\"\)\s*\)")
        and _matches(idmap, r"mnt_open_tree\s*\(\s*AT_FDCWD\s*,\s*"
                           r"target\s*,[\s\S]{0,260}?"
                           r"mnt_context_is_restricted\(cxt\)\s*\?\s*"
                           r"RESOLVE_NO_SYMLINKS\s*:\s*0\s*\)")
    )
    # Require BOTH a safe path opening AND relative subdir resolution. A
    # separate unsafe open_tree() path is still a security regression.
    direct_subdir = any(_matches(doc, (
        r"(?<!mnt_)\bopen_tree\s*\(\s*(?:api->fd_tree|fd)\s*,\s*"
        r"(?:subdir|api->subdir)\s*,"
    )) for doc in (subdir, mount))
    c78409 = (
        _protected_subdir_call(sources)
        and _matches(subdir, r"while\s*\(\s*\*dir\s*==\s*'/'\s*\)\s*"
                             r"dir\+\+\s*;")
        and not direct_subdir
    )
    values = (c76642, c78408, c78409, c78410)
    descriptions = (
        "failed mount helpers cannot trigger MOUNT_POST hooks",
        "cgroup descriptor is CLOEXEC and closed after joining",
        "X-mount.subdir must resolve beneath detached tree without symlinks",
        "restricted bind source requires no-symlink fd resolution",
    )
    return {
        cve: {
            "source_guard_present": bool(present),
            "expected_guard": description,
            "runtime_exploit_regression_executed": False,
        }
        for cve, present, description in zip(
            REQUIRED_CVES, values, descriptions, strict=True
        )
    }


def inspect_versioned_source(root: Path) -> dict:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Unpacked source directory missing")
    sources: dict[str, str] = {}
    for relative in SOURCE_NAMES:
        path = root / relative
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 300000:
            raise ValueError("Source guard evidence file missing or oversized")
        sources[relative] = path.read_text(encoding="utf-8")
    guards = check_cve_source_guards(sources)
    missing = [key for key, value in guards.items()
               if not value["source_guard_present"]]
    return {
        "status": ("source_guards_incomplete_release_blocked" if missing
                   else "all_source_guards_present_runtime_unverified"),
        "source_version": SOURCE_VERSION,
        "cve_guard_results": guards,
        "missing_source_guards": missing,
        "all_source_guards_present": not missing,
        "runtime_cve_regressions_passed": False,
        "cve_remediated": False,
        "debian_trixie_abi_validated": False,
        "runtime_image_replaced": False,
        "vex": "not_issued",
        "release_authorized": False,
        "security_gate": "blocked",
    }


def inspect_pinned_handoff(source: Path) -> dict:
    """Authenticate R1.36 bytes before extracting an unsigned descriptor."""
    if os.geteuid() == 0:
        raise ValueError("Non-root source inspection required")
    admitted = validate_source(source)
    with tempfile.TemporaryDirectory(prefix="folio-r138-cve-", dir="/tmp") as tmp:
        root = Path(tmp)
        tree = root / "source"
        try:
            process = subprocess.run(
                ["dpkg-source", "--no-check", "-x",
                 str(source / f"util-linux_{SOURCE_VERSION}.dsc"), str(tree)],
                cwd=root, text=True, capture_output=True,
                timeout=150, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Versioned source extraction failed") from error
        if process.returncode:
            raise ValueError("Pinned source descriptor extraction failed")
        report = inspect_versioned_source(tree)
        report["source_sha256"] = admitted["source_sha256"]
        report["source_handoff_validated"] = True
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inspect_pinned_handoff(args.source_dir)
    except (ValueError, OSError, UnicodeError, TypeError):
        print(json.dumps({
            "status": "source_cve_evidence_unverified",
            "release_authorized": False, "security_gate": "blocked",
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 2 if report["all_source_guards_present"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
