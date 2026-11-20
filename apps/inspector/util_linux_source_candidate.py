"""R1.32: offline proof of signed util-linux 2.41.6 + CVE-78408 backport.

This prepares an *ephemeral source candidate*, not patched Debian packages or
a runtime image. No untrusted PDF, apt, Docker, release, VEX or deployment.
Successful evidence exits 2 (the inspector release remains blocked). Missing
or inconsistent signatures, sources or code semantics exit 3.

Security: Kernel.org maintainer signature authenticates the UNCOMPRESSED tar,
Kernel.org autosigner authenticates its checksum manifest. The upstream
follow-up commit is HTTPS-fetched and SHA256-pinned; its commit identity is
checked, but the commit PATCH IS NOT independently OpenPGP signed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

VERSION="2.41.6"
CVES=("CVE-2026-76642","CVE-2026-78408",
      "CVE-2026-78409","CVE-2026-78410")
TAR_NAME="util-linux-2.41.6.tar.xz"
TAR_SHA256="e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed"
SIGNER_FINGERPRINT="B0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284"
AUTOSIGNER_FINGERPRINT="B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"
PATCH_COMMIT="485dbb67f1b6bb18e08b1b77f4aa2373ff3a705b"
PATCH_NAME="cve-2026-78408-close-fd.patch"
PATCH_SHA256="0b30248db96c77926ab9ad33474003bb1b13d652368dc754a84ac51ec61f7220"
ORIGINAL_NSENTER_SHA256="9de70a7aaeebc492ee4eaff3597c82d290aa150bd04f1c91b782f19c5348c390"
PATCHED_NSENTER_SHA256="070fb7c5fac3dfcebaff3ae008999fac21bf4d1e5e01ee4dfb0aa225555a2d0c"
ARTIFACT_NAMES=(
    TAR_NAME,"util-linux-2.41.6.tar.sign","sha256sums.asc",
    "karel-zak.asc","kernel-autosigner.asc",PATCH_NAME,
)
REQUIRED_SOURCES=(
    "sys-utils/nsenter.c",
    "sys-utils/unshare.c",
    "libmount/src/context_mount.c",
    "libmount/src/context.c",
    "libmount/src/utils.c",
    "lib/fileutils.c",
)
MAX_SIZE={
    TAR_NAME:11_000_000,
    "util-linux-2.41.6.tar.sign":10_000,
    "sha256sums.asc":30_000,
    "karel-zak.asc":100_000,
    "kernel-autosigner.asc":100_000,
    PATCH_NAME:30_000,
}


def _digest(path:Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda:file.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_digest(message:str) -> str:
    matches=[]
    for row in message.splitlines():
        if TAR_NAME not in row:
            continue
        exact=re.fullmatch(r"([a-f0-9]{64})  "+re.escape(TAR_NAME),row)
        if exact is None:
            raise ValueError("Signed util-linux manifest entry malformed")
        matches.append(exact.group(1))
    if len(matches)!=1 or matches[0]!=TAR_SHA256:
        raise ValueError("Source archive digest or signed manifest entries changed")
    return matches[0]


def _assert_primary_key(colons:str,expected:str) -> str:
    lines=colons.splitlines()
    pubs=[i for i,line in enumerate(lines) if line.startswith("pub:")]
    if len(pubs)!=1:
        raise ValueError("Public key must have exactly one primary certificate")
    index=pubs[0]
    primary=next(
        (line.split(":")[9] for line in lines[index+1:]
         if line.startswith("fpr:")),
        None,
    )
    if primary!=expected:
        raise ValueError("Unpinned maintainer/autosigner OpenPGP fingerprint")
    return primary


def _valid_signature_status(message:str,expected:str) -> bool:
    lines=message.splitlines()
    if any("[GNUPG:] "+name in line for line in lines
           for name in ("BADSIG","ERRSIG","REVKEYSIG","EXPKEYSIG","EXPSIG")):
        return False
    good=any(line.startswith("[GNUPG:] GOODSIG ") for line in lines)
    valid=[
        line.split()[2] for line in lines
        if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split())>=3
    ]
    return good and valid==[expected]


def _patch_identity(message:str,expected_sha256:str) -> None:
    if hashlib.sha256(message.encode("utf-8")).hexdigest()!=expected_sha256:
        raise ValueError("Pinned upstream follow-up patch has changed")
    if not message.startswith("From "+PATCH_COMMIT+" "):
        raise ValueError("CVE-78408 upstream backport commit changed")
    subject=message.split("diff --git ",1)[0]
    if "CVE-2026-78408" not in subject or "nsenter:" not in subject:
        raise ValueError("CVE-78408 patch subject/provenance changed")
    diffs=re.findall(r"(?m)^diff --git a/(\S+) b/(\S+)$",message)
    if diffs!=[("sys-utils/nsenter.c","sys-utils/nsenter.c")]:
        raise ValueError("Upstream patch affects unexpected source files")
    if "close(cgroup_procs_fd);" not in message:
        raise ValueError("CVE-78408 patch missing authority descriptor close")


def _assert_cve_source_semantics(source:dict[str,str]) -> dict[str,list[str]]:
    if set(source)!=set(REQUIRED_SOURCES):
        raise ValueError("Source-level regression coverage changed")
    mount=source["libmount/src/context_mount.c"]
    context=source["libmount/src/context.c"]
    utils=source["libmount/src/utils.c"]
    fileutils=source["lib/fileutils.c"]
    nsenter=source["sys-utils/nsenter.c"]
    unshare=source["sys-utils/unshare.c"]
    checks={
        CVES[0]:(
            "res == 0 && !is_mount_stage_failed(cxt)" in mount
            and "MNT_STAGE_MOUNT_POST" in mount
        ),
        CVES[1]:(
            "static int cgroup_procs_fd = -1;" in nsenter
            and "close(cgroup_fd);" in nsenter
            and "O_APPEND | O_CLOEXEC" in nsenter
            and "O_CLOEXEC" in unshare
            and all(nsenter.count(needle)>=1 for needle in (
                "join_into_cgroup();","close(cgroup_procs_fd);",
                "cgroup_procs_fd = -1;","setgid(gid)","setuid(uid)","execvp(",
            ))
            and nsenter.index("join_into_cgroup();")
                < nsenter.index("close(cgroup_procs_fd);")
                < nsenter.index("setgid(gid)")
                < nsenter.index("setuid(uid)")
                < nsenter.index("execvp(")
        ),
        CVES[2]:(
            "mnt_context_is_restricted(cxt)" in context
            and "RESOLVE_NO_SYMLINKS" in context
            and "ul_openat_resolve" in utils
        ),
        CVES[3]:(
            "ul_openat_resolve" in utils
            and "openat2" in fileutils
            and "RESOLVE_NO_SYMLINKS" in context
        ),
    }
    if any(v is not True for v in checks.values()):
        raise ValueError("One or more known CVE source mitigations was removed")
    return {k:["source_code_patterns_present","archive_signature_verified",
               "manual_patch_review_still_required"] for k in CVES}


def _run(args:list[str],*,cwd:Path|None=None,timeout:int=60) -> subprocess.CompletedProcess:
    try:
        result=subprocess.run(args,cwd=cwd,capture_output=True,text=True,
                              timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ValueError("Source verification tool unavailable/timed out") from exc
    if result.returncode:
        raise ValueError("Source verification command rejected input")
    return result


def _key_import(path:Path,home:Path,expected:str) -> None:
    check=_run(["gpg","--batch","--show-keys","--with-colons",str(path)])
    _assert_primary_key(check.stdout,expected)
    _run(["gpg","--homedir",str(home),"--batch","--import",str(path)])


def _verify_manifest(home:Path,manifest:Path) -> str:
    result=_run(["gpg","--homedir",str(home),"--batch","--status-fd","2",
                 "--decrypt",str(manifest)])
    if not _valid_signature_status(result.stderr,AUTOSIGNER_FINGERPRINT):
        raise ValueError("Kernel.org archive checksum signature not validated")
    return _manifest_digest(result.stdout)


def _verify_tar_signature(home:Path,src:Path,sig:Path) -> None:
    # tar.sign signs the uncompressed tar bytes, not the xz-wrapped archive.
    try:
        unzip=subprocess.Popen(["xz","-dc",str(src)],
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        verify=subprocess.run(
            ["gpg","--homedir",str(home),"--batch","--status-fd","2",
             "--verify",str(sig),"-"],
            stdin=unzip.stdout,capture_output=True,text=True,timeout=90,
        )
        if unzip.stdout is not None:
            unzip.stdout.close()
        unzip_err=unzip.communicate(timeout=25)[1]
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ValueError("Incomplete upstream tar signature verification") from exc
    if (unzip.returncode!=0 or verify.returncode!=0
            or not _valid_signature_status(
                verify.stderr,SIGNER_FINGERPRINT
            )):
        raise ValueError("Maintainer tar signature invalid or decompression incomplete")


def _input_files(directory:Path) -> dict[str,Path]:
    files={}
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("Expected private signed-artifact directory")
    for name in ARTIFACT_NAMES:
        path=directory/name
        if (not path.is_file() or path.is_symlink()
                or path.stat().st_size<80
                or path.stat().st_size>MAX_SIZE[name]):
            raise ValueError("Signed source / patch artifact missing or too large")
        files[name]=path
    if _digest(files[TAR_NAME])!=TAR_SHA256:
        raise ValueError("Source archive digest disagrees with pinned source")
    if _digest(files[PATCH_NAME])!=PATCH_SHA256:
        raise ValueError("CVE-78408 patch byte hash differs from pinned upstream")
    return files


def verify_artifacts(directory:Path) -> dict:
    files=_input_files(directory.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix="folio-ul-proof-",dir="/tmp") as tmp:
        root=Path(tmp)
        home=root/"gnupg"
        home.mkdir(mode=0o700)
        os.chmod(home,0o700)
        _key_import(files["karel-zak.asc"],home,SIGNER_FINGERPRINT)
        _key_import(files["kernel-autosigner.asc"],home,AUTOSIGNER_FINGERPRINT)
        _verify_manifest(home,files["sha256sums.asc"])
        _verify_tar_signature(home,files[TAR_NAME],
                              files["util-linux-2.41.6.tar.sign"])

        patch_bytes=files[PATCH_NAME].read_bytes()
        patch_text=patch_bytes.decode("utf-8",errors="strict")
        _patch_identity(patch_text,PATCH_SHA256)

        source=root/"source"
        source.mkdir()
        # A cryptographically verified vendor tarball is extracted ONLY under
        # a private disposable /tmp directory, with no root ownership/modes.
        listing=_run(["tar","-tJf",str(files[TAR_NAME])],timeout=45).stdout.splitlines()
        prefix="util-linux-"+VERSION+"/"
        if (not listing or any(
            (not name.startswith(prefix)
             or "/../" in name or name.startswith("/"))
            for name in listing
            if name!="util-linux-"+VERSION
        )):
            raise ValueError("Unexpected vendor tarball directory traversal")
        _run(["tar","-xJf",str(files[TAR_NAME]),
              "--directory",str(source),"--strip-components=1",
              "--no-same-owner","--no-same-permissions"],timeout=80)

        nsenter=source/"sys-utils/nsenter.c"
        if _digest(nsenter)!=ORIGINAL_NSENTER_SHA256:
            raise ValueError("Signed pre-patch nsenter.c changed")
        _run(["git","apply","--check","--verbose",str(files[PATCH_NAME])],
             cwd=source,timeout=20)
        _run(["git","apply","--whitespace=error",str(files[PATCH_NAME])],
             cwd=source,timeout=20)
        if _digest(nsenter)!=PATCHED_NSENTER_SHA256:
            raise ValueError("Backport was not applied cleanly and exactly")
        # Prevent hiding any unrelated source modifications by checking only
        # source files selected for the four-CVE inspection.
        audit={
            name:(source/name).read_text(encoding="utf-8",errors="strict")
            for name in REQUIRED_SOURCES
        }
        cve=_assert_cve_source_semantics(audit)
    return {
        "status":"signed_util_linux_2416_plus_78408_backport_candidate_release_blocked",
        "source_version":VERSION,
        "source_sha256":TAR_SHA256,
        "maintainer_signature_fingerprint":SIGNER_FINGERPRINT,
        "kernel_autosigner_fingerprint":AUTOSIGNER_FINGERPRINT,
        "upstream_backport_commit":PATCH_COMMIT,
        "patch_sha256":PATCH_SHA256,
        "patched_nsenter_sha256":PATCHED_NSENTER_SHA256,
        "cve_source_checks":cve,
        "source_authenticity_verified":True,
        "upstream_patch_applies_without_fuzz":True,
        "debian_package_rebuilt":False,
        "debian_trixie_package_patched":False,
        "runtime_image_replaced":False,
        "test_binary_compiled":False,
        "patch_independently_signed":False,
        "cve_status":"open_in_debian_trixie",
        "vex":"not_issued",
        "security_gate":"blocked",
        "release_authorized":False,
    }


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir",required=True,type=Path)
    args=parser.parse_args()
    try:
        result=verify_artifacts(args.artifacts_dir)
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):
        print(json.dumps({"status":"error","reason":"source_candidate_invalid",
                          "release_authorized":False},sort_keys=True))
        return 3
    print(json.dumps(result,sort_keys=True))
    return 2


if __name__=="__main__":
    raise SystemExit(main())
