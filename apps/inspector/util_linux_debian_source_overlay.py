"""R1.33: signed Trixie Debian packaging roundtrip using 2.41.6 + CVE backport.

OFFLINE, unprivileged, source-only, ephemeral. NOT Debian-maintained, signed,
built as binaries, installed, published, VEXed, or authorized for release.
Valid evidence exits 2 (blocked); any break/incompleteness exits 3.

Two Debian Trixie patches are ALREADY upstream in 2.41.6. Applying those
again can accidentally REVERSE their fixes if a patch tool auto-detects
reverse direction. Require git-apply reverse-check SUCCESS and forward-check
FAILURE on the pristine, vendor-signed new source, then omit exactly these.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from util_linux_source_candidate import (
    VERSION, TAR_NAME, TAR_SHA256, PATCH_NAME, PATCH_SHA256,
    PATCHED_NSENTER_SHA256, REQUIRED_SOURCES,
    _assert_primary_key, _valid_signature_status, _assert_cve_source_semantics,
    verify_artifacts,
)

DEBIAN_VERSION="2.41.5-0+deb13u1"
EXPERIMENT_VERSION="2.41.6-0+folio1~deb13u1"
SOURCE_DATE_EPOCH=1795190400  # 2026-11-20 16:00:00 UTC; changelog date
DEBIAN_DSC_NAME="util-linux_2.41.5-0+deb13u1.dsc"
DEBIAN_DSC_SHA256="43e9b2cbebd10fdc598c4ad10217c8202c28de53af6eafc892c8e9b5cbf3a3a5"
DEBIAN_SIGNER_FINGERPRINT="7D1ACFFAD9E0806C9C4CD3925C13D6DB93052E03"
DEBIAN_SOURCE_FILES={
    "util-linux_2.41.5.orig.tar.xz":
        ("f586e35d320ff537aab3ffeca37e9ecd482ccbe013590db4429a414d8aa6a728",9474992),
    "util-linux_2.41.5-0+deb13u1.debian.tar.xz":
        ("5b327ccd22f0f4ed28a389870aa51d04ecedb8693e52a1d122850f2b3188cbf6",107604),
}
DEBIAN_SOURCE_MD5={
    "util-linux_2.41.5.orig.tar.xz":"c21a3cb29f510f019ac3da929819ffbf",
    "util-linux_2.41.5-0+deb13u1.debian.tar.xz":"5265eba63ec6002d90959e435dedbac7",
}
RETAINED_DEBIAN_PATCHES=(
    "debian/man-getopt-examples.patch",
    "debian/verbose-tests.patch",
    "debian/hardlink-tests-known-failed.patch",
    "debian/lsfd-usrbin.patch",
    "debian/sensible-pager.patch",
    "debian/login-support-LOG_OK_LOGINS.patch",
    "debian/login-do-not-print-motd-done-by-PAM.patch",
    "debian/login-turn-off-btmp-utmp-lastlog-writing.patch",
    "debian/salsa-ci-skip-tests.patch",
)
UPSTREAM_PATCH_SERIES=(
    "upstream/loopdev-use-openat2-RESOLVE_NO_SYMLINKS-for-backing-file.patch",
    "upstream/libmount-restrict-source-path-canonicalization-for-non-ro.patch",
)
CVE_FOLLOWUP_NAME="upstream/CVE-2026-78408-followup.patch"
DEBIAN_KEY_NAME="debian-maintainer.asc"
ARTIFACT_NAMES=(DEBIAN_DSC_NAME,*DEBIAN_SOURCE_FILES,DEBIAN_KEY_NAME)
EXPECTED_OVERLAY_SERIES=(*RETAINED_DEBIAN_PATCHES,CVE_FOLLOWUP_NAME)
PINNED_DSC_FIELDS={
    "Format":"3.0 (quilt)",
    "Source":"util-linux",
    "Version":DEBIAN_VERSION,
    "Maintainer":"Chris Hofstaedtler <zeha@debian.org>",
}


def _hash(path:Path,algorithm:str="sha256")->str:
    h=hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def _section(content:str,label:str)->list[str]:
    lines=content.splitlines()
    starts=[i for i,line in enumerate(lines) if line==label+":"]
    if len(starts)!=1:
        raise ValueError("Signed Debian manifest missing or duplicated")
    collected=[]
    for line in lines[starts[0]+1:]:
        if not line.startswith((" ","\t")):
            break
        collected.append(line.strip())
    return collected


def _debian_signed_manifest(content:str)->dict[str,tuple[str,int]]:
    fields={}
    for line in content.splitlines():
        match=re.fullmatch(r"([A-Za-z-]+): (.+)",line)
        if match and match.group(1) in PINNED_DSC_FIELDS:
            if match.group(1) in fields:
                raise ValueError("Duplicated Debian source metadata")
            fields[match.group(1)]=match.group(2)
    if fields!=PINNED_DSC_FIELDS:
        raise ValueError("Unexpected Debian source package identity/version")
    sha={}
    for row in _section(content,"Checksums-Sha256"):
        match=re.fullmatch(r"([a-f0-9]{64}) ([0-9]+) (\S+)",row)
        if match is None:
            raise ValueError("Malformed Debian source SHA manifest")
        name=match.group(3)
        if name in sha:
            raise ValueError("Duplicate SHA256 source payload")
        sha[name]=(match.group(1),int(match.group(2)))
    if sha!=DEBIAN_SOURCE_FILES:
        raise ValueError("Signed Debian source bytes/size or coverage changed")
    md5={}
    for row in _section(content,"Files"):
        match=re.fullmatch(r"([a-f0-9]{32}) ([0-9]+) (\S+)",row)
        if match is None or match.group(3) in md5:
            raise ValueError("Malformed/duplicated Debian MD5 source files")
        md5[match.group(3)]=(match.group(1),int(match.group(2)))
    expected={
        name:(digest,DEBIAN_SOURCE_FILES[name][1])
        for name,digest in DEBIAN_SOURCE_MD5.items()
    }
    if md5!=expected:
        raise ValueError("Inconsistent Debian signed source inventory")
    return sha


def _expected_overlay_series(original:list[str])->list[str]:
    if original!=list((*RETAINED_DEBIAN_PATCHES,*UPSTREAM_PATCH_SERIES)):
        raise ValueError("Debian patch series changed or re-ordered")
    return list(EXPECTED_OVERLAY_SERIES)


def _local_changelog(original:str)->str:
    if not original.startswith(
        "util-linux ("+DEBIAN_VERSION+") trixie-security;"
    ):
        raise ValueError("Expected Trixie source changelog changed")
    return (
        "util-linux ("+EXPERIMENT_VERSION+") UNRELEASED; urgency=low\n\n"
        "  * LOCAL RESEARCH ONLY. NOT AN OFFICIAL DEBIAN PACKAGE.\n"
        "  * Verify vendor-signed util-linux 2.41.6 + Trixie source packaging.\n"
        "  * Drop two upstream-applied patches and add CVE-2026-78408 FD close.\n\n"
        " -- Folio Civico Local Lab <noreply@invalid>  "
        "Fri, 20 Nov 2026 11:00:00 -0500\n\n"
        +original
    )


def _check_duplicate_upstream_patches(
    paths:list[Path],checker
)->None:
    if len(paths)!=len(UPSTREAM_PATCH_SERIES):
        raise ValueError("Missing Debian patches already upstream")
    for path in paths:
        if checker(path,False)==0:
            raise ValueError("Debian patch unexpectedly applies forward")
        if checker(path,True)!=0:
            raise ValueError("Debian patch is not already upstream")
    # Never invoke patch --batch, which can auto-REVERSE a patch!


def _normalize_debian_mtimes(debian:Path)->None:
    """Normalize only the disposable Debian packaging tree for reproducibility."""
    if not debian.is_dir() or debian.is_symlink():
        raise ValueError("Unexpected Debian overlay root")
    # Keep the signed upstream tarball untouched.
    for path in (*debian.rglob("*"),debian):
        os.utime(path,(SOURCE_DATE_EPOCH,SOURCE_DATE_EPOCH),
                 follow_symlinks=False)


def _assert_roundtrip_tree(root:Path)->dict:
    series=root/"debian/patches/series"
    if (not series.is_file() or series.is_symlink() or
            series.read_text(encoding="utf-8").splitlines()
            !=list(EXPECTED_OVERLAY_SERIES)):
        raise ValueError("Source package lost exact safe Debian patch series")
    changelog=root/"debian/changelog"
    if (not changelog.is_file() or changelog.is_symlink() or
            not changelog.read_text(encoding="utf-8").startswith(
                "util-linux ("+EXPERIMENT_VERSION+") UNRELEASED;")):
        raise ValueError("Experimental Debian source impersonates official release")
    nsenter=root/"sys-utils/nsenter.c"
    if not nsenter.is_file() or nsenter.is_symlink() or _hash(nsenter)!=PATCHED_NSENTER_SHA256:
        raise ValueError("CVE-78408 patch missing from Debian source roundtrip")
    source={}
    for path in REQUIRED_SOURCES:
        file=root/path
        if not file.is_file() or file.is_symlink():
            raise ValueError("CVE coverage source file missing")
        source[path]=file.read_text(encoding="utf-8",errors="strict")
    return _assert_cve_source_semantics(source)


def _run(argv:list[str],*,cwd:Path|None=None,timeout:int=95)->subprocess.CompletedProcess:
    try:
        p=subprocess.run(argv,cwd=cwd,capture_output=True,text=True,
                         timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as err:
        raise ValueError("Debian signed-source proof command failed") from err
    if p.returncode!=0:
        raise ValueError("Debian signed-source proof command rejected input")
    return p


def _validate_debian_signature(root:Path,work:Path) -> dict:
    home=work/"gnupg"
    home.mkdir(mode=0o700)
    os.chmod(home,0o700)
    key=root/DEBIAN_KEY_NAME
    colons=_run(["gpg","--batch","--show-keys","--with-colons",str(key)])
    _assert_primary_key(colons.stdout,DEBIAN_SIGNER_FINGERPRINT)
    _run(["gpg","--homedir",str(home),"--batch","--import",str(key)])
    verified=_run([
        "gpg","--homedir",str(home),"--batch","--status-fd","2",
        "--decrypt",str(root/DEBIAN_DSC_NAME),
    ])
    if not _valid_signature_status(
        verified.stderr,DEBIAN_SIGNER_FINGERPRINT
    ):
        raise ValueError("Debian Trixie source descriptor not signed by pinned maintainer")
    _debian_signed_manifest(verified.stdout)
    return {"debian_dsc_signed":True,
            "debian_source_version":DEBIAN_VERSION,
            "debian_signer_fingerprint":DEBIAN_SIGNER_FINGERPRINT}


def verify_debian_source_overlay(artifacts:Path)->dict:
    if os.geteuid()==0:
        raise ValueError("Unprivileged source-only verification required")
    artifacts=artifacts.resolve(strict=True)
    if not artifacts.is_dir() or artifacts.is_symlink():
        raise ValueError("Signed source artifacts directory missing")
    for name in ARTIFACT_NAMES:
        file=artifacts/name
        if not file.is_file() or file.is_symlink():
            raise ValueError("Signed Debian source input missing")
        maxbytes=250000 if name==DEBIAN_KEY_NAME else (
            10000 if name==DEBIAN_DSC_NAME else 11000000
        )
        if file.stat().st_size<100 or file.stat().st_size>maxbytes:
            raise ValueError("Oversized or truncated source artifact")
    if _hash(artifacts/DEBIAN_DSC_NAME)!=DEBIAN_DSC_SHA256:
        raise ValueError("Unpinned Debian source descriptor")
    for name,(digest,size) in DEBIAN_SOURCE_FILES.items():
        file=artifacts/name
        if file.stat().st_size!=size or _hash(file)!=digest:
            raise ValueError("Debian source archive checksum/size changed")

    # Independent R1.32 checks on maintainer-signed upstream 2.41.6,
    # kernel.org-signed checksum manifest, and SHA-pinned CVE follow-up.
    source_result=verify_artifacts(artifacts)
    if (not source_result.get("source_authenticity_verified") or
            source_result.get("patch_sha256")!=PATCH_SHA256 or
            source_result.get("release_authorized") is not False):
        raise ValueError("Upstream signed candidate failed")

    with tempfile.TemporaryDirectory(prefix="folio-ul-trixie-overlay-",dir="/tmp") as temp:
        work=Path(temp)
        signed=_validate_debian_signature(artifacts,work)
        current=work/"trixie"
        _run(["dpkg-source","--no-check","-x",
              str(artifacts/DEBIAN_DSC_NAME),str(current)],timeout=90)
        series=current/"debian/patches/series"
        original_series=series.read_text(encoding="utf-8").splitlines()
        new_series=_expected_overlay_series(original_series)

        source=work/"overlay"
        source.mkdir()
        # Recheck the vendor source archive is the pinned signed tar.
        if _hash(artifacts/TAR_NAME)!=TAR_SHA256:
            raise ValueError("Vendor source changed after signature verification")
        _run(["tar","-xJf",str(artifacts/TAR_NAME),
              "-C",str(source),"--strip-components=1",
              "--no-same-owner","--no-same-permissions"],timeout=90)

        def probe_duplicate(path:Path,reverse:bool)->int:
            command=["git","apply","--check",
                     *(["--reverse"] if reverse else []),str(path)]
            try:
                p=subprocess.run(
                    command,cwd=source,capture_output=True,text=True,timeout=22
                )
            except (OSError,subprocess.TimeoutExpired) as err:
                raise ValueError("Cannot classify duplicated security patches") from err
            return p.returncode

        _check_duplicate_upstream_patches([
            current/"debian/patches"/path for path in UPSTREAM_PATCH_SERIES
        ],probe_duplicate)

        shutil.copytree(current/"debian",source/"debian")
        overlay_series=source/"debian/patches/series"
        overlay_series.write_text("\n".join(new_series)+"\n",encoding="utf-8")
        patch=source/"debian/patches"/CVE_FOLLOWUP_NAME
        patch.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(artifacts/PATCH_NAME,patch)
        if _hash(patch)!=PATCH_SHA256:
            raise ValueError("The followup cgroup FD patch was changed")
        changelog=source/"debian/changelog"
        changelog.write_text(
            _local_changelog(changelog.read_text(encoding="utf-8")),
            encoding="utf-8",
        )
        _normalize_debian_mtimes(source/"debian")
        # dpkg-source also honors SOURCE_DATE_EPOCH during artifact creation.
        os.environ["SOURCE_DATE_EPOCH"]=str(SOURCE_DATE_EPOCH)
        # dpkg-source 3.0/quilt needs the unsigned *locally renamed* upstream
        # archive; its CONTENT is still the independently signed vendor tar.
        orig=work/("util-linux_"+VERSION+".orig.tar.xz")
        shutil.copy2(artifacts/TAR_NAME,orig)
        if _hash(orig)!=TAR_SHA256:
            raise ValueError("Rebased upstream tarball bytes changed")
        _run(["dpkg-source","--before-build",str(source)],cwd=work,timeout=90)
        _assert_roundtrip_tree(source)
        _run(["dpkg-source","--build",str(source)],cwd=work,timeout=160)
        experimental=work/("util-linux_"+EXPERIMENT_VERSION+".dsc")
        debian_archive=work/("util-linux_"+EXPERIMENT_VERSION+".debian.tar.xz")
        if not experimental.is_file() or not debian_archive.is_file():
            raise ValueError("Debian 3.0 quilt source package not built")
        roundtrip=work/"roundtrip"
        # Our experimental DSC IS NOT SIGNED. The original Debian .dsc and
        # upstream tar sources were checked cryptographically before rebase.
        _run(["dpkg-source","--no-check","-x",
              str(experimental),str(roundtrip)],cwd=work,timeout=90)
        _assert_roundtrip_tree(roundtrip)
        if list(work.glob("*.deb")):
            raise ValueError("Source-only proof must not produce binary packages")
        result={
            "status":"trixie_debian_quilt_overlay_source_built_release_blocked",
            **signed,
            "vendor_upstream_version":VERSION,
            "vendor_upstream_source_sha256":TAR_SHA256,
            "upstream_signatures_verified":True,
            "debian_maintainer_source_verified":True,
            "debian_original_patches":len(original_series),
            "debian_patches_preserved":len(RETAINED_DEBIAN_PATCHES),
            "already_upstream_security_patches_removed":len(UPSTREAM_PATCH_SERIES),
            "cve_78408_backport_added":True,
            "new_quilt_patch_count":len(new_series),
            "source_roundtrip_verified":True,
            "patched_nsenter_sha256":PATCHED_NSENTER_SHA256,
            "experimental_debian_version":EXPERIMENT_VERSION,
            "experimental_dsc_sha256":_hash(experimental),
            "experimental_debian_tar_sha256":_hash(debian_archive),
            "experimental_dsc_signed":False,
            "debian_binary_packages_built":False,
            "debian_trixie_fixed_package_installed":False,
            "runtime_image_replaced":False,
            "cve_applicability":"not_established",
            "source_package_release_authorized":False,
            "security_gate":"blocked",
            "vex":"not_issued",
            "release_authorized":False,
        }
        return result


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir",required=True,type=Path)
    args=parser.parse_args()
    try:
        report=verify_debian_source_overlay(args.artifacts_dir)
    except (ValueError,TypeError,KeyError,OSError,UnicodeError):
        print(json.dumps({"status":"error",
                          "reason":"debian_source_overlay_unverified",
                          "release_authorized":False},sort_keys=True))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 2


if __name__=="__main__":
    raise SystemExit(main())
