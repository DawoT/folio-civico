"""R1.28 fail-closed proof that SUID/namespace ELF files were removed.

The previous chmod-only R1.24 attempt was bypassable by ld-linux; now both
direct exec and loader paths must be absent in the flattened rootfs.
Compare exact scanner CVEs, CycloneDX, Docker config, five dpkg package
reports, and unchanged native ClamAV code. Never authorize release.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from privileged_loader_surface import REMOVE, OWNERS, SOURCE
from privileged_loader_dpkg import compare_missing
from runtime_prune_comparison import _scan, _sbom

BEFORE="folio-civico-inspector:clamav-cli-limited-experiment"
AFTER="folio-civico-inspector:privileged-loader-removed-experiment"
EMPTY="sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
SHA=re.compile(r"^[a-f0-9]{64}$")
DIGEST=re.compile(r"^sha256:[a-f0-9]{64}$")
CONFIG_FIELDS=(
    "User","Cmd","Entrypoint","WorkingDir","ExposedPorts",
    "Volumes","Healthcheck","StopSignal","Env",
)


def _inspect(meta:object) -> tuple[str,dict,set[str]]:
    if (not isinstance(meta,dict)
            or not isinstance(meta.get("Id"),str)
            or not DIGEST.fullmatch(meta["Id"])
            or meta.get("Os")!="linux" or meta.get("Architecture")!="amd64"):
        raise ValueError("Immutable Linux amd64 Docker image required")
    rootfs=meta.get("RootFS")
    layers=rootfs.get("Layers") if isinstance(rootfs,dict) else None
    if (not isinstance(layers,list) or len(layers)!=2
            or layers.count(EMPTY)!=1
            or not all(isinstance(x,str) and DIGEST.fullmatch(x)
                       for x in layers)):
        raise ValueError("Unexpected nonflattened OCI filesystem layers")
    config=meta.get("Config")
    if (not isinstance(config,dict) or config.get("User")!="65534:65534"
            or config.get("Cmd")!=[
                "python3","-I","/srv/folio-inspector/inspector.py"
            ]):
        raise ValueError("Privileged inspector identity or command changed")
    return meta["Id"],config,set(layers)


def _surface(value:object,*,after:bool) -> dict[str,str]:
    expected={
        "source","state","scan_complete","entries","missing","special"
    }
    if (not isinstance(value,dict) or set(value)!=expected
            or value["source"]!=SOURCE
            or value["scan_complete"] is not True
            or value["state"]!=("removed" if after else "baseline")
            or value["special"]!=[]
            or value["missing"]!=(list(REMOVE) if after else [])):
        raise ValueError("Privileged binary inventory state was not measured")
    items=value["entries"]
    paths=[] if after else list(REMOVE)
    if (not isinstance(items,list) or len(items)!=len(paths)
            or not all(isinstance(item,dict) for item in items)
            or [item.get("path") for item in items]!=paths):
        raise ValueError("Sensitive executable presence is ambiguous")
    hashes={}
    for item in items:
        if (set(item)!={"path","mode","uid","package","sha256"}
                or item.get("mode")!="0644"
                or item.get("uid")!=0
                or item.get("package")!=OWNERS[item["path"]]
                or not isinstance(item.get("sha256"),str)
                or not SHA.fullmatch(item["sha256"])):
            raise ValueError("Sensitive executable mode, ownership or hash changed")
        hashes[item["path"]]=item["sha256"]
    return hashes


def _clamav(value:object) -> list[dict]:
    # This package was already minimized in R1.27. Require native byte
    # equality, not the pre-R1.27 16-ELF intact dpkg assertion.
    required={
        "source","package","package_version","architecture",
        "clamscan_version","expected_absent",
        "dpkg_verified_expected_removals","shared_library_linked",
        "files","release_authorized",
    }
    if (not isinstance(value,dict) or set(value)!=required
            or value.get("source")!="folio-clamav-minimal-native-v1"
            or value.get("package")!="clamav"
            or value.get("package_version")!="1.5.5-1"
            or value.get("architecture")!="amd64"
            or value.get("clamscan_version")!="ClamAV 1.5.5"
            or value.get("dpkg_verified_expected_removals") is not True
            or value.get("shared_library_linked") is not True
            or value.get("release_authorized") is not False):
        raise ValueError("Minimal signed-ClamAV inheritance was altered")
    paths=value.get("expected_absent")
    if (not isinstance(paths,list) or len(paths)!=10
            or paths!=sorted(set(paths))
            or "/usr/local/bin/freshclam" not in paths
            or "/usr/local/sbin/clamd" not in paths):
        raise ValueError("ClamAV CLI removals are not independently attested")
    files=value.get("files")
    if (not isinstance(files,list) or not files or
            any(not isinstance(x,dict) or set(x)!={"path","sha256"} or
                not isinstance(x.get("path"),str) or
                not isinstance(x.get("sha256"),str) or
                not SHA.fullmatch(x["sha256"]) for x in files) or
            [x["path"] for x in files]!=sorted(set(x["path"] for x in files))):
        raise ValueError("ClamAV native ELF inventory invalid")
    if not all(any(row["path"]==p for row in files) for p in (
        "/usr/local/bin/clamscan",
        "/usr/local/lib/libclamav.so.12.1.0",
        "/usr/local/lib/libclamav_rust.a",
    )):
        raise ValueError("Required ClamAV native runtime code unavailable")
    return files


def verify_loader_removal(
    before_scan:dict,after_scan:dict,before_sbom:dict,after_sbom:dict,
    before_inspect:dict,after_inspect:dict,before_surface:dict,
    after_surface:dict,before_dpkg:dict,after_dpkg:dict,
    before_clamav:dict,after_clamav:dict,
) -> dict:
    before_id,before_config,before_layers=_inspect(before_inspect)
    after_id,after_config,after_layers=_inspect(after_inspect)
    if before_id==after_id or (before_layers&after_layers)-{EMPTY}:
        raise ValueError("Historical filesystem content layers shared")
    if any(before_config.get(x)!=after_config.get(x) for x in CONFIG_FIELDS):
        raise ValueError("Runtime security envelope or configuration changed")

    before_hashes=_surface(before_surface,after=False)
    after_hashes=_surface(after_surface,after=True)
    if len(before_hashes)!=len(REMOVE) or after_hashes:
        raise ValueError("Privileged ELF files remain in runtime")
    newly_missing=compare_missing(before_dpkg,after_dpkg)
    if newly_missing!=len(REMOVE):
        raise ValueError("Unexpected Debian-owned file deletion")
    native_before=_clamav(before_clamav)
    native_after=_clamav(after_clamav)
    if before_clamav!=after_clamav or native_before!=native_after:
        raise ValueError("Unrelated ClamAV executable or library bytes changed")

    before_packages=_sbom(before_sbom,BEFORE,before_id)
    after_packages=_sbom(after_sbom,AFTER,after_id)
    if before_packages!=after_packages:
        raise ValueError("Debian package inventory was changed")
    before_cves=_scan(before_scan,BEFORE)
    after_cves=_scan(after_scan,AFTER)
    if before_cves!=after_cves:
        raise ValueError("Trivy CVE or severity was suppressed or changed")
    counts=Counter()
    for key,n in before_cves.items():
        counts[key[4]]+=n
    return {
        "status":"privileged_elf_loader_blocked_no_release",
        "release_authorized":False,
        "scanner_gate":"blocked",
        "vex":"not_issued",
        "source_image_id":before_id,
        "experimental_image_id":after_id,
        "removed_entrypoints":len(REMOVE),
        "new_missing_dpkg_files":newly_missing,
        "validated_owning_packages":len(set(OWNERS.values())),
        "remaining_privileged_modes":0,
        "preserved_clamav_native_files":len(native_after),
        "nonempty_parent_layers_reused":0,
        "unapproved_package_changes":0,
        "unapproved_cve_changes":0,
        "critical_before":counts["CRITICAL"],
        "critical_after":counts["CRITICAL"],
        "high_before":counts["HIGH"],
        "high_after":counts["HIGH"],
        "unknown_before":counts["UNKNOWN"],
        "unknown_after":counts["UNKNOWN"],
        "util_linux_cve_assessment":"still_open",
    }


def main() -> int:
    parser=argparse.ArgumentParser()
    fields=(
        "before-scan","after-scan","before-sbom","after-sbom",
        "before-inspect","after-inspect","before-surface","after-surface",
        "before-dpkg","after-dpkg","before-clamav","after-clamav",
    )
    for field in fields:
        parser.add_argument("--"+field,required=True,type=Path)
    args=parser.parse_args()
    try:
        report=verify_loader_removal(*[
            json.loads(getattr(args,field.replace("-","_")).read_text(
                encoding="utf-8"
            )) for field in fields
        ])
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        print(json.dumps({"status":"error",
                          "reason":"privileged_elf_loader_evidence_invalid"}))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 2  # A real mitigated launch surface is not a CVE fix or release.


if __name__=="__main__":
    raise SystemExit(main())
