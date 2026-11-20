"""R1.29 differential libmount ELF/ABI audit. Release always blocked.

Retaining a Debian package record is *not* proof its code is still available;
we insist the only filesystem losses are nine identified unused commands plus
the libmount SONAME symlink and real ELF, while no remaining ELF directly
mentions the SONAME. Runtime library exploitability is NOT fully assessed.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from libmount_prune_surface import (
    ALL, REFS, OWNERS, TOOL_PATHS, DSO_FILE, DSO_LINK, SOURCE,
)
from libmount_prune_dpkg import delta
from runtime_prune_comparison import _scan, _sbom

BEFORE="folio-civico-inspector:privileged-loader-removed-experiment"
AFTER="folio-civico-inspector:libmount-pruned-experiment"
EMPTY="sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
SHA=re.compile(r"^[a-f0-9]{64}$")
IMAGE=re.compile(r"^sha256:[a-f0-9]{64}$")
FIELDS=(
    "User","Cmd","Entrypoint","WorkingDir","ExposedPorts",
    "Volumes","Healthcheck","StopSignal","Env",
)


def _image(metadata:object) -> tuple[str,dict,set[str]]:
    if (not isinstance(metadata,dict)
            or not isinstance(metadata.get("Id"),str)
            or not IMAGE.fullmatch(metadata["Id"])
            or metadata.get("Os")!="linux"
            or metadata.get("Architecture")!="amd64"):
        raise ValueError("Immutable Linux amd64 image identity required")
    root=metadata.get("RootFS")
    layers=root.get("Layers") if isinstance(root,dict) else None
    if (not isinstance(layers,list) or len(layers)!=2
            or layers.count(EMPTY)!=1 or
            not all(isinstance(x,str) and IMAGE.fullmatch(x) for x in layers)):
        raise ValueError("Historical filesystem layer or invalid OCI layout")
    config=metadata.get("Config")
    if (not isinstance(config,dict) or config.get("User")!="65534:65534"
            or config.get("Cmd")!=[
                "python3","-I","/srv/folio-inspector/inspector.py"
            ]):
        raise ValueError("Inspector UID or entrypoint unexpectedly changed")
    return metadata["Id"],config,set(layers)


def _surface(value:object,*,after:bool) -> dict[str,str]:
    keys={"source","state","scan_complete","entries","missing","elf_references"}
    if (not isinstance(value,dict) or set(value)!=keys
            or value.get("source")!=SOURCE
            or value.get("state")!=("removed" if after else "baseline")
            or value.get("scan_complete") is not True
            or value.get("missing")!=(list(ALL) if after else [])
            or value.get("elf_references")!=([] if after else list(REFS))):
        raise ValueError("Unattested or incomplete libmount ELF reference scan")
    entries=value["entries"]
    expected=[] if after else list(ALL)
    if (not isinstance(entries,list) or len(entries)!=len(expected) or
            any(not isinstance(x,dict) for x in entries) or
            [x.get("path") for x in entries]!=expected):
        raise ValueError("Unexpected libmount package file presence")
    hashes={}
    for row in entries:
        path=row["path"]
        if row.get("package")!=OWNERS[path]:
            raise ValueError("Debian libmount file ownership mismatched")
        if path==DSO_LINK:
            if (set(row)!={"path","package","kind","target"} or
                    row["kind"]!="symlink" or
                    row["target"]!="libmount.so.1.1.0"):
                raise ValueError("Unexpected libmount DSO symlink")
        else:
            expected_mode="0644" if path==DSO_FILE else "0755"
            if (set(row)!={"path","package","kind","mode","sha256"} or
                    row.get("kind")!="elf" or
                    row.get("mode")!=expected_mode or
                    not isinstance(row.get("sha256"),str) or
                    not SHA.fullmatch(row["sha256"])):
                raise ValueError("ClamAV or util-linux binary integrity mismatch")
            hashes[path]=row["sha256"]
    return hashes


def _clamav(value:object) -> list[dict]:
    if (not isinstance(value,dict) or
            value.get("source")!="folio-clamav-minimal-native-v1" or
            value.get("release_authorized") is not False):
        raise ValueError("ClamAV native byte provenance missing")
    files=value.get("files")
    if (not isinstance(files,list) or not files or
            any(not isinstance(x,dict) or set(x)!={"path","sha256"} or
                not isinstance(x.get("path"),str) or
                not isinstance(x.get("sha256"),str) or
                not SHA.fullmatch(x["sha256"]) for x in files)):
        raise ValueError("ClamAV native manifest invalid")
    paths=[x["path"] for x in files]
    if (paths!=sorted(set(paths)) or
            "/usr/local/bin/clamscan" not in paths):
        raise ValueError("ClamAV scanner was lost or replaced")
    return files


def verify_prune(
    before_scan:dict,after_scan:dict,before_sbom:dict,after_sbom:dict,
    before_inspect:dict,after_inspect:dict,before_surface:dict,
    after_surface:dict,before_dpkg:dict,after_dpkg:dict,
    before_clamav:dict,after_clamav:dict,
) -> dict:
    before_id,before_cfg,before_layers=_image(before_inspect)
    after_id,after_cfg,after_layers=_image(after_inspect)
    if before_id==after_id or (before_layers&after_layers)-{EMPTY}:
        raise ValueError("New image retains old filesystem contents")
    if any(before_cfg.get(x)!=after_cfg.get(x) for x in FIELDS):
        raise ValueError("Runtime configuration changed without authorization")
    original=_surface(before_surface,after=False)
    reduced=_surface(after_surface,after=True)
    if len(original)!=len(REFS) or reduced:
        raise ValueError("Unexpected libmount native file coverage")
    if delta(before_dpkg,after_dpkg)!=len(ALL):
        raise ValueError("Unapproved Debian package filesystem removals")

    if _clamav(before_clamav)!=_clamav(after_clamav):
        raise ValueError("ClamAV scanner or native library byte hash changed")
    if before_clamav!=after_clamav:
        raise ValueError("ClamAV native package metadata changed")

    old_pkg=_sbom(before_sbom,BEFORE,before_id)
    new_pkg=_sbom(after_sbom,AFTER,after_id)
    if old_pkg!=new_pkg:
        raise ValueError("CycloneDX Debian package inventory has changed")
    old_alerts=_scan(before_scan,BEFORE)
    new_alerts=_scan(after_scan,AFTER)
    if old_alerts!=new_alerts:
        raise ValueError("Trivy vulnerability/CVE coverage was suppressed")
    counter=Counter()
    for key,num in old_alerts.items():
        counter[key[4]]+=num
    return {
        "status":"libmount_entrypoints_removed_release_blocked",
        "release_authorized":False,
        "scanner_gate":"blocked",
        "vex":"not_issued",
        "cve_applicability":"individually_unassessed",
        "source_image_id":before_id,
        "experimental_image_id":after_id,
        "removed_unneeded_elf_commands":len(TOOL_PATHS),
        "removed_libmount_files":2,
        "new_missing_dpkg_files":len(ALL),
        "residual_direct_elf_soname_references":0,
        "nonempty_parent_layers_reused":0,
        "clamav_native_files_preserved":len(_clamav(before_clamav)),
        "unapproved_package_changes":0,
        "unapproved_cve_changes":0,
        "critical_before":counter["CRITICAL"],
        "critical_after":counter["CRITICAL"],
        "high_before":counter["HIGH"],
        "high_after":counter["HIGH"],
        "unknown_before":counter["UNKNOWN"],
        "unknown_after":counter["UNKNOWN"],
    }


def main() -> int:
    parser=argparse.ArgumentParser()
    labels=(
        "before-scan","after-scan","before-sbom","after-sbom",
        "before-inspect","after-inspect","before-surface","after-surface",
        "before-dpkg","after-dpkg","before-clamav","after-clamav",
    )
    for label in labels:
        parser.add_argument("--"+label,required=True,type=Path)
    args=parser.parse_args()
    try:
        report=verify_prune(*[
            json.loads(getattr(args,label.replace("-","_")).read_text(
                encoding="utf-8"
            )) for label in labels
        ])
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        print(json.dumps({"status":"error","reason":"libmount_prune_evidence_invalid"}))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 2


if __name__=="__main__":
    raise SystemExit(main())
