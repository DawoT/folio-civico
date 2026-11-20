"""R1.30 strict side-by-side Trivy, CycloneDX, native UUID and dpkg proof.

No waiver, CVE severity reduction, OCI publication or release authorization.
Exit 2 after valid evidence, exit 3 if any expectation is broken.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from utility_dso_surface import (
    TOOLS, DSO, LINKS, OWNERS, ALL, REFS, KEEP_UUID, SOURCE,
)
from utility_dso_dpkg import compare_delta
from libmount_prune_gate import _image, _clamav, FIELDS
from runtime_prune_comparison import _scan, _sbom

BEFORE="folio-civico-inspector:libmount-pruned-experiment"
AFTER="folio-civico-inspector:utility-dso-pruned-experiment"
EMPTY="sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
SHA=re.compile(r"^[a-f0-9]{64}$")


def _surface(report:object,*,after:bool) -> list[dict]:
    if (not isinstance(report,dict) or set(report)!={
        "source","state","entries","missing","references",
        "retained_uuid","scan_complete"
    } or report.get("source")!=SOURCE or
        report.get("state")!=("pruned" if after else "baseline") or
        report.get("scan_complete") is not True or
        report.get("missing")!=(list(ALL) if after else []) or
        report.get("references")!=(
            {k:[] for k in REFS} if after
            else {k:list(v) for k,v in REFS.items()}
        )):
        raise ValueError("ELF filesystem inventory not trustworthy")
    files=report["entries"]
    expected=[] if after else list(ALL)
    if (not isinstance(files,list) or len(files)!=len(expected) or
            any(not isinstance(row,dict) for row in files) or
            [row.get("path") for row in files]!=expected):
        raise ValueError("Expected package-owned native code absent or replaced")
    for row in files:
        name=row["path"]
        if row.get("package")!=OWNERS[name]:
            raise ValueError("Unexpected Debian package owner")
        if name in LINKS.values():
            if (set(row)!={"path","package","kind","target"} or
                    row["kind"]!="symlink" or
                    row["target"]!=name.split("/")[-1]+".1.0"):
                raise ValueError("Invalid native DSO symlink")
        else:
            mode="0644" if name in DSO.values() else "0755"
            if (set(row)!={"path","package","kind","mode","sha256"} or
                    row["kind"]!="elf" or row.get("mode")!=mode or
                    not isinstance(row.get("sha256"),str) or
                    not SHA.fullmatch(row["sha256"])):
                raise ValueError("Incorrect original ELF bytes or permissions")

    kept=report["retained_uuid"]
    if (not isinstance(kept,list) or len(kept)!=len(KEEP_UUID) or
            any(not isinstance(x,dict) or
                set(x)!={"path","sha256"} or
                not isinstance(x["sha256"],str) or
                not SHA.fullmatch(x["sha256"]) for x in kept) or
            [row["path"] for row in kept]!=list(KEEP_UUID)):
        raise ValueError("Untrusted retained libuuid/Python UUID code")
    return kept


def verify_prune(
    before_scan:dict,after_scan:dict,before_sbom:dict,after_sbom:dict,
    before_inspect:dict,after_inspect:dict,before_surface:dict,
    after_surface:dict,before_dpkg:dict,after_dpkg:dict,
    before_clamav:dict,after_clamav:dict,
) -> dict:
    old_id,old_cfg,old_layers=_image(before_inspect)
    new_id,new_cfg,new_layers=_image(after_inspect)
    if old_id==new_id or (old_layers&new_layers)-{EMPTY}:
        raise ValueError("Source historical rootfs layer was retained")
    if any(old_cfg.get(key)!=new_cfg.get(key) for key in FIELDS):
        raise ValueError("Unapproved native runtime configuration change")

    uuid_before=_surface(before_surface,after=False)
    uuid_after=_surface(after_surface,after=True)
    if uuid_before!=uuid_after:
        raise ValueError("Python UUID dependency bytes changed in source/dest")
    if compare_delta(before_dpkg,after_dpkg)!=len(ALL):
        raise ValueError("Debian extra package file removal detected")

    if (_clamav(before_clamav)!=_clamav(after_clamav) or
            before_clamav!=after_clamav):
        raise ValueError("Preserved ClamAV native scanner changed")

    old_packages=_sbom(before_sbom,BEFORE,old_id)
    new_packages=_sbom(after_sbom,AFTER,new_id)
    if old_packages!=new_packages:
        raise ValueError("CycloneDX installed package list was modified")
    old_vulns=_scan(before_scan,BEFORE)
    new_vulns=_scan(after_scan,AFTER)
    if old_vulns!=new_vulns:
        raise ValueError("Trivy changed or suppressed a CVE")
    counts=Counter()
    for key,value in old_vulns.items():
        counts[key[4]]+=value

    return {
        "status":"utility_dso_pruned_release_blocked",
        "source_image_id":old_id,
        "experimental_image_id":new_id,
        "removed_cli":len(TOOLS),
        "removed_dsos_and_links":len(ALL)-len(TOOLS),
        "new_missing_dpkg_files":len(ALL),
        "residual_elf_soname_references":0,
        "retained_python_uuid_code_files":len(uuid_after),
        "unchanged_native_clamav_files":len(_clamav(before_clamav)),
        "nonempty_parent_layers_reused":0,
        "unapproved_cve_changes":0,
        "unapproved_packages":0,
        "critical_before":counts["CRITICAL"],
        "critical_after":counts["CRITICAL"],
        "high_before":counts["HIGH"],
        "high_after":counts["HIGH"],
        "unknown_before":counts["UNKNOWN"],
        "unknown_after":counts["UNKNOWN"],
        "scanner_gate":"blocked",
        "cve_applicability":"individually_unassessed",
        "vex":"not_issued",
        "release_authorized":False,
    }


def main() -> int:
    parser=argparse.ArgumentParser()
    fields=(
        "before-scan","after-scan","before-sbom","after-sbom",
        "before-inspect","after-inspect","before-surface","after-surface",
        "before-dpkg","after-dpkg","before-clamav","after-clamav",
    )
    for name in fields:
        parser.add_argument("--"+name,required=True,type=Path)
    args=parser.parse_args()
    try:
        report=verify_prune(*[
            json.loads(getattr(args,name.replace("-","_")).read_text(
                encoding="utf-8"
            )) for name in fields
        ])
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        print(json.dumps({"status":"error",
                          "reason":"utility_dso_differential_evidence_invalid"}))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 2


if __name__=="__main__":
    raise SystemExit(main())
