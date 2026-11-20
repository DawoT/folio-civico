"""R1.30 fail-closed four-CVE reachability gate, never a VEX or release.

No source upgrade, container rebuild or CVE suppression is performed. The
exact R1.29 Docker ID is bound to Trivy JSON/CycloneDX and two independent
filesystem probes, including inherited R1.28/R1.29 safeguards. A valid report
still exits 2 because the Debian Trixie source package is unpatched.

The nine binary package rows each carry all four HIGH IDs in the current DB.
This source-origin scanner attribution is *not* proof that all nine binaries
contain every vulnerable function.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from util_linux_cve_runtime import (
    CVES, OWNED_PACKAGES, REQUIRED_ABSENT, validate_runtime_inventory,
)
from libmount_prune_gate import _surface as verify_libmount_removed
from privileged_loader_gate import _surface as verify_privileged_removed
from runtime_prune_comparison import _scan, _sbom

IMAGE="folio-civico-inspector:libmount-pruned-experiment"
IMAGE_ID="sha256:0af77fb9144634a8e4d77456eb460f92e5d9274ad042f52483157330d565651c"
EMPTY="sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
DIGEST=re.compile(r"^sha256:[a-f0-9]{64}$")
VERSIONS=OWNED_PACKAGES
UPSTREAM_COMPLETE_FIX="2.42.4"
CVE_PREREQUISITES={
    "CVE-2026-76642":(
        "privileged_mount_helper_entrypoint_absent",
        "libmount_post_hook_dso_absent",
        "fstab_mount_entries_absent",
    ),
    "CVE-2026-78408":(
        "nsenter_and_unshare_entrypoints_absent",
        "no_cgroup_procs_inherited_descriptors",
        "capabilities_and_new_privileges_disabled",
    ),
    "CVE-2026-78409":(
        "mount_entrypoint_absent",
        "libmount_detached_subdir_dso_absent",
        "fstab_x_mount_subdir_entries_absent",
    ),
    "CVE-2026-78410":(
        "restricted_mount_entrypoint_absent",
        "libmount_bind_source_dso_absent",
        "fstab_bind_and_ownership_hooks_absent",
    ),
}
if tuple(CVE_PREREQUISITES)!=tuple(CVES):
    raise AssertionError("CVE provenance incomplete")


def _validate_image(inspect:object) -> None:
    if (not isinstance(inspect,dict)
            or inspect.get("Id")!=IMAGE_ID
            or inspect.get("Os")!="linux"
            or inspect.get("Architecture")!="amd64"):
        raise ValueError("R1.29 image identity or architecture changed")
    root=inspect.get("RootFS")
    layers=root.get("Layers") if isinstance(root,dict) else None
    if (
        not isinstance(layers,list) or len(layers)!=2 or
        layers.count(EMPTY)!=1 or
        not all(isinstance(x,str) and DIGEST.fullmatch(x)
                for x in layers)
    ):
        raise ValueError("R1.29 flattened OCI image not verified")
    config=inspect.get("Config")
    if (
        not isinstance(config,dict) or
        config.get("User")!="65534:65534" or
        config.get("Cmd")!=[
            "python3","-I","/srv/folio-inspector/inspector.py"
        ] or
        config.get("Entrypoint") is not None or
        config.get("WorkingDir")!="/srv/folio-inspector" or
        config.get("ExposedPorts")!={"8789/tcp":{}} or
        not isinstance(config.get("Env"),list) or
        "CLAMAV_DB_DIR=/opt/clamdb" not in config["Env"]
    ):
        raise ValueError("Scanner runtime entrypoint/user/config changed")


def _expected_purl(package:str, version:str) -> str:
    if ":" in version:
        epoch,unprefixed=version.split(":",1)
    else:
        epoch,unprefixed="",version
    return (
        "pkg:deb/debian/"+package+"@"+unprefixed.replace("+","%2B")
        +"?arch=amd64&distro=debian-13.7"
        +("&epoch="+epoch if epoch else "")
    )


def _validate_sbom(sbom:dict) -> None:
    components=_sbom(sbom,IMAGE,IMAGE_ID)
    tracked={
        (row[1],row[2],row[3]):n
        for row,n in components.items()
        if row[1] in VERSIONS
    }
    expected={
        (package,version,_expected_purl(package,version)):1
        for package,version in VERSIONS.items()
    }
    if tracked!=expected:
        raise ValueError("Nine vulnerable Debian package identities not preserved")


def _validate_scan(scan:dict) -> tuple[Counter,int]:
    hits=_scan(scan,IMAGE)
    # Account for each CVE separately even when the scanner attributes a
    # source-package bug to several different derived Debian packages.
    observed={
        key:n for key,n in hits.items()
        if key[3] in CVES
    }
    expected={
        ("debian",pkg,version,cve,"HIGH"):1
        for pkg,version in VERSIONS.items() for cve in CVES
    }
    if observed!=expected:
        raise ValueError("One or more of the 36 HIGH util-linux entries changed")
    counts=Counter()
    for key,n in hits.items():
        counts[key[4]]+=n
    if counts["CRITICAL"]!=0 or counts["HIGH"]<len(expected):
        raise ValueError("Trivy high/critical baseline unexpectedly changed")
    return counts,len(expected)


def check_util_linux_scope(
    runtime:dict,scan:dict,sbom:dict,inspect:dict,
    libmount_inventory:dict,privileged_inventory:dict,
) -> dict:
    _validate_image(inspect)
    validate_runtime_inventory(runtime)
    _validate_sbom(sbom)
    severity,records=_validate_scan(scan)
    if verify_libmount_removed(libmount_inventory,after=True):
        raise ValueError("R1.29 libmount native code reappeared")
    if verify_privileged_removed(privileged_inventory,after=True):
        raise ValueError("R1.28 privileged tools reappeared")

    # These CVE-specific findings are not a VEX determination; failure to
    # observe a known entrypoint is bounded by the audited runtime and cannot
    # rule out all alternate callers or source-package vulnerabilities.
    return {
        "status":"four_util_linux_cves_open_release_blocked",
        "image":IMAGE,
        "image_id":IMAGE_ID,
        "scanner_gate":"blocked",
        "release_authorized":False,
        "vex":"not_issued",
        "individual_cve_applicability":"manual_review_required",
        "debian_release":"trixie",
        "debian_trixie_package_version":"2.41.5-0+deb13u1",
        "upstream_complete_fix_floor":UPSTREAM_COMPLETE_FIX,
        "recommended_remediation_path":"trixie_security_backport_or_verified_source_build",
        "do_not_install_from":"debian_sid_or_forky",
        "cve_ids":list(CVES),
        "cve_conditions_which_were_observed_absent":{
            key:list(CVE_PREREQUISITES[key]) for key in CVES
        },
        "vulnerable_debian_binary_packages":len(VERSIONS),
        "cve_high_records_preserved":records,
        "inspected_known_absent_paths":len(REQUIRED_ABSENT),
        "removed_libmount_elf_reference_scan":"passed",
        "removed_privileged_elf_inventory":"passed",
        "source_package_patch_applied":False,
        "critical_findings":severity["CRITICAL"],
        "high_findings":severity["HIGH"],
        "unknown_findings":severity["UNKNOWN"],
    }


def main() -> int:
    parser=argparse.ArgumentParser()
    for label in (
        "runtime","scan","sbom","inspect","libmount","privileged"
    ):
        parser.add_argument("--"+label,required=True,type=Path)
    args=parser.parse_args()
    try:
        report=check_util_linux_scope(*[
            json.loads(getattr(args,label).read_text(encoding="utf-8"))
            for label in (
                "runtime","scan","sbom","inspect","libmount","privileged"
            )
        ])
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        print(json.dumps({
            "status":"error","reason":"util_linux_cve_evidence_invalid",
        }))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 2  # Four HIGH CVEs remain open; no automatic release.


if __name__=="__main__":
    raise SystemExit(main())
