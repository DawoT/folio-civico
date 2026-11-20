"""R1.30 TDD: CVE-specific runtime reachability evidence, NEVER release/VEX.

All nine Debian binaries remain vulnerable per the scanner, even when the
known mount/nsenter/unshare entrypoints were physically removed in R1.28-29.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"apps/inspector"))

from util_linux_cve_runtime import (
    SOURCE, CVES, OWNED_PACKAGES, REQUIRED_ABSENT,
    validate_root_paths, validate_runtime_inventory,
)
from util_linux_cve_gate import (
    IMAGE, IMAGE_ID, check_util_linux_scope, VERSIONS,
)
from libmount_prune_surface import ALL as LIBMOUNT_MISSING
from privileged_loader_surface import REMOVE as PRIVILEGED_MISSING


def fixture():
    runtime={
        "source":SOURCE, "scan_complete":True,
        "os":"debian", "os_version":"13.7",
        "uid":65534,"euid":65534,
        "cap_eff":"0000000000000000",
        "no_new_privileges":True,
        "read_only_root":True,
        "network_interfaces":["lo"],
        "packages":dict(VERSIONS),
        "absent_paths":list(REQUIRED_ABSENT),
        "fstab_entries":[],
        "cgroup_procs_fds":[],
        "libmount_load_rejected":True,
        "clamscan_version":"ClamAV 1.5.5",
        "status":"known_entrypoints_absent_package_still_vulnerable",
        "release_authorized":False,
    }
    vulns=[]
    for name,version in sorted(VERSIONS.items()):
        for cve in CVES:
            vulns.append({
                "PkgName":name,"InstalledVersion":version,
                "VulnerabilityID":cve,"Severity":"HIGH",
            })
    # Include unrelated HIGH and UNKNOWN to demonstrate they remain visible.
    vulns += [
        {"PkgName":"clamav","InstalledVersion":"1.5.5-1",
         "VulnerabilityID":"CVE-2026-112222","Severity":"HIGH"},
        {"PkgName":"libexpat1","InstalledVersion":"2.10.0-1+folio1",
         "VulnerabilityID":"CVE-2026-111111","Severity":"UNKNOWN"},
    ]
    scan={"ArtifactName":IMAGE,"ArtifactType":"container_image",
          "Results":[{"Target":"debian 13.7","Type":"debian",
                      "Vulnerabilities":vulns}]}
    def purl(name,version):
        if ":" in version:
            epoch,plain=version.split(":",1)
        else:
            epoch,plain=None,version
        return (
            "pkg:deb/debian/"+name+"@"+plain.replace("+","%2B")
            +"?arch=amd64&distro=debian-13.7"
            +("&epoch="+epoch if epoch else "")
        )
    sbom={
        "bomFormat":"CycloneDX",
        "metadata":{"component":{
            "name":IMAGE,"type":"container",
            "properties":[{"name":"aquasecurity:trivy:ImageID",
                           "value":IMAGE_ID}]}},
        "components":[
            {"name":name,"type":"library","version":version,
             "purl":purl(name,version)}
            for name,version in VERSIONS.items()
        ],
    }
    inspect={"Id":IMAGE_ID,"Os":"linux","Architecture":"amd64",
             "RootFS":{"Type":"layers","Layers":[
                  "sha256:"+"b"*64,
                  "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"]},
             "Config":{"User":"65534:65534",
                       "Cmd":["python3","-I","/srv/folio-inspector/inspector.py"],
                       "WorkingDir":"/srv/folio-inspector",
                       "Entrypoint":None,"Env":["CLAMAV_DB_DIR=/opt/clamdb"],
                       "ExposedPorts":{"8789/tcp":{}}}}
    libmount={
        "source":"folio-libmount-prune-v1",
        "state":"removed","scan_complete":True,
        "entries":[],"missing":list(LIBMOUNT_MISSING),
        "elf_references":[],
    }
    privileged={
        "source":"folio-privileged-loader-presence-v1",
        "state":"removed","scan_complete":True,
        "entries":[],"missing":list(PRIVILEGED_MISSING),
        "special":[],
    }
    return [runtime,scan,sbom,inspect,libmount,privileged]


class UtilLinuxScopeTDD(unittest.TestCase):
    def test_four_cves_nine_packages_and_upstream_floor_are_fixed_contract(self):
        self.assertEqual(tuple(CVES),(
            "CVE-2026-76642","CVE-2026-78408",
            "CVE-2026-78409","CVE-2026-78410",
        ))
        self.assertEqual(set(VERSIONS),set(OWNED_PACKAGES))
        self.assertEqual(len(VERSIONS),9)
        self.assertEqual(len(REQUIRED_ABSENT),len(set(REQUIRED_ABSENT)))
        self.assertIn("/usr/bin/mount",REQUIRED_ABSENT)
        self.assertIn("/usr/bin/nsenter",REQUIRED_ABSENT)
        self.assertIn("/usr/bin/unshare",REQUIRED_ABSENT)
        self.assertIn("/usr/lib/x86_64-linux-gnu/libmount.so.1",REQUIRED_ABSENT)

    def test_clean_image_evidence_always_release_blocked(self):
        report=check_util_linux_scope(*fixture())
        self.assertEqual(report["status"],"four_util_linux_cves_open_release_blocked")
        self.assertEqual(report["cve_high_records_preserved"],36)
        self.assertEqual(report["vulnerable_debian_binary_packages"],9)
        self.assertEqual(report["cve_ids"],list(CVES))
        self.assertEqual(report["upstream_complete_fix_floor"],"2.42.4")
        self.assertEqual(report["debian_trixie_package_version"],"2.41.5-0+deb13u1")
        self.assertEqual(report["individual_cve_applicability"],"manual_review_required")
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["scanner_gate"],"blocked")
        self.assertEqual(report["vex"],"not_issued")

    def test_existing_images_can_be_probed_read_only_but_test_fixture_is_offline(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"etc").mkdir()
            (root/"etc/fstab").write_text(
                "# UNCONFIGURED FSTAB FOR BASE SYSTEM\n",
                encoding="utf-8",
            )
            self.assertEqual(validate_root_paths(root),list(REQUIRED_ABSENT))
            (root/"usr/bin").mkdir(parents=True)
            (root/"usr/bin/mount").write_bytes(b"\x7fELF")
            with self.assertRaises(ValueError):
                validate_root_paths(root)
            (root/"usr/bin/mount").unlink()
            (root/"etc/fstab").write_text(
                "/dev/sdb /media removable user,X-mount.subdir=subdir 0 0\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                validate_root_paths(root)
            (root/"etc/fstab").write_text("# empty\n")
            (root/"usr/lib/x86_64-linux-gnu").mkdir(parents=True)
            (root/"usr/lib/x86_64-linux-gnu/libmount.so.99").write_bytes(b"ELF")
            with self.assertRaises(ValueError):
                validate_root_paths(root)

    def test_bad_runtime_capabilities_cgroup_fds_pkg_or_fstab_fail_closed(self):
        tests=[
            lambda d:d[0].update(uid=0),
            lambda d:d[0].update(cap_eff="0000000000000001"),
            lambda d:d[0].update(no_new_privileges=False),
            lambda d:d[0].update(read_only_root=False),
            lambda d:d[0].update(network_interfaces=["lo","eth0"]),
            lambda d:d[0]["absent_paths"].pop(),
            lambda d:d[0].update(fstab_entries=["/dev/sdb /tmp none bind 0 0"]),
            lambda d:d[0].update(cgroup_procs_fds=["/sys/fs/cgroup/cgroup.procs"]),
            lambda d:d[0].update(libmount_load_rejected=False),
            lambda d:d[0]["packages"].update({"mount":"2.42.3-1"}),
            lambda d:d[0].update(release_authorized=True),
            lambda d:d[0].update(clamscan_version="ClamAV 1.5.4"),
        ]
        for i,mutate in enumerate(tests):
            with self.subTest(i=i):
                args=copy.deepcopy(fixture());mutate(args)
                with self.assertRaises((ValueError,TypeError,KeyError)):
                    check_util_linux_scope(*args)

    def test_missing_reclassified_replaced_scanner_and_sbom_fail_closed(self):
        tests=[
            lambda d:d[1]["Results"][0]["Vulnerabilities"].pop(0),
            lambda d:d[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda d:d[1]["Results"][0]["Vulnerabilities"][0].update(
                InstalledVersion="2.42.4-1",
            ),
            lambda d:d[1]["Results"][0]["Vulnerabilities"].append(
                copy.deepcopy(d[1]["Results"][0]["Vulnerabilities"][0])
            ),
            lambda d:d[2]["components"][0].update(version="2.42.4-1"),
            lambda d:d[2]["components"].pop(),
            lambda d:d[2]["metadata"]["component"]["properties"][0].update(value="spoof"),
            lambda d:d[3].update(Id="sha256:"+"0"*64),
            lambda d:d[3]["Config"].update(User="root"),
            lambda d:d[3]["RootFS"]["Layers"].pop(),
            lambda d:d[3]["Config"].update(Cmd=["sh"]),
            lambda d:d[4]["missing"].pop(),
            lambda d:d[4]["elf_references"].append("/usr/bin/findmnt"),
            lambda d:d[5]["missing"].pop(),
            lambda d:d[5]["special"].append("/usr/bin/su"),
        ]
        for i,mutate in enumerate(tests):
            with self.subTest(i=i):
                args=copy.deepcopy(fixture());mutate(args)
                with self.assertRaises((ValueError,TypeError,KeyError)):
                    check_util_linux_scope(*args)

    def test_cli_exit_codes_two_for_blocked_three_for_inconsistent(self):
        with tempfile.TemporaryDirectory() as d:
            paths=[]
            for name,value in zip(
                ("runtime","scan","sbom","inspect","libmount","privileged"),
                fixture(),
            ):
                path=Path(d)/(name+".json")
                path.write_text(json.dumps(value),encoding="utf-8")
                paths.extend(["--"+name,str(path)])
            command=["python3","apps/inspector/util_linux_cve_gate.py",*paths]
            good=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=9)
            self.assertEqual(good.returncode,2,good.stderr)
            (Path(d)/"scan.json").write_text("{}")
            bad=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=9)
            self.assertEqual(bad.returncode,3)

    def test_local_script_no_release_and_no_scanner_bypass(self):
        shell=(ROOT/"apps/inspector/scan_util_linux_cve_scope.sh").read_text()
        for expected in (
            "--network none","--read-only","--cap-drop ALL",
            "--security-opt no-new-privileges",
            "util_linux_cve_runtime.py","util_linux_cve_gate.py",
            "--format json","--format cyclonedx","docker image inspect",
        ):
            self.assertIn(expected,shell)
        for forbidden in (
            "docker push","wrangler deploy","--ignorefile",
            "--ignore-unfixed","--skip-db-update",
        ):
            self.assertNotIn(forbidden,shell)
        rc=subprocess.run(["bash","apps/inspector/scan_util_linux_cve_scope.sh","--bad"],
                          cwd=ROOT,capture_output=True,text=True,timeout=6)
        self.assertEqual(rc.returncode,3)


if __name__=="__main__":
    unittest.main()
