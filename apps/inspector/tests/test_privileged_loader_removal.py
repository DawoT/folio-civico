"""TDD R1.28: ELF-loader bypass must be impossible after physical removal."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
from privilege_surface import GUARDED
from privileged_loader_surface import inventory, remove_entrypoints, REMOVE, OWNERS
from privileged_loader_gate import verify_loader_removal, BEFORE, AFTER
from privileged_loader_smoke import TARGETS as SMOKE_TARGETS
from privileged_loader_dpkg import compare_missing, OWNERS as DPKG_OWNERS
from clamav_cli_surface import DENY as CLAMAV_DENY

OLD_ID="sha256:"+"a"*64
NEW_ID="sha256:"+"b"*64
EMPTY="sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"


def fixture():
    def scan(image):
        return {"ArtifactName": image, "ArtifactType": "container_image",
                "Results": [{"Target": "debian 13.7", "Type": "debian",
                  "Vulnerabilities": [
                    {"PkgName":"util-linux","InstalledVersion":"2.41.5-0+deb13u1",
                     "VulnerabilityID":"CVE-2026-76642","Severity":"HIGH"},
                    {"PkgName":"libexpat1","InstalledVersion":"2.10.0-1+folio1",
                     "VulnerabilityID":"CVE-2026-124317","Severity":"UNKNOWN"},
                  ]}]}
    def sbom(image,identity):
        return {"bomFormat":"CycloneDX",
                "metadata":{"component":{"name":image,"type":"container",
                  "properties":[{"name":"aquasecurity:trivy:ImageID","value":identity}]}},
                "components":[{"name":"util-linux","type":"library","version":"2.41.5-0+deb13u1",
                               "purl":"pkg:deb/debian/util-linux@2.41.5-0%2Bdeb13u1?arch=amd64"},
                              {"name":"clamav","type":"library","version":"1.5.5-1",
                               "purl":"pkg:deb/debian/clamav@1.5.5-1?arch=amd64"}]}
    def inspect(ident,diffid):
        return {"Id": ident, "Os":"linux","Architecture":"amd64",
                "RootFS":{"Type":"layers","Layers":[diffid,EMPTY]},
                "Config":{"User":"65534:65534","Cmd":["python3","-I","/srv/folio-inspector/inspector.py"],
                          "Entrypoint":None,"WorkingDir":"/srv/folio-inspector",
                          "Env":["PATH=/usr/local/bin:/usr/bin:/bin","CLAMAV_DB_DIR=/opt/clamdb"],
                          "ExposedPorts":{"8789/tcp":{}}}}
    def surf(after):
        return {"source":"folio-privileged-loader-presence-v1",
                "state":"removed" if after else "baseline",
                "scan_complete": True,
                "entries":[] if after else [
                  {"path":path,"mode":"0644","uid":0,"package":OWNERS[path],
                   "sha256":hashlib.sha256(path.encode()).hexdigest()}
                  for path in REMOVE
                ],
                "missing":list(REMOVE) if after else [],
                "special":[]}
    def dpkg(after):
        return {"source":"folio-privileged-loader-dpkg-v1",
                "packages":{
                  package:{"version":"synthetic","missing": sorted(
                    ["/usr/share/doc/"+package+"/readme"]
                    + ([p for p in REMOVE if OWNERS[p]==package] if after else []))}
                  for package in sorted(set(OWNERS.values()))
                }}
    def clamav():
        paths=(
            "/usr/local/bin/clamscan",
            "/usr/local/lib/libclamav.so.12.1.0",
            "/usr/local/lib/libclamav_rust.a",
        )
        return {
            "source":"folio-clamav-minimal-native-v1",
            "package":"clamav","package_version":"1.5.5-1",
            "architecture":"amd64","clamscan_version":"ClamAV 1.5.5",
            "expected_absent":sorted(CLAMAV_DENY),
            "dpkg_verified_expected_removals":True,
            "shared_library_linked":True,
            "files":[{"path":path,"sha256":hashlib.sha256(path.encode()).hexdigest()}
                     for path in paths],
            "release_authorized":False,
        }
    return (scan(BEFORE),scan(AFTER),sbom(BEFORE,OLD_ID),sbom(AFTER,NEW_ID),
            inspect(OLD_ID,"sha256:"+"d"*64),inspect(NEW_ID,"sha256:"+"e"*64),
            surf(False),surf(True),dpkg(False),dpkg(True),clamav(),clamav())


class PrivilegedLoaderTDD(unittest.TestCase):
    def test_known_paths_are_identical_to_previous_privilege_policy(self):
        self.assertEqual(tuple(REMOVE), tuple(GUARDED))
        self.assertEqual(tuple(SMOKE_TARGETS), tuple(REMOVE))
        self.assertEqual(DPKG_OWNERS, OWNERS)
        self.assertEqual(len(REMOVE),14)
        self.assertEqual(set(OWNERS.values()),
                         {"passwd","login","mount","util-linux","libpam-modules-bin"})

    def test_before_to_after_removes_exactly_all_fourteen_bytes(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            for name in REMOVE:
                path=root/name.lstrip("/")
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b"\x7fELF"+name.encode())
                path.chmod(0o644)
            before=inventory(root, owned=OWNERS)
            self.assertEqual(before["state"],"baseline")
            result=remove_entrypoints(root, owned=OWNERS)
            self.assertEqual(result["state"],"removed")
            self.assertEqual(result["missing"],list(REMOVE))
            self.assertEqual(result["entries"],[])
            for name in REMOVE:
                self.assertFalse((root/name.lstrip("/")).exists())
            self.assertEqual(inventory(root, owned=OWNERS),result)

    def test_partial_deletion_symlink_and_executable_are_rejected(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            for name in REMOVE:
                path=root/name.lstrip("/")
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b"\x7fELF"+name.encode())
                path.chmod(0o644)
            first=root/REMOVE[0].lstrip("/")
            first.unlink()
            with self.assertRaises(ValueError):
                remove_entrypoints(root, owned=OWNERS)
            first.symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                remove_entrypoints(root, owned=OWNERS)
            first.unlink()
            first.write_bytes(b"\x7fELF");first.chmod(0o755)
            with self.assertRaises(ValueError):
                remove_entrypoints(root, owned=OWNERS)

    def test_dpkg_delta_exactness_and_no_new_native_cve(self):
        f=fixture()
        self.assertEqual(compare_missing(f[8],f[9]),len(REMOVE))
        result=verify_loader_removal(*f)
        self.assertEqual(result["status"],"privileged_elf_loader_blocked_no_release")
        self.assertEqual(result["removed_entrypoints"],14)
        self.assertEqual(result["new_missing_dpkg_files"],14)
        self.assertEqual(result["unknown_after"],1)
        self.assertEqual(result["high_after"],1)
        self.assertEqual(result["nonempty_parent_layers_reused"],0)
        self.assertFalse(result["release_authorized"])

    def test_fail_closed_on_unexpected_missing_or_version_and_all_evidence_tamper(self):
        changes=[
            lambda v: v[9]["packages"]["mount"]["missing"].append("/etc/shadow"),
            lambda v: v[9]["packages"]["mount"].update(version="different"),
            lambda v: v[8]["packages"]["passwd"]["missing"].append("/usr/bin/passwd"),
            lambda v: v[7]["missing"].pop(),
            lambda v: v[7]["entries"].append(v[6]["entries"][0]),
            lambda v: v[6]["entries"][0].update(mode="0755"),
            lambda v: v[6]["entries"][0].update(sha256="x"*64),
            lambda v: v[0]["Results"][0]["Vulnerabilities"].pop(),
            lambda v: v[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda v: v[3]["components"].pop(),
            lambda v: v[3]["metadata"]["component"]["properties"][0].update(value="changed"),
            lambda v: v[5]["Config"].update(User="root"),
            lambda v: v[5]["RootFS"]["Layers"].__setitem__(0,"sha256:"+"d"*64),
            lambda v: v[11].update(release_authorized=True),
            lambda v: v[11]["files"][0].update(sha256="0"*64),
        ]
        for i,mutate in enumerate(changes):
            with self.subTest(i=i):
                data=copy.deepcopy(fixture())
                mutate(data)
                with self.assertRaises((ValueError,TypeError,KeyError)):
                    verify_loader_removal(*data)

    def test_cli_exit_two_on_valid_evidence_three_on_tamper(self):
        names=("before-scan","after-scan","before-sbom","after-sbom",
               "before-inspect","after-inspect","before-surface","after-surface",
               "before-dpkg","after-dpkg","before-clamav","after-clamav")
        with tempfile.TemporaryDirectory() as d:
            files=Path(d)
            cmd=["python3","apps/inspector/privileged_loader_gate.py"]
            for name,value in zip(names,fixture()):
                p=files/(name+".json")
                p.write_text(json.dumps(value),encoding="utf-8")
                cmd.extend(["--"+name,str(p)])
            r=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,2,r.stderr)
            self.assertFalse(json.loads(r.stdout)["release_authorized"])
            (files/"after-dpkg.json").write_text("{}")
            r=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,3)

    def test_build_and_scan_scripts_enforce_no_release_or_permissions_only(self):
        docker=(ROOT/"apps/inspector/Dockerfile.privileged-loader-experiment").read_text()
        build=(ROOT/"apps/inspector/build_privileged_loader_experiment.sh").read_text()
        scan=(ROOT/"apps/inspector/scan_privileged_loader_experiment.sh").read_text()
        for token in ("FROM folio-civico-inspector:clamav-cli-limited-experiment AS hardener",
                      "FROM scratch","COPY --from=hardener / /",
                      "privileged_loader_surface.py","--remove","USER 65534:65534"):
            self.assertIn(token,docker)
        for token in ("--network none","--read-only","--cap-drop ALL",
                      "privileged_loader_smoke.py","smoke_real_engines.py",
                      "smoke_http_real.py"):
            self.assertIn(token,build)
        for token in ("--format json","--format cyclonedx",
                      "privileged_loader_gate.py","privileged_loader_dpkg.py",
                      "clamav_cli_native_inventory.py","docker image inspect"):
            self.assertIn(token,scan)
        for token in ("--ignore-unfixed","--ignorefile","--skip-db-update",
                      "docker push","wrangler deploy"):
            self.assertNotIn(token,build+scan)
        for script in ("build_privileged_loader_experiment.sh",
                       "scan_privileged_loader_experiment.sh"):
            p=subprocess.run(["bash","apps/inspector/"+script,"--bad"],
                             cwd=ROOT,capture_output=True,text=True,timeout=5)
            self.assertEqual(p.returncode,3)


if __name__=="__main__":
    unittest.main()
