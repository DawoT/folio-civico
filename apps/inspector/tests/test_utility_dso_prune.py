"""R1.30: exact ELF reverse refs, Debian delta and runtime library preservation."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"apps/inspector"))
from utility_dso_surface import (
    TOOLS, DSO, OWNERS, REFS, KEEP_UUID,
    inventory, remove_unneeded_utilities,
)
from utility_dso_dpkg import compare_delta, OWNERS as DPKG_OWNERS
from utility_dso_gate import verify_prune, BEFORE, AFTER

O="sha256:"+"a"*64
N="sha256:"+"b"*64
EMPTY="sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"


def fixture():
    def scan(tag):
        return {"ArtifactName":tag,"ArtifactType":"container_image",
                "Results":[{"Target":"debian 13.7","Type":"debian",
                  "Vulnerabilities":[
                    {"PkgName":"util-linux","InstalledVersion":"2.41.5-0+deb13u1",
                     "VulnerabilityID":"CVE-2026-76642","Severity":"HIGH"},
                    {"PkgName":"libsmartcols1","InstalledVersion":"2.41.5-0+deb13u1",
                     "VulnerabilityID":"CVE-2026-78408","Severity":"HIGH"},
                    {"PkgName":"libexpat1","InstalledVersion":"2.10.0-1+folio1",
                     "VulnerabilityID":"CVE-2026-124317","Severity":"UNKNOWN"},
                  ]}]}
    def sbom(tag,id):
        return {"bomFormat":"CycloneDX",
                "metadata":{"component":{"type":"container","name":tag,
                  "properties":[{"name":"aquasecurity:trivy:ImageID","value":id}]}},
                "components":[{"name":p,"type":"library","version":"2.41.5-0+deb13u1",
                               "purl":"pkg:deb/debian/"+p+"@2.41.5-0%2Bdeb13u1?arch=amd64"}
                              for p in ("util-linux","libblkid1","libsmartcols1","libuuid1")]}
    def image(id,diff):
        return {"Id":id,"Os":"linux","Architecture":"amd64",
                "RootFS":{"Type":"layers","Layers":[diff,EMPTY]},
                "Config":{"User":"65534:65534",
                          "Cmd":["python3","-I","/srv/folio-inspector/inspector.py"],
                          "Entrypoint":None,"WorkingDir":"/srv/folio-inspector",
                          "Env":["PATH=/usr/local/bin:/usr/bin:/bin"],
                          "ExposedPorts":{"8789/tcp":{}}}}
    def entry(path):
        if path.endswith(".so.1"):
            return {"path":path,"package":OWNERS[path],"kind":"symlink",
                    "target":path.split("/")[-1]+".1.0"}
        return {"path":path,"package":OWNERS[path],"kind":"elf",
                "mode":"0644" if path in DSO.values() else "0755",
                "sha256":hashlib.sha256(path.encode()).hexdigest()}
    keep=[{"path":p,"sha256":hashlib.sha256(p.encode()).hexdigest()}
          for p in KEEP_UUID]
    def surface(after):
        return {"source":"folio-utility-dso-reduction-v1",
                "state":"pruned" if after else "baseline",
                "entries":[] if after else [entry(x) for x in sorted(OWNERS)],
                "missing":sorted(OWNERS) if after else [],
                "references":{k:[] if after else sorted(v) for k,v in REFS.items()},
                "retained_uuid":copy.deepcopy(keep),"scan_complete":True}
    def dpkg(after):
        return {"source":"folio-utility-dso-dpkg-v1","packages":{
            pkg:{"version":"2.41.5-0+deb13u1",
                 "missing":sorted(["/usr/share/doc/"+pkg+"/old"]
                  + ([p for p in OWNERS if OWNERS[p]==pkg] if after else []))}
            for pkg in sorted(set(OWNERS.values()))}}
    clamav={"source":"folio-clamav-minimal-native-v1",
            "release_authorized":False,"files":[
                {"path":"/usr/local/bin/clamscan","sha256":"f"*64}]}
    return [scan(BEFORE),scan(AFTER),sbom(BEFORE,O),sbom(AFTER,N),
            image(O,"sha256:"+"c"*64),image(N,"sha256:"+"d"*64),
            surface(False),surface(True),dpkg(False),dpkg(True),
            copy.deepcopy(clamav),copy.deepcopy(clamav)]


class UtilityDSOTDD(unittest.TestCase):
    def test_exact_count_and_uuid_retention(self):
        self.assertEqual(len(TOOLS),15)
        self.assertEqual(len(OWNERS),19)
        self.assertEqual(OWNERS,DPKG_OWNERS)
        self.assertEqual(set(REFS),{"libblkid.so.1","libsmartcols.so.1"})
        self.assertEqual(set(REFS["libblkid.so.1"]) & set(REFS["libsmartcols.so.1"]),
                         {"/usr/bin/partx","/usr/sbin/wipefs"})

    def make_files(self,root:Path):
        for p in sorted((*OWNERS,*KEEP_UUID)):
            file=root/p.lstrip("/")
            file.parent.mkdir(parents=True,exist_ok=True)
            if file.exists() or file.is_symlink():
                file.unlink()
            if p.endswith(".so.1"):
                file.symlink_to(file.name+".1.0")
            else:
                needles=tuple(k.encode() for k,v in REFS.items() if p in v)
                file.write_bytes(b"\x7fELF"+b".".join(needles)+p.encode())
                file.chmod(0o644 if p.endswith(".so.1.1.0") or p in KEEP_UUID else 0o755)

    def test_strict_removal_preserves_uuid_and_removes_every_reference(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);self.make_files(root)
            before=inventory(root,owned=OWNERS)
            self.assertEqual(before["state"],"baseline")
            after=remove_unneeded_utilities(root,owned=OWNERS)
            self.assertEqual(after["state"],"pruned")
            self.assertTrue(all(not (root/p.lstrip("/")).exists() for p in OWNERS))
            self.assertTrue(all((root/p.lstrip("/")).is_file() for p in KEEP_UUID))
            self.assertEqual(before["retained_uuid"],after["retained_uuid"])

    def test_symlink_partial_and_stray_elf_ref_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);self.make_files(root)
            strange=root/"usr/local/bin/unexpected"
            strange.parent.mkdir(parents=True,exist_ok=True)
            strange.write_bytes(b"\x7fELF"+b"libblkid.so.1")
            with self.assertRaises(ValueError):
                remove_unneeded_utilities(root,owned=OWNERS)
            strange.unlink()
            first=root/sorted(TOOLS)[0].lstrip("/")
            first.unlink()
            with self.assertRaises(ValueError):
                remove_unneeded_utilities(root,owned=OWNERS)
            self.make_files(root)
            first.unlink()
            first.symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                remove_unneeded_utilities(root,owned=OWNERS)

    def test_dpkg_and_frozen_trivy_and_oci_comparator(self):
        f=fixture()
        self.assertEqual(compare_delta(f[8],f[9]),19)
        result=verify_prune(*f)
        self.assertEqual(result["status"],"utility_dso_pruned_release_blocked")
        self.assertEqual(result["removed_cli"],15)
        self.assertEqual(result["removed_dsos_and_links"],4)
        self.assertEqual(result["high_before"],result["high_after"])
        self.assertEqual(result["unknown_before"],result["unknown_after"])
        self.assertFalse(result["release_authorized"])

    def test_evidence_corruptions_must_fail_closed(self):
        tamper=[
            lambda f:f[6]["references"]["libblkid.so.1"].pop(),
            lambda f:f[7]["missing"].pop(),
            lambda f:f[7]["retained_uuid"][0].update(sha256="0"*64),
            lambda f:f[6]["entries"][0].update(package="wrong"),
            lambda f:f[6]["entries"][0].update(sha256="z"*64),
            lambda f:f[9]["packages"]["util-linux"]["missing"].append("/tmp/evil"),
            lambda f:f[9]["packages"]["libsmartcols1"].update(version="2.42.4"),
            lambda f:f[0]["Results"][0]["Vulnerabilities"].pop(),
            lambda f:f[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda f:f[3]["components"].pop(),
            lambda f:f[3]["metadata"]["component"]["properties"][0].update(value="wrong"),
            lambda f:f[5]["Config"].update(User="root"),
            lambda f:f[5]["RootFS"]["Layers"].__setitem__(0,"sha256:"+"c"*64),
            lambda f:f[11]["files"][0].update(sha256="0"*64),
        ]
        for i,fn in enumerate(tamper):
            with self.subTest(i=i):
                data=copy.deepcopy(fixture());fn(data)
                with self.assertRaises((ValueError,TypeError,KeyError)):
                    verify_prune(*data)

    def test_gate_exit_codes_and_scripts_cannot_deploy(self):
        names=("before-scan","after-scan","before-sbom","after-sbom",
               "before-inspect","after-inspect","before-surface","after-surface",
               "before-dpkg","after-dpkg","before-clamav","after-clamav")
        with tempfile.TemporaryDirectory() as t:
            cmd=["python3","apps/inspector/utility_dso_gate.py"]
            for name,data in zip(names,fixture()):
                f=Path(t)/(name+".json");f.write_text(json.dumps(data))
                cmd+=["--"+name,str(f)]
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=15)
            self.assertEqual(p.returncode,2,p.stderr)
            (Path(t)/"after-dpkg.json").write_text("{}")
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=15)
            self.assertEqual(p.returncode,3)
        docker=(ROOT/"apps/inspector/Dockerfile.utility-dso-experiment").read_text()
        build=(ROOT/"apps/inspector/build_utility_dso_experiment.sh").read_text()
        scan=(ROOT/"apps/inspector/scan_utility_dso_experiment.sh").read_text()
        for expected in ("FROM folio-civico-inspector:libmount-pruned-experiment AS hardener",
                         "FROM scratch","COPY --from=hardener / /",
                         "utility_dso_surface.py","--remove","USER 65534:65534"):
            self.assertIn(expected,docker)
        for expected in ("smoke_real_engines.py","smoke_http_real.py",
                         "utility_dso_smoke.py","--network none",
                         "--read-only","--cap-drop ALL"):
            self.assertIn(expected,build)
        for expected in ("--format json","--format cyclonedx",
                         "utility_dso_dpkg.py","utility_dso_gate.py",
                         "clamav_cli_native_inventory.py"):
            self.assertIn(expected,scan)
        for banned in ("docker push","wrangler deploy","--ignore-unfixed",
                       "--skip-db-update","--ignorefile"):
            self.assertNotIn(banned,build+scan)
        for name in ("build_utility_dso_experiment.sh","scan_utility_dso_experiment.sh"):
            p=subprocess.run(["bash","apps/inspector/"+name,"--bad"],cwd=ROOT,
                             capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,3)


if __name__=="__main__":
    unittest.main()
