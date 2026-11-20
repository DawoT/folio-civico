"""R1.29 TDD: remove libmount ELF only after every reverse reference is absent."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"apps/inspector"))
from libmount_prune_surface import (
    TOOL_PATHS, DSO_FILE, DSO_LINK, OWNERS,
    inventory, remove_libmount_surface,
)
from libmount_prune_dpkg import delta, OWNERS as DPKG_OWNERS
from libmount_prune_gate import verify_prune, BEFORE, AFTER
from libmount_prune_smoke import REMOVED_TOOLS as SMOKE_TOOLS

OLD_ID="sha256:"+"a"*64
NEW_ID="sha256:"+"b"*64
EMPTY="sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
ALL=tuple(sorted((*TOOL_PATHS,DSO_LINK,DSO_FILE)))
REFS=tuple(sorted((*TOOL_PATHS,DSO_FILE)))


def fixture():
    def scan(tag):
        return {
            "ArtifactName":tag,"ArtifactType":"container_image",
            "Results":[{"Target":"debian 13.7","Type":"debian",
                "Vulnerabilities":[
                    {"PkgName":"libmount1","InstalledVersion":"2.41.5-0+deb13u1",
                     "Severity":"HIGH","VulnerabilityID":"CVE-2026-78410"},
                    {"PkgName":"util-linux","InstalledVersion":"2.41.5-0+deb13u1",
                     "Severity":"HIGH","VulnerabilityID":"CVE-2026-78408"},
                    {"PkgName":"libexpat1","InstalledVersion":"2.10.0-1+folio1",
                     "Severity":"UNKNOWN","VulnerabilityID":"CVE-2026-124317"},
                ]}]}
    def sbom(tag,id):
        return {"bomFormat":"CycloneDX",
            "metadata":{"component":{"name":tag,"type":"container",
                "properties":[{"name":"aquasecurity:trivy:ImageID","value":id}]}},
            "components":[{"name":pkg,"type":"library","version":v,
                "purl":"pkg:deb/debian/"+pkg+"@"+v+"?arch=amd64"}
                for pkg,v in (("libmount1","2.41.5-0+deb13u1"),
                              ("util-linux","2.41.5-0+deb13u1"),
                              ("clamav","1.5.5-1"))]}
    def inspect(ident,layer):
        return {"Id":ident,"Os":"linux","Architecture":"amd64",
                "RootFS":{"Type":"layers","Layers":[layer,EMPTY]},
                "Config":{"User":"65534:65534",
                  "Cmd":["python3","-I","/srv/folio-inspector/inspector.py"],
                  "WorkingDir":"/srv/folio-inspector","Entrypoint":None,
                  "Env":["PATH=/opt/folio-poppler/bin:/usr/local/bin:/usr/bin:/bin"],
                  "ExposedPorts":{"8789/tcp":{}}}}
    def entry(path):
        if path==DSO_LINK:
            return {"path":path,"package":OWNERS[path],"kind":"symlink",
                    "target":"libmount.so.1.1.0"}
        return {"path":path,"package":OWNERS[path],"kind":"elf",
                "mode":"0644" if path==DSO_FILE else "0755",
                "sha256":hashlib.sha256(path.encode()).hexdigest()}
    def surf(removed):
        return {"source":"folio-libmount-prune-v1",
            "state":"removed" if removed else "baseline",
            "scan_complete":True,"entries":[] if removed else [entry(x) for x in ALL],
            "missing":list(ALL) if removed else [],
            "elf_references":[] if removed else list(REFS)}
    def dpkg(pruned):
        return {"source":"folio-libmount-dpkg-v1","packages":{
          pkg:{"version":"2.41.5-0+deb13u1","missing":sorted(
             ["/usr/share/doc/"+pkg+"/README"]
             + ([path for path in ALL if OWNERS[path]==pkg] if pruned else []))}
          for pkg in sorted(set(OWNERS.values()))}}
    def clamav():
        return {"source":"folio-clamav-minimal-native-v1","files":[
                {"path":"/usr/local/bin/clamscan","sha256":"f"*64}
            ],"release_authorized":False}
    return [scan(BEFORE),scan(AFTER),sbom(BEFORE,OLD_ID),sbom(AFTER,NEW_ID),
            inspect(OLD_ID,"sha256:"+"c"*64),inspect(NEW_ID,"sha256:"+"d"*64),
            surf(False),surf(True),dpkg(False),dpkg(True),clamav(),clamav()]


class LibmountTDD(unittest.TestCase):
    def test_fixed_pkg_paths_and_protected_primary_scanner(self):
        self.assertEqual(len(TOOL_PATHS),9)
        self.assertEqual(set(SMOKE_TOOLS),set(TOOL_PATHS))
        self.assertEqual(OWNERS,DPKG_OWNERS)
        self.assertEqual(set(OWNERS.values()),{"util-linux","mount","libmount1"})

    def _setup(self,root:Path):
        for name in ALL:
            file=root/name.lstrip("/")
            file.parent.mkdir(parents=True,exist_ok=True)
            if file.is_symlink() or file.exists():
                file.unlink()
            if name==DSO_LINK:
                file.symlink_to("libmount.so.1.1.0")
            else:
                file.write_bytes(b"\x7fELF"+b"libmount.so.1"+name.encode())
                file.chmod(0o644 if name==DSO_FILE else 0o755)

    def test_file_and_reverse_elf_dependency_inventory_before_after(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            self._setup(root)
            before=inventory(root,owned=OWNERS)
            self.assertEqual(before["state"],"baseline")
            self.assertEqual(before["elf_references"],list(REFS))
            after=remove_libmount_surface(root,owned=OWNERS)
            self.assertEqual(after["state"],"removed")
            self.assertEqual(after["missing"],list(ALL))
            self.assertEqual(after["elf_references"],[])
            self.assertEqual(inventory(root,owned=OWNERS),after)

    def test_extra_reverse_dependency_symlink_and_partial_removal_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            self._setup(root)
            evil=root/"usr/local/bin/unexpected"
            evil.parent.mkdir(parents=True)
            evil.write_bytes(b"\x7fELF"+b"libmount.so.1")
            with self.assertRaises(ValueError):
                remove_libmount_surface(root,owned=OWNERS)
            evil.unlink()
            (root/TOOL_PATHS[0].lstrip("/")).unlink()
            with self.assertRaises(ValueError):
                remove_libmount_surface(root,owned=OWNERS)
            self._setup(root)
            s=root/TOOL_PATHS[0].lstrip("/")
            s.unlink()
            s.symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                remove_libmount_surface(root,owned=OWNERS)

    def test_dpkg_exact_delta_and_unchanged_scanner_gate(self):
        data=fixture()
        self.assertEqual(delta(data[8],data[9]),11)
        res=verify_prune(*data)
        self.assertEqual(res["removed_unneeded_elf_commands"],9)
        self.assertEqual(res["removed_libmount_files"],2)
        self.assertEqual(res["new_missing_dpkg_files"],11)
        self.assertEqual(res["status"],"libmount_entrypoints_removed_release_blocked")
        self.assertEqual(res["high_before"],res["high_after"])
        self.assertEqual(res["unknown_before"],res["unknown_after"])
        self.assertFalse(res["release_authorized"])

    def test_adversarial_tampering_fail_closed(self):
        changes=[
            lambda f:f[6]["elf_references"].pop(),
            lambda f:f[7]["missing"].pop(),
            lambda f:f[7]["entries"].append(f[6]["entries"][0]),
            lambda f:f[6]["entries"][0].update(sha256="x"*64),
            lambda f:f[8]["packages"]["mount"]["missing"].append("/unexpected"),
            lambda f:f[9]["packages"]["libmount1"]["missing"].pop(),
            lambda f:f[9]["packages"]["util-linux"].update(version="2.42.3"),
            lambda f:f[0]["Results"][0]["Vulnerabilities"].pop(),
            lambda f:f[1]["Results"][0]["Vulnerabilities"][0].update(Severity="MEDIUM"),
            lambda f:f[3]["components"].pop(),
            lambda f:f[3]["metadata"]["component"]["properties"][0].update(value="bad"),
            lambda f:f[5]["Config"].update(User="root"),
            lambda f:f[5]["RootFS"]["Layers"].__setitem__(0,"sha256:"+"c"*64),
            lambda f:f[11]["files"][0].update(sha256="0"*64),
            lambda f:f[11].update(release_authorized=True),
        ]
        for index,mutate in enumerate(changes):
            with self.subTest(index=index):
                data=copy.deepcopy(fixture());mutate(data)
                with self.assertRaises((ValueError,TypeError,KeyError)):
                    verify_prune(*data)

    def test_gate_cli_exit_codes_and_local_scripts_forbid_release(self):
        keys=("before-scan","after-scan","before-sbom","after-sbom",
              "before-inspect","after-inspect","before-surface","after-surface",
              "before-dpkg","after-dpkg","before-clamav","after-clamav")
        with tempfile.TemporaryDirectory() as d:
            command=["python3","apps/inspector/libmount_prune_gate.py"]
            for key,value in zip(keys,fixture()):
                f=Path(d)/(key+".json");f.write_text(json.dumps(value))
                command.extend(["--"+key,str(f)])
            p=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=12)
            self.assertEqual(p.returncode,2,p.stderr)
            (Path(d)/"after-dpkg.json").write_text("{}")
            q=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=12)
            self.assertEqual(q.returncode,3)
        docker=(ROOT/"apps/inspector/Dockerfile.libmount-prune-experiment").read_text()
        build=(ROOT/"apps/inspector/build_libmount_prune_experiment.sh").read_text()
        scan=(ROOT/"apps/inspector/scan_libmount_prune_experiment.sh").read_text()
        for key in ("FROM folio-civico-inspector:privileged-loader-removed-experiment AS hardener",
                    "FROM scratch","COPY --from=hardener / /",
                    "libmount_prune_surface.py","--remove","USER 65534:65534"):
            self.assertIn(key,docker)
        for key in ("--network none","--read-only","--cap-drop ALL",
                    "smoke_real_engines.py","smoke_http_real.py",
                    "libmount_prune_smoke.py"):
            self.assertIn(key,build)
        for key in ("--format json","--format cyclonedx",
                    "libmount_prune_gate.py","libmount_prune_dpkg.py",
                    "docker image inspect","clamav_cli_native_inventory.py"):
            self.assertIn(key,scan)
        for script in ("build_libmount_prune_experiment.sh",
                       "scan_libmount_prune_experiment.sh"):
            p=subprocess.run(["bash","apps/inspector/"+script,"--bad"],
                             cwd=ROOT,capture_output=True,text=True,timeout=8)
            self.assertEqual(p.returncode,3)
        for banned in ("docker push","wrangler deploy","--ignorefile",
                       "--ignore-unfixed","--skip-db-update"):
            self.assertNotIn(banned,docker+build+scan)


if __name__=="__main__":
    unittest.main()
