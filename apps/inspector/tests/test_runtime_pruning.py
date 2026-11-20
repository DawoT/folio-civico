"""TDD: remove only unused GnuPG runtime packages without weakening CVE gate."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"apps/inspector"))
from runtime_prune_comparison import compare_images, REMOVED_PACKAGES

OLD="folio-civico-inspector:expat-experiment"
NEW="folio-civico-inspector:runtime-pruned-experiment"
REMOVED=(
    "dirmngr","gnupg","gnupg-l10n","gpg","gpg-agent","gpgconf","gpgsm",
    "libgpgme11t64","libgpgmepp6t64"
)

def fixtures():
    before={"ArtifactName":OLD,"ArtifactType":"container_image","Results":[
        {"Type":"debian","Target":"debian 13.7","Vulnerabilities":[
            {"PkgName":name, "InstalledVersion":"1.0",
             "VulnerabilityID":"CVE-2026-24882", "Severity":"HIGH"}
            for name in REMOVED[:7]
        ]+[
            {"PkgName":"libexpat1","InstalledVersion":"2.10.0-1+folio1",
             "VulnerabilityID":"CVE-2026-124317","Severity":"UNKNOWN"},
            {"PkgName":"clamav","InstalledVersion":"1.5.5-1",
             "VulnerabilityID":"CVE-2026-20213","Severity":"HIGH"},
        ]}
    ]}
    after=copy.deepcopy(before)
    after["ArtifactName"]=NEW
    after["Results"][0]["Vulnerabilities"]=after["Results"][0]["Vulnerabilities"][7:]
    def sbom(image, digest, removed):
        return {
            "bomFormat":"CycloneDX","specVersion":"1.7",
            "metadata":{"component":{"type":"container","name":image,
                "properties":[{"name":"aquasecurity:trivy:ImageID","value":digest}]}},
            "components":[{"type":"library","name":name,"version":"1.0",
                "purl":"pkg:deb/debian/"+name+"@1.0?arch=amd64"}
                for name in list(removed)+["libexpat1","clamav"]]+[
                {"type":"operating-system","name":"debian","version":"13.7"}]
        }
    oldid="sha256:"+("a"*64);newid="sha256:"+("b"*64)
    return (before,after,sbom(OLD,oldid,REMOVED),sbom(NEW,newid,()),oldid,newid)


class RuntimePruneTests(unittest.TestCase):
    def test_only_known_gpg_packages_and_findings_may_disappear(self):
        self.assertEqual(set(REMOVED_PACKAGES),set(REMOVED))
        result=compare_images(*fixtures())
        self.assertEqual(result["status"],"surface_reduced_release_blocked")
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["removed_high"],7)
        self.assertEqual(result["high_before"],8)
        self.assertEqual(result["high_after"],1)
        self.assertEqual(result["unknown_before"],1)
        self.assertEqual(result["unknown_after"],1)
        self.assertEqual(set(result["removed_packages"]),set(REMOVED))
        self.assertEqual(result["unapproved_package_changes"],0)
        self.assertEqual(result["unapproved_vulnerability_changes"],0)

    def test_real_cyclonedx_debian_operating_system_component_is_supported(self):
        docs=list(fixtures())
        self.assertEqual(docs[2]["components"][-1]["type"],"operating-system")
        output=compare_images(*docs)
        self.assertEqual(output["removed_high"],7)
        self.assertEqual(output["unapproved_package_changes"],0)
        # OS identity change is a hard error, not a pruning improvement.
        docs[3]["components"][-1]["version"]="13.8"
        with self.assertRaises((ValueError,TypeError)):
            compare_images(*docs)

    def test_fails_closed_on_new_cv_es_unexpected_removed_packages_or_missing_evidence(self):
        modifications=[
            lambda f: f[1]["Results"][0]["Vulnerabilities"].append({
                "PkgName":"clamav","InstalledVersion":"1.5.5-1",
                "VulnerabilityID":"CVE-2026-NEW","Severity":"HIGH"}),
            lambda f: f[1]["Results"][0]["Vulnerabilities"].clear(),
            lambda f: f[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda f: f[1]["Results"].clear(),
            lambda f: f[1].update(ArtifactName="other"),
            lambda f: f[3]["components"].append({
                "name":"gpg","type":"library","version":"1.0",
                "purl":"pkg:deb/debian/gpg@1.0?arch=amd64"}),
            lambda f: f[3]["components"].pop(),
            lambda f: f[3]["metadata"]["component"]["properties"][0].update(value="bad"),
            lambda f: f[2]["metadata"]["component"].update(name="other"),
            lambda f: f[4] is None,
        ]
        for index,change in enumerate(modifications[:-1]):
            with self.subTest(index=index):
                data=list(copy.deepcopy(fixtures()))
                change(data)
                with self.assertRaises((ValueError,TypeError)):
                    compare_images(*data)

    def test_comparison_cli_requires_valid_cross_image_reports(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            names=("before-scan","after-scan","before-sbom","after-sbom")
            data=fixtures()
            paths={name:root/(name+".json") for name in names}
            for n,v in zip(names,data[:4]):
                paths[n].write_text(json.dumps(v))
            cmd=["python3","apps/inspector/runtime_prune_comparison.py"]
            for name,path in paths.items():
                cmd.extend(["--"+name,str(path)])
            cmd.extend(["--before-id",data[4],"--after-id",data[5]])
            good=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=8)
            self.assertEqual(good.returncode,2)
            self.assertFalse(json.loads(good.stdout)["release_authorized"])
            paths["after-sbom"].write_text("{}")
            bad=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=8)
            self.assertEqual(bad.returncode,3)
            self.assertEqual(json.loads(bad.stdout)["status"],"error")

    def test_prototype_builder_is_strict_and_does_not_delete_essential_packages(self):
        dockerfile=(ROOT/"apps/inspector/Dockerfile.runtime-pruned-experiment").read_text()
        runner=(ROOT/"apps/inspector/build_runtime_pruned_experiment.sh").read_text()
        checker=(ROOT/"apps/inspector/scan_runtime_pruned_experiment.sh").read_text()
        for required in (
            "FROM folio-civico-inspector:expat-experiment",
            "apt-get -s purge", "apt-get purge -y",
            "dpkg-query", "libgpgme11t64", "libgpgmepp6t64",
            "libfontconfig", "/opt/folio-poppler",
            "/opt/folio-ocr", "ClamAV",
        ):
            self.assertIn(required,dockerfile)
        for bad in ("--allow-remove-essential","apt-get autoremove",
                    "util-linux","bsdutils","mount","login","libmount1",
                    "libblkid1","libuuid1","libsmartcols1"):
            self.assertNotIn(bad,dockerfile)
        for required in ("set -euo pipefail","--network none",
                         "--read-only","--cap-drop ALL","smoke_real_engines.py",
                         "smoke_http_real.py","expat-experiment",
                         "runtime-pruned-experiment"):
            self.assertIn(required,runner)
        for required in ("--format json","--format cyclonedx",
                         "runtime_prune_comparison.py", "docker image inspect"):
            self.assertIn(required,checker)
        for bad in ("--ignore-unfixed","--ignorefile","--skip-db-update",
                    "docker push","wrangler deploy","docker system prune"):
            self.assertNotIn(bad,checker)
            self.assertNotIn(bad,runner)
        for script in ("build_runtime_pruned_experiment.sh","scan_runtime_pruned_experiment.sh"):
            result=subprocess.run(["bash","apps/inspector/"+script,"--bad"],
                                  cwd=ROOT,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,3)


if __name__=="__main__":
    unittest.main()
