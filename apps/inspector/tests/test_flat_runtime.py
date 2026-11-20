"""R1.23 TDD: flatten the runtime without hiding CVEs or native source debt."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
from flat_runtime_comparison import verify_flattening, REMOVED_PACKAGES

BEFORE = "folio-civico-inspector:headless-pruned-experiment"
AFTER = "folio-civico-inspector:flat-runtime-experiment"
BEFORE_ID = "sha256:" + "a" * 64
AFTER_ID = "sha256:" + "b" * 64
REMOVED = ("pinentry-curses", "libncursesw6")


def fake_metadata(image: str, digest: str, layers: int):
    return {"Id": digest, "Os": "linux", "Architecture": "amd64",
            "RootFS": {"Type": "layers", "Layers": [f"sha256:{i:064x}" for i in range(layers)]},
            "Config": {
                "User": "65534:65534",
                "Env": [
                    "PATH=/opt/folio-poppler/bin:/opt/folio-ocr/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG=C.UTF-8", "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
                    "TESSDATA_PREFIX=/usr/share/tesseract-ocr/5/tessdata",
                    "CLAMAV_DB_DIR=/opt/clamdb", "FOLIO_INSPECTOR_BIND=0.0.0.0", "PYTHONUNBUFFERED=1"],
                "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
                "WorkingDir": "/srv/folio-inspector", "Entrypoint": None,
                "ExposedPorts": {"8789/tcp": {}}, "Volumes": None,
                "Healthcheck": None, "StopSignal": None,
            }}


def fake_scan(image: str, pruned: bool):
    issues = [
        {"Severity": "HIGH", "VulnerabilityID": "CVE-2025-69720",
         "PkgName": "libncursesw6", "InstalledVersion": "6.5+20250216-2"},
        {"Severity": "MEDIUM", "VulnerabilityID": "CVE-2025-00001",
         "PkgName": "pinentry-curses", "InstalledVersion": "1.0"},
        {"Severity": "HIGH", "VulnerabilityID": "CVE-2026-20213",
         "PkgName": "clamav", "InstalledVersion": "1.5.5-1"},
        {"Severity": "UNKNOWN", "VulnerabilityID": "CVE-2026-124317",
         "PkgName": "libexpat1", "InstalledVersion": "2.10.0-1+folio1"},
    ]
    if pruned:
        issues = issues[2:]
    return {"ArtifactName": image, "ArtifactType": "container_image",
            "Results": [{"Target": "debian 13.7", "Type": "debian",
                         "Vulnerabilities": issues}]}


def fake_sbom(image: str, digest: str, pruned: bool):
    names = ["clamav", "libexpat1", "util-linux", "ncurses-bin", "qpdf"]
    if not pruned:
        names += list(REMOVED)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "metadata": {"component": {
            "name": image, "type": "container",
            "properties": [{"name": "aquasecurity:trivy:ImageID", "value": digest}]}},
        "components": [
            {"type": "library", "name": n,
             "version": "2.10.0-1+folio1" if n == "libexpat1" else "1.0",
             "purl": f"pkg:deb/debian/{n}@1.0?arch=amd64"} for n in names
        ] + [{"type": "operating-system", "name": "debian", "version": "13.7"}],
    }


def fake_native():
    return {
        "source": "folio-local-elf-provenance-v1",
        "components": [{"name": "poppler", "library_sha256": "a" * 64},
                       {"name": "tesseract", "library_sha256": "b" * 64}],
        "source_cve_coverage": "unassessed",
    }


def fake_expat():
    return {"source": "folio-expat-local-provenance-v1",
            "package": "libexpat1", "package_version": "2.10.0-1+folio1",
            "library_sha256": "c" * 64, "patch_sha256": "d" * 64,
            "native_cve_coverage": "unassessed"}


def fixtures():
    after_meta = fake_metadata(AFTER, AFTER_ID, 2)
    after_meta["Config"]["Env"] = [
        x for x in after_meta["Config"]["Env"] if not x.startswith("GPG_KEY=")
    ]
    after_meta["RootFS"]["Layers"] = [
        "sha256:" + "c" * 64,
        "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
    ]
    return (
        fake_scan(BEFORE, False), fake_scan(AFTER, True),
        fake_sbom(BEFORE, BEFORE_ID, False), fake_sbom(AFTER, AFTER_ID, True),
        fake_metadata(BEFORE, BEFORE_ID, 20),
        after_meta,
        fake_native(), fake_native(), fake_expat(), fake_expat(),
    )


class FlatRuntimeTests(unittest.TestCase):
    def test_exact_two_package_removal_with_one_layer_and_no_native_changes(self):
        self.assertEqual(set(REMOVED_PACKAGES), set(REMOVED))
        result = verify_flattening(*fixtures())
        self.assertEqual(result["status"], "flattened_runtime_release_blocked")
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["after_layers"], 2)
        self.assertEqual(result["nonempty_parent_layers_reused"], 0)
        self.assertEqual(result["before_layers"], 20)
        self.assertEqual(result["high_before"], 2)
        self.assertEqual(result["high_after"], 1)
        self.assertEqual(result["unknown_before"], 1)
        self.assertEqual(result["unknown_after"], 1)
        self.assertEqual(result["removed_high"], 1)
        self.assertEqual(result["removed_packages"], sorted(REMOVED))
        self.assertTrue(result["native_provenance_unchanged"])
        self.assertEqual(result["removed_unused_env"], ["GPG_KEY"])

    def test_inconsistent_config_cves_sbom_or_provenance_fail_closed(self):
        changes = [
            lambda v: v[5]["RootFS"]["Layers"].append("sha256:" + "f" * 64),
            lambda v: v[5]["RootFS"]["Layers"].__setitem__(0,v[4]["RootFS"]["Layers"][0]),
            lambda v: v[5]["RootFS"]["Layers"].__setitem__(1,"sha256:" + "e" * 64),
            lambda v: v[5]["Config"].update(User="root"),
            lambda v: v[5]["Config"]["Env"].append("FOLIO_DEBUG=1"),
            lambda v: v[5]["Config"]["Env"].append("GPG_KEY=attacker"),
            lambda v: v[4]["Config"]["Env"].remove("GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305"),
            lambda v: v[5]["Config"].update(Entrypoint=["/bin/sh"]),
            lambda v: v[4].update(Id="sha256:" + "f" * 64),
            lambda v: v[3]["metadata"]["component"]["properties"][0].update(value="bad"),
            lambda v: v[3]["components"].append({
                "type": "library", "name": "libncursesw6", "version": "1.0",
                "purl": "pkg:deb/debian/libncursesw6@1.0?arch=amd64"}),
            lambda v: v[3]["components"].pop(),
            lambda v: v[1]["Results"][0]["Vulnerabilities"].clear(),
            lambda v: v[0]["Results"][0]["Vulnerabilities"].append({
                "Severity": "HIGH", "VulnerabilityID": "CVE-2026-FAKE",
                "PkgName": "libncursesw6", "InstalledVersion": "6.5+20250216-2"}),
            lambda v: v[7]["components"][0].update(library_sha256="f" * 64),
            lambda v: v[9].update(patch_sha256="f" * 64),
            lambda v: v[5].update(Architecture="arm64"),
            lambda v: v[0].update(Results=[]),
        ]
        for i, mutate in enumerate(changes):
            with self.subTest(case=i):
                data=list(copy.deepcopy(fixtures()))
                mutate(data)
                with self.assertRaises((ValueError, TypeError)):
                    verify_flattening(*data)

    def test_cli_distinguishes_blocked_evidence_from_malformed(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            names=("before-scan","after-scan","before-sbom","after-sbom",
                   "before-inspect","after-inspect","before-native","after-native",
                   "before-expat","after-expat")
            cmd=["python3", "apps/inspector/flat_runtime_comparison.py"]
            for name, body in zip(names, fixtures()):
                file=root/f"{name}.json"
                file.write_text(json.dumps(body))
                cmd.extend(["--"+name,str(file)])
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,2)
            self.assertFalse(json.loads(p.stdout)["release_authorized"])
            (root/"after-inspect.json").write_text("{}")
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,3)
            self.assertEqual(json.loads(p.stdout)["status"],"error")

    def test_scratch_image_builder_and_offline_differential_enforce_release_block(self):
        dockerfile=(ROOT/"apps/inspector/Dockerfile.flat-runtime-experiment").read_text()
        build=(ROOT/"apps/inspector/build_flat_runtime_experiment.sh").read_text()
        scan=(ROOT/"apps/inspector/scan_flat_runtime_experiment.sh").read_text()
        for token in (
            "FROM folio-civico-inspector:headless-pruned-experiment AS pruner",
            "apt-get -s purge", "apt-get purge -y",
            "len(removed)==2", "pinentry-curses", "libncursesw6",
            "FROM scratch", "COPY --from=pruner / /", "USER 65534:65534",
            "CLAMAV_DB_DIR", "TESSDATA_PREFIX",
            "/opt/folio-poppler", "/opt/folio-ocr",
            "ClamAV 1.5.5", "ncurses-bin", "qpdf",
        ):
            self.assertIn(token,dockerfile)
        for bad in ("apt-get autoremove","--allow-remove-essential","dpkg --force",
                    "ENV GPG_KEY="):
            self.assertNotIn(bad,dockerfile)
        for token in ("--network none", "--read-only", "--cap-drop ALL",
                      "smoke_real_engines.py", "smoke_http_real.py",
                      "headless-pruned-experiment", "flat-runtime-experiment"):
            self.assertIn(token,build)
        for token in ("--format json", "--format cyclonedx", "docker image inspect",
                      "source_inventory.py", "expat_runtime_inventory.py",
                      "flat_runtime_comparison.py"):
            self.assertIn(token,scan)
        for file in (build,scan):
            for bad in ("--skip-db-update","--ignore-unfixed","--ignorefile",
                        "docker push","wrangler deploy","docker system prune"):
                self.assertNotIn(bad,file)
        for script in ("build_flat_runtime_experiment.sh",
                       "scan_flat_runtime_experiment.sh"):
            p=subprocess.run(["bash","apps/inspector/"+script,"--bad"],
                             cwd=ROOT,capture_output=True,text=True,timeout=5)
            self.assertEqual(p.returncode,3)


if __name__=="__main__":
    unittest.main()
