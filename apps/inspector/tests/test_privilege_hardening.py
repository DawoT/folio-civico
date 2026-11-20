"""TDD: fail closed when SUID/SGID or util-linux entrypoints survive R1.24."""
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
from privilege_surface import inventory, harden, GUARDED, PRIVILEGED
from privilege_gate import verify_privilege_hardening
from privilege_denial_smoke import RESTRICTED

OLD = "folio-civico-inspector:flat-runtime-experiment"
NEW = "folio-civico-inspector:nonprivileged-experiment"
BEFORE_ID = "sha256:" + "a" * 64
AFTER_ID = "sha256:" + "b" * 64
EMPTY = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"


def fake_evidence():
    before_scan = {"ArtifactName": OLD, "ArtifactType": "container_image",
        "Results": [{"Target": "debian 13.7", "Type": "debian",
                     "Vulnerabilities": [
                         {"Severity": "HIGH", "PkgName": "mount",
                          "InstalledVersion": "2.41.5-0+deb13u1",
                          "VulnerabilityID": "CVE-2026-78408"},
                         {"Severity": "UNKNOWN", "PkgName": "libexpat1",
                          "InstalledVersion": "2.10.0-1+folio1",
                          "VulnerabilityID": "CVE-2026-124317"}]}]}
    after_scan = copy.deepcopy(before_scan)
    after_scan["ArtifactName"] = NEW

    def sbom(name, id):
        return {"bomFormat": "CycloneDX", "specVersion": "1.7",
            "metadata": {"component": {"name": name, "type": "container",
                "properties": [{"name": "aquasecurity:trivy:ImageID", "value": id}]}},
            "components": [{"name": package, "version": version,
                "purl": f"pkg:deb/debian/{package}@{version}", "type": "library"}
                for package, version in [
                    ("mount", "2.41.5-0+deb13u1"),
                    ("libexpat1", "2.10.0-1+folio1"), ("clamav", "1.5.5-1")]],
        }
    def inspect(id, layers):
        return {"Id": id, "Os": "linux", "Architecture": "amd64",
            "RootFS": {"Type": "layers", "Layers": layers},
            "Config": {"User": "65534:65534",
                "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
                "Entrypoint": None, "WorkingDir": "/srv/folio-inspector",
                "ExposedPorts": {"8789/tcp": {}},
                "Env": ["PATH=/opt/folio-poppler/bin:/opt/folio-ocr/bin:/usr/local/bin:/usr/bin:/bin",
                        "TESSDATA_PREFIX=/usr/share/tesseract-ocr/5/tessdata",
                        "CLAMAV_DB_DIR=/opt/clamdb", "FOLIO_INSPECTOR_BIND=0.0.0.0"]}}
    def modes(hardened):
        paths = []
        for name in GUARDED:
            paths.append({
                "path": name, "mode": "0644" if hardened else (
                    "4755" if name in PRIVILEGED else "0755"
                ), "sha256": hashlib.sha256(name.encode()).hexdigest(),
            })
        return {"source": "folio-runtime-privilege-inventory-v1",
                "guarded": paths,
                "special": [] if hardened else list(PRIVILEGED),
                "scan_complete": True}
    return (before_scan, after_scan,
            sbom(OLD, BEFORE_ID), sbom(NEW, AFTER_ID),
            inspect(BEFORE_ID, ["sha256:"+ "c"*64, EMPTY]),
            inspect(AFTER_ID, ["sha256:"+ "d"*64, EMPTY]),
            modes(False), modes(True))


class PrivilegeHardeningTDD(unittest.TestCase):
    def test_fake_runtime_modes_are_removed_and_bytes_not_modified(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            for name in GUARDED:
                file = root / name.lstrip("/")
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"\x7fELF" + name.encode())
                file.chmod(0o4755 if name in PRIVILEGED else 0o755)
            original = inventory(root)
            self.assertEqual(set(original["special"]), set(PRIVILEGED))
            self.assertEqual(len(original["guarded"]), len(GUARDED))
            hardened = harden(root)
            self.assertEqual(hardened["special"], [])
            self.assertTrue(all(x["mode"] == "0644" for x in hardened["guarded"]))
            self.assertEqual(
                {x["path"]:x["sha256"] for x in original["guarded"]},
                {x["path"]:x["sha256"] for x in hardened["guarded"]})
            self.assertEqual(inventory(root), hardened)

    def test_unknown_special_bits_symlinks_and_missing_commands_block(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            for name in GUARDED:
                file = root / name.lstrip("/")
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"\x7fELF" + name.encode())
                file.chmod(0o4755 if name in PRIVILEGED else 0o755)
            surprise = root / "usr/bin/evil"
            surprise.write_bytes(b"\x7fELF")
            surprise.chmod(0o4755)
            with self.assertRaises(ValueError):
                harden(root)
            surprise.unlink()
            target = root/"usr/bin/mount"
            target.unlink()
            target.symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                harden(root)

    def test_differential_scan_never_relabels_known_high_or_grants_release(self):
        result = verify_privilege_hardening(*fake_evidence())
        self.assertEqual(result["status"], "nonprivileged_runtime_release_blocked")
        self.assertEqual(result["disabled_entrypoints"], len(GUARDED))
        self.assertEqual(result["setid_removed"], len(PRIVILEGED))
        self.assertEqual(result["high_before"], 1)
        self.assertEqual(result["high_after"], 1)
        self.assertEqual(result["unknown_before"], 1)
        self.assertEqual(result["unknown_after"], 1)
        self.assertEqual(result["nonempty_parent_layers_reused"], 0)
        self.assertFalse(result["release_authorized"])

    def test_changed_sbom_cve_metadata_or_binary_mode_fails_closed(self):
        changes = [
            lambda a: a[1]["Results"][0]["Vulnerabilities"].pop(),
            lambda a: a[3]["components"].pop(),
            lambda a: a[3]["metadata"]["component"]["properties"][0].update(value="changed"),
            lambda a: a[5]["Config"].update(User="root"),
            lambda a: a[5]["RootFS"]["Layers"].__setitem__(0,"sha256:"+"c"*64),
            lambda a: a[7]["guarded"][0].update(mode="0755"),
            lambda a: a[7]["guarded"][1].update(sha256="0"*64),
            lambda a: a[7].update(special=["/usr/bin/mount"]),
            lambda a: a[7]["guarded"].pop(),
            lambda a: a[6].update(special=[]),
            lambda a: a[5]["Config"]["Env"].append("DEBUG=yes"),
        ]
        for i,change in enumerate(changes):
            with self.subTest(i=i):
                a = list(copy.deepcopy(fake_evidence()))
                change(a)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    verify_privilege_hardening(*a)

    def test_kernel_denial_smoke_covers_the_exact_guarded_inventory(self):
        self.assertEqual(set(RESTRICTED), set(GUARDED))
        self.assertEqual(len(RESTRICTED), len(GUARDED))

    def test_builder_runs_offline_smokes_and_scanner_never_ignores_advisories(self):
        files = {
            "docker": (ROOT/"apps/inspector/Dockerfile.nonprivileged-experiment").read_text(),
            "build": (ROOT/"apps/inspector/build_nonprivileged_experiment.sh").read_text(),
            "scan": (ROOT/"apps/inspector/scan_nonprivileged_experiment.sh").read_text(),
        }
        for x in ("FROM folio-civico-inspector:flat-runtime-experiment AS hardener",
                  "FROM scratch", "COPY --from=hardener / /",
                  "privilege_surface.py", "--apply", "USER 65534:65534"):
            self.assertIn(x, files["docker"])
        for x in ("--network none", "--read-only", "--cap-drop ALL",
                  "smoke_real_engines.py", "smoke_http_real.py",
                  "privilege_denial_smoke.py"):
            self.assertIn(x,files["build"])
        for x in ("--format json","--format cyclonedx","docker image inspect",
                  "privilege_gate.py","privilege_surface.py"):
            self.assertIn(x,files["scan"])
        for key in ("docker push","wrangler deploy","--ignorefile","--ignore-unfixed",
                    "--skip-db-update","--allow-remove-essential"):
            for content in files.values():
                self.assertNotIn(key,content)
        for script in ("build_nonprivileged_experiment.sh",
                       "scan_nonprivileged_experiment.sh"):
            cmd = subprocess.run(["bash","apps/inspector/"+script,"--bad"],
                cwd=ROOT, capture_output=True, text=True, timeout=5)
            self.assertEqual(cmd.returncode,3)


if __name__=="__main__":
    unittest.main()
