"""R1.27 TDD: retain clamscan and deny ten unnecessary signed ClamAV CLIs.

All package vulnerabilities and native bytes remain present. This image
remains non-deployable and must not gain a VEX or scanner suppression.
"""
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
from clamav_cli_surface import inventory, harden, DENY, KEEP, CLI_PATHS
from clamav_cli_gate import verify_cli_reduction, BEFORE, AFTER
from clamav_cli_denial_smoke import DENY as KERNEL_DENY, KEEP as KERNEL_KEEP
from clamav_cli_native_inventory import DENY as NATIVE_DENY, KEEP as NATIVE_KEEP
from clamav_signed_gate import CVES, MEDIUM_CVES
from clamav_vendor_evidence import TALOS_FINGERPRINT

ID_BEFORE = "sha256:" + "a" * 64
ID_AFTER = "sha256:" + "b" * 64
EMPTY = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
VERSION = "1.5.5-1"
NATIVE = [
    {"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest()}
    for path in sorted((
        "/usr/local/bin/clamscan",
        "/usr/local/lib/libclamav.so.12.1.0",
        "/usr/local/lib/libclamav_rust.a",
        "/usr/local/sbin/clamd",
    ))
]


def fixture():
    def scan(tag):
        return {
            "ArtifactName": tag, "ArtifactType": "container_image",
            "Results": [{"Target": "debian 13.7", "Type": "debian", "Vulnerabilities": [
                {"PkgName": "clamav", "InstalledVersion": VERSION,
                 "VulnerabilityID": cve, "Severity": severity}
                for cve, severity in (
                    [(c, "HIGH") for c in CVES]
                    + [(c, "MEDIUM") for c in MEDIUM_CVES]
                )
            ] + [{"PkgName": "libexpat1", "InstalledVersion": "2.10.0-1+folio1",
                  "VulnerabilityID": "CVE-2026-124317", "Severity": "UNKNOWN"}]}],
        }

    def sbom(tag, identity):
        return {
            "bomFormat": "CycloneDX",
            "metadata": {"component": {"type": "container", "name": tag,
                "properties": [{"name": "aquasecurity:trivy:ImageID", "value": identity}]}},
            "components": [
                {"name": "clamav", "type": "library", "version": VERSION,
                 "purl": "pkg:deb/debian/clamav@1.5.5-1?arch=amd64"},
                {"name": "libexpat1", "type": "library", "version": "2.10.0-1+folio1",
                 "purl": "pkg:deb/debian/libexpat1@2.10.0-1%2Bfolio1?arch=amd64"},
            ],
        }
    def inspect(identity, layer):
        return {
            "Id": identity, "Os": "linux", "Architecture": "amd64",
            "RootFS": {"Type": "layers", "Layers": [layer, EMPTY]},
            "Config": {
                "User": "65534:65534", "Entrypoint": None,
                "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
                "WorkingDir": "/srv/folio-inspector",
                "ExposedPorts": {"8789/tcp": {}},
                "Env": ["PATH=/opt/folio-poppler/bin:/opt/folio-ocr/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "CLAMAV_DB_DIR=/opt/clamdb", "FOLIO_INSPECTOR_BIND=0.0.0.0"],
            },
        }
    def cli(limited):
        return {
            "source": "folio-clamav-cli-mode-v2", "scan_complete": True,
            "state": "limited" if limited else "baseline",
            "package": "clamav", "package_version": VERSION,
            "absent": sorted(DENY) if limited else [],
            "files": [
                {"path": p, "mode": "0755",
                 "uid": 0, "sha256": hashlib.sha256(p.encode()).hexdigest()}
                for p in CLI_PATHS if not limited or p == KEEP
            ],
        }
    vendor = {
        "source": "talos-detached-debian-package-v1",
        "signature_verified": True, "signer_fingerprint": TALOS_FINGERPRINT,
        "package": "clamav", "package_version": VERSION, "architecture": "amd64",
        "signed_deb_sha256": "d" * 64, "files": copy.deepcopy(NATIVE),
        "vendor_patched_floor": "1.5.3", "release_authorized": False,
    }
    def native():
        return {
            "source": "folio-clamav-installed-native-v1",
            "package": "clamav", "package_version": VERSION, "architecture": "amd64",
            "clamscan_version": "ClamAV 1.5.5",
            "dpkg_verify_clean": True, "shared_library_linked": True,
            "files": copy.deepcopy(NATIVE), "release_authorized": False,
        }
    def native_minimal():
        return {
            "source": "folio-clamav-minimal-native-v1",
            "package": "clamav", "package_version": VERSION,
            "architecture": "amd64", "clamscan_version": "ClamAV 1.5.5",
            "expected_absent": sorted(DENY),
            "dpkg_verified_expected_removals": True,
            "shared_library_linked": True,
            "files": [copy.deepcopy(row) for row in NATIVE if row["path"] not in DENY],
            "release_authorized": False,
        }
    return (scan(BEFORE), scan(AFTER),
            sbom(BEFORE, ID_BEFORE), sbom(AFTER, ID_AFTER),
            inspect(ID_BEFORE, "sha256:" + "c" * 64),
            inspect(ID_AFTER, "sha256:" + "e" * 64),
            cli(False), cli(True), native(), native_minimal(), vendor)


class ClamAVCLITests(unittest.TestCase):
    def test_source_and_target_modes_allow_only_clamscan_without_changing_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for cli in CLI_PATHS:
                item = root / cli.lstrip("/")
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_bytes(b"\x7fELF" + cli.encode())
                item.chmod(0o755)
            source = inventory(root, listed_paths=CLI_PATHS, package_version=VERSION)
            self.assertEqual([row["mode"] for row in source["files"]], ["0755"] * 11)
            target = harden(root, listed_paths=CLI_PATHS, package_version=VERSION)
            self.assertEqual([row["path"] for row in target["files"]], [KEEP])
            self.assertEqual(target["absent"], sorted(DENY))
            self.assertTrue(all(not (root/p.lstrip("/")).exists() for p in DENY))
            self.assertEqual(
                next(x["sha256"] for x in source["files"] if x["path"] == KEEP),
                target["files"][0]["sha256"],
            )
            self.assertEqual(inventory(root, listed_paths=CLI_PATHS, package_version=VERSION), target)

    def test_extra_missing_symlink_and_wrong_mode_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for cli in CLI_PATHS:
                item = root / cli.lstrip("/")
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_bytes(b"\x7fELF" + cli.encode())
                item.chmod(0o755)
            invalid = [*CLI_PATHS, "/usr/local/bin/unexpected-clamav"]
            with self.assertRaises(ValueError):
                inventory(root, listed_paths=invalid, package_version=VERSION)
            with self.assertRaises(ValueError):
                inventory(root, listed_paths=CLI_PATHS[:-1], package_version=VERSION)
            keep = root / KEEP.lstrip("/")
            keep.unlink()
            keep.symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                harden(root, listed_paths=CLI_PATHS, package_version=VERSION)
            keep.unlink()
            keep.write_bytes(b"\x7fELF")
            keep.chmod(0o600)
            with self.assertRaises(ValueError):
                harden(root, listed_paths=CLI_PATHS, package_version=VERSION)

    def test_vendor_signed_16_files_sbom_and_every_cve_remain_blocked(self):
        result = verify_cli_reduction(*fixture())
        self.assertEqual(result["status"], "clamav_cli_limited_release_blocked")
        self.assertEqual(result["disabled_clamav_entrypoints"], 10)
        self.assertEqual(result["allowlisted_clamav_entrypoints"], ["clamscan"])
        self.assertEqual(result["native_files_preserved"], len(NATIVE)-1)
        self.assertEqual(result["native_files_physically_removed"],1)
        self.assertEqual(result["package_manifest_expected_missing"],10)
        self.assertEqual(result["high_before"], result["high_after"])
        self.assertEqual(result["unknown_before"], result["unknown_after"])
        self.assertFalse(result["release_authorized"])

    def test_tampered_signed_package_native_hash_cve_permissions_or_oci_fails(self):
        changes = [
            lambda x: x[0]["Results"][0]["Vulnerabilities"].pop(),
            lambda x: x[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda x: x[3]["components"][0].update(version="1.5.4-1"),
            lambda x: x[3]["metadata"]["component"]["properties"][0].update(value="spoofed"),
            lambda x: x[5]["Config"].update(User="root"),
            lambda x: x[5]["RootFS"]["Layers"].__setitem__(0, "sha256:" + "c" * 64),
            lambda x: x[7]["files"][0].update(mode="0644"),
            lambda x: x[7]["files"][-1].update(sha256="0" * 64),
            lambda x: x[6]["files"][0].update(mode="0644"),
            lambda x: x[7]["files"].pop(),
            lambda x: x[7]["absent"].pop(),
            lambda x: x[9].update(dpkg_verified_expected_removals=False),
            lambda x: x[9]["expected_absent"].pop(),
            lambda x: x[9]["files"].pop(),
            lambda x: x[9]["files"][0].update(sha256="0" * 64),
            lambda x: x[10].update(signature_verified=False),
            lambda x: x[10].update(signer_fingerprint="0" * 40),
            lambda x: x[10].update(signed_deb_sha256="bad"),
        ]
        for i, mut in enumerate(changes):
            with self.subTest(i=i):
                case = copy.deepcopy(fixture())
                mut(case)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    verify_cli_reduction(*case)

    def test_kernel_denial_probe_uses_exact_package_owned_allowlist(self):
        self.assertEqual(set(KERNEL_DENY), set(DENY))
        self.assertEqual(KERNEL_KEEP, KEEP)
        self.assertEqual(set(NATIVE_DENY), set(DENY))
        self.assertEqual(NATIVE_KEEP, KEEP)
        self.assertEqual(set(KERNEL_DENY) | {KERNEL_KEEP}, set(CLI_PATHS))

    def test_build_scan_and_kernel_denial_smokes_cannot_publish_or_suppress(self):
        dockerfile=(ROOT/"apps/inspector/Dockerfile.clamav-cli-experiment").read_text()
        build=(ROOT/"apps/inspector/build_clamav_cli_experiment.sh").read_text()
        scan=(ROOT/"apps/inspector/scan_clamav_cli_experiment.sh").read_text()
        for word in ("FROM folio-civico-inspector:nonprivileged-experiment AS hardener",
                     "FROM scratch", "COPY --from=hardener / /",
                     "clamav_cli_surface.py", "--apply", "USER 65534:65534"):
            self.assertIn(word, dockerfile)
        for word in ("--network none", "--read-only", "--cap-drop ALL",
                     "smoke_real_engines.py", "smoke_http_real.py",
                     "clamav_cli_denial_smoke.py"):
            self.assertIn(word, build)
        for word in ("--format json", "--format cyclonedx",
                     "clamav_vendor_evidence.py", "clamav_runtime_inventory.py",
                     "clamav_cli_native_inventory.py", "clamav_cli_gate.py",
                     "docker image inspect"):
            self.assertIn(word, scan)
        for file in (dockerfile,build,scan):
            for forbidden in ("docker push","wrangler deploy","--ignorefile",
                              "--ignore-unfixed","--skip-db-update",
                              "--allow-remove-essential"):
                self.assertNotIn(forbidden,file)
        for script in ("build_clamav_cli_experiment.sh",
                       "scan_clamav_cli_experiment.sh"):
            proc=subprocess.run(["bash","apps/inspector/"+script,"--bad"],
                                cwd=ROOT,capture_output=True,text=True,timeout=5)
            self.assertEqual(proc.returncode,3)


if __name__=="__main__":
    unittest.main()
