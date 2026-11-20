"""TDD R1.26: Talos-signed ClamAV package must match installed native bytes."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
from clamav_signed_gate import verify_signed_vendor_evidence, CVES, MEDIUM_CVES, IMAGE
from clamav_vendor_evidence import code_files_from_tar, TALOS_FINGERPRINT
from clamav_runtime_inventory import _code_digest

VERSION = "1.5.5-1"
IMAGE_ID = "sha256:" + "a" * 64
FILES = [
    {"path": "/usr/local/bin/clamscan", "sha256": "b" * 64},
    {"path": "/usr/local/lib/libclamav.so.12.1.0", "sha256": "c" * 64},
    {"path": "/usr/local/lib/libclamav_rust.a", "sha256": "e" * 64},
    {"path": "/usr/local/sbin/clamd", "sha256": "f" * 64},
]


def fixtures():
    scan = {"ArtifactName": IMAGE, "ArtifactType": "container_image",
            "Results": [{"Target": "debian 13.7", "Type": "debian",
             "Vulnerabilities": [
                 {"PkgName": "clamav", "InstalledVersion": VERSION,
                  "Severity": "HIGH", "VulnerabilityID": cve}
                 for cve in CVES
             ] + [
                 {"PkgName": "clamav", "InstalledVersion": VERSION,
                  "Severity": "MEDIUM", "VulnerabilityID": cve}
                 for cve in MEDIUM_CVES
             ] + [{
                 "PkgName": "libexpat1", "InstalledVersion": "2.10.0-1+folio1",
                 "Severity": "UNKNOWN", "VulnerabilityID": "CVE-2026-124317",
             }]}]}
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.7",
            "metadata": {"component": {"name": IMAGE, "type": "container",
                "properties": [{"name": "aquasecurity:trivy:ImageID",
                                "value": IMAGE_ID}]}},
            "components": [
                {"name": "clamav", "type": "library", "version": VERSION,
                 "purl": "pkg:deb/debian/clamav@1.5.5-1?arch=amd64"},
                {"name": "libexpat1", "type": "library",
                 "version": "2.10.0-1+folio1",
                 "purl": "pkg:deb/debian/libexpat1@2.10.0-1%2Bfolio1?arch=amd64"},
            ]}
    vendor = {
        "source": "talos-detached-debian-package-v1",
        "signature_verified": True,
        "signer_fingerprint": TALOS_FINGERPRINT,
        "package": "clamav",
        "package_version": VERSION, "architecture": "amd64",
        "signed_deb_sha256": "d" * 64,
        "files": copy.deepcopy(FILES),
        "vendor_patched_floor": "1.5.3",
        "release_authorized": False,
    }
    runtime = {
        "source": "folio-clamav-installed-native-v1",
        "package": "clamav", "package_version": VERSION,
        "architecture": "amd64", "clamscan_version": "ClamAV 1.5.5",
        "dpkg_verify_clean": True,
        "shared_library_linked": True,
        "files": copy.deepcopy(FILES),
        "release_authorized": False,
    }
    return (scan, sbom, vendor, runtime, IMAGE_ID)


class SignedClamAVTDD(unittest.TestCase):
    def test_seven_advisories_remain_and_all_installed_code_matches_vendor(self):
        report=verify_signed_vendor_evidence(*fixtures())
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["scanner_gate"],"blocked")
        self.assertEqual(report["clamav_high_still_reported"],7)
        self.assertEqual(report["clamav_medium_still_reported"],6)
        self.assertEqual(report["vendor_signed_files_matched"],4)
        self.assertEqual(report["vendor_patched_floor"],"1.5.3")
        self.assertEqual(report["other_unknown_still_blocking"],1)

    def test_missing_or_changed_cve_signer_sbom_elf_and_dpkg_fails_closed(self):
        mutations=[
            lambda a: a[0]["Results"][0]["Vulnerabilities"].pop(0),
            lambda a: a[0]["Results"][0]["Vulnerabilities"][0].update(Severity="MEDIUM"),
            lambda a: a[0]["Results"][0]["Vulnerabilities"][0].update(InstalledVersion="1.5.2"),
            lambda a: a[0]["Results"].clear(),
            lambda a: a[1]["metadata"]["component"]["properties"][0].update(value="bad"),
            lambda a: a[1]["components"][0].update(version="1.5.3"),
            lambda a: a[2].update(signature_verified=False),
            lambda a: a[2].update(signer_fingerprint="0"*40),
            lambda a: a[2].update(signed_deb_sha256="bad"),
            lambda a: a[2]["files"][0].update(sha256="0"*64),
            lambda a: a[2]["files"].pop(),
            lambda a: a[3]["files"][1].update(sha256="0"*64),
            lambda a: a[3]["files"].append({"path":"/usr/local/bin/other","sha256":"d"*64}),
            lambda a: a[3].update(dpkg_verify_clean=False),
            lambda a: a[3].update(shared_library_linked=False),
            lambda a: a[3].update(release_authorized=True),
            lambda a: a[2].update(vendor_patched_floor="1.5.2"),
            lambda a: a[3].update(clamscan_version="ClamAV 1.5.3"),
            lambda a: a[4] + "wrong",
        ]
        for i,mutate in enumerate(mutations[:-1]):
            with self.subTest(i=i):
                values=list(copy.deepcopy(fixtures()))
                mutate(values)
                with self.assertRaises((ValueError,TypeError,KeyError)):
                    verify_signed_vendor_evidence(*values)

    def test_cannot_accept_ambiguous_package_entries_or_duplicate_advisories(self):
        data=list(copy.deepcopy(fixtures()))
        data[0]["Results"][0]["Vulnerabilities"].append(
            dict(data[0]["Results"][0]["Vulnerabilities"][0])
        )
        with self.assertRaises(ValueError):
            verify_signed_vendor_evidence(*data)
        data=list(copy.deepcopy(fixtures()))
        data[1]["components"].append(copy.deepcopy(data[1]["components"][0]))
        with self.assertRaises(ValueError):
            verify_signed_vendor_evidence(*data)
        data=list(copy.deepcopy(fixtures()))
        data[2]["files"].append(copy.deepcopy(data[2]["files"][0]))
        with self.assertRaises(ValueError):
            verify_signed_vendor_evidence(*data)

    def test_tar_stream_hashes_only_elf_or_static_archives_no_path_writes(self):
        elf=b"\x7fELF" + b"A" * 19
        archive=b"!<arch>\n" + b"J" * 15
        files={
            "./usr/local/bin/clamscan": elf,
            "./usr/local/lib/libclamav.so.12.1.0": elf,
            "./usr/local/lib/libclamav_rust.a": archive,
            "./usr/local/sbin/clamd": elf,
            "./usr/local/share/doc/readme.html": b"no executable",
            "./usr/local/lib/not-code.txt": b"not compiled",
        }
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode="w") as writer:
            for name, raw in files.items():
                info=tarfile.TarInfo(name=name);info.size=len(raw)
                writer.addfile(info, io.BytesIO(raw))
        output.seek(0)
        with tarfile.open(fileobj=output,mode="r|") as reader:
            result=code_files_from_tar(reader)
        self.assertEqual(result, [
            {"path":"/usr/local/bin/clamscan", "sha256":hashlib.sha256(elf).hexdigest()},
            {"path":"/usr/local/lib/libclamav.so.12.1.0", "sha256":hashlib.sha256(elf).hexdigest()},
            {"path":"/usr/local/lib/libclamav_rust.a", "sha256":hashlib.sha256(archive).hexdigest()},
            {"path":"/usr/local/sbin/clamd", "sha256":hashlib.sha256(elf).hexdigest()},
        ])
        self.assertIsNone(_code_digest(io.BytesIO(b"not a program"), "readme.txt"))

    def test_cli_always_blocked_and_vendor_script_has_no_release_bypass(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            cmd=["python3","apps/inspector/clamav_signed_gate.py"]
            for name,data in zip(("scan","sbom","vendor","runtime"),fixtures()[:4]):
                path=root/(name+".json");path.write_text(json.dumps(data))
                cmd.extend(["--"+name,str(path)])
            cmd.extend(["--image-id",IMAGE_ID])
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,2)
            self.assertFalse(json.loads(p.stdout)["release_authorized"])
            (root/"vendor.json").write_text("{}")
            p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,3)
        script=(ROOT/"apps/inspector/scan_clamav_signed_vendor.sh").read_text()
        vendor=(ROOT/"apps/inspector/clamav_vendor_evidence.py").read_text()
        runtime=(ROOT/"apps/inspector/clamav_runtime_inventory.py").read_text()
        for t in ("--network none","--read-only","--cap-drop ALL",
                  "docker image inspect","--format json","--format cyclonedx",
                  "clamav_vendor_evidence.py","clamav_runtime_inventory.py",
                  "clamav_signed_gate.py"):
            self.assertIn(t,script)
        for t in ("5BADCA2665EF59DCF8A23D8B707F0DB480836771",
                  "gpg","--verify","--status-fd", "dpkg-deb",
                  "TemporaryDirectory","sha256"):
            self.assertIn(t,vendor)
        for t in ("dpkg", "-V","clamscan","--version","libclamav.so.12"):
            self.assertIn(t,runtime)
        for txt in (script,vendor):
            for bad in ("--ignorefile","--skip-db-update","--ignore-unfixed",
                        "docker push","wrangler deploy","--allow-unauthenticated"):
                self.assertNotIn(bad,txt)
        p=subprocess.run(["bash","apps/inspector/scan_clamav_signed_vendor.sh","--bad"],
                         cwd=ROOT,capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode,3)


if __name__=="__main__":
    unittest.main()
