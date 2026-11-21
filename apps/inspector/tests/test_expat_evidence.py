"""TDD: experiment evidence must be tied to one immutable image, not a CVE waiver."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from expat_evidence import verify_evidence
from expat_runtime_inventory import gather

IMAGE = "folio-civico-inspector:expat-experiment"
IMAGE_ID = "sha256:" + "a" * 64
EX_VERSION = "2.10.0-1+folio1"
PATCH_SHA = "0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3"
SOURCE_SHA = "b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f"
TOOLS = ("pdfinfo", "pdftotext", "pdftoppm", "pdfdetach", "pdfattach")


def fixtures():
    scan = {
        "ArtifactName": IMAGE, "ArtifactType": "container_image",
        "Results": [{"Target": IMAGE + " (debian 13.7)", "Type": "debian",
                     "Vulnerabilities": [{"Severity": "HIGH",
                        "VulnerabilityID": "CVE-2026-124317", "PkgName": "libexpat1",
                        "InstalledVersion": EX_VERSION}]}],
    }
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "metadata": {"component": {"name": IMAGE, "type": "container",
                    "properties": [{"name": "aquasecurity:trivy:ImageID",
                                    "value": IMAGE_ID}]}},
        "components": [{"name": "libexpat1", "version": EX_VERSION, "type": "library",
                        "purl": "pkg:deb/debian/libexpat1@2.10.0-1%2Bfolio1?arch=amd64&distro=debian-13.7"},
                       {"name": "qpdf", "version": "12.0", "type": "library"}],
    }
    native = {
        "source": "folio-local-elf-provenance-v1", "mode": "experiment",
        "source_cve_coverage": "unassessed", "components": [],
    }
    for name, version in (("tesseract", "5.5.4"), ("poppler", "25.03.0-5+deb13u4")):
        native["components"].append({
            "name": name, "version": version,
            "executable_sha256": "a" * 64, "library_sha256": "b" * 64,
            "provenance_sha256": "c" * 64,
            "tool_sha256": {x: "d" * 64 for x in (*TOOLS, "pdfimages")} if name == "poppler" else {},
            "model_sha256": {"eng": "e" * 64, "spa": "f" * 64} if name == "tesseract" else {},
            "cve_assessment": "required", "automated_cve_coverage": "not_verified",
        })
    expat = {
        "source": "folio-expat-local-provenance-v1",
        "package": "libexpat1", "package_version": EX_VERSION,
        "library_sha256": "f" * 64, "provenance_sha256": "0" * 64,
        "source_sha256": SOURCE_SHA, "patch_sha256": PATCH_SHA,
        "runtime_version": "expat_2.10.0",
        "linked_poppler_tools": list(TOOLS),
        "xmlwf_present": False,
        "native_cve_coverage": "unassessed",
    }
    return scan, sbom, native, expat


class ExpatEvidenceGateTests(unittest.TestCase):
    def test_consistent_vulnerability_sbom_and_three_native_provenances_still_block(self):
        report = verify_evidence(*fixtures(), IMAGE_ID, IMAGE)
        self.assertEqual(report["status"], "evidence_valid_release_blocked")
        self.assertFalse(report["release_authorized"])
        self.assertEqual(report["image_id"], IMAGE_ID)
        self.assertEqual(report["sbom_components"], 2)
        self.assertEqual(report["source_components_unassessed"], 3)
        self.assertEqual(report["selected_native_cves_unassessed"], 24)
        self.assertEqual(report["expat_library_sha256"], "f" * 64)
        self.assertEqual(report["expat_patch_sha256"], PATCH_SHA)
        self.assertTrue(report["advisory_coverage_incomplete"])
        self.assertEqual(report["blocking_scan_high"], 1)

    def test_tampering_image_version_sbom_or_source_evidence_fails_closed(self):
        for index, change in enumerate((
            lambda a: a[0].update(ArtifactName="other"),
            lambda a: a[1]["metadata"]["component"].update(name="other"),
            lambda a: a[1]["metadata"]["component"]["properties"][0].update(value="sha256:"+"b"*64),
            lambda a: a[1]["components"][0].update(version="2.9.0"),
            lambda a: a[1]["components"][0].update(purl="pkg:deb/debian/other@2.10.0"),
            lambda a: a[1].update(components=[]),
            lambda a: a[2]["components"][0].update(library_sha256="malformed"),
            lambda a: a[2].update(source_cve_coverage="verified"),
            lambda a: a[3].update(patch_sha256="f"*64),
            lambda a: a[3].update(library_sha256="broken"),
            lambda a: a[3].update(xmlwf_present=True),
            lambda a: a[3].update(linked_poppler_tools=["pdfinfo"]),
            lambda a: a[3].update(package_version="2.9.0"),
            lambda a: a[0]["Results"][0]["Vulnerabilities"][0].update(InstalledVersion="2.9.0"),
            lambda a: a[0].update(Results=[]),
        )):
            with self.subTest(case=index):
                args=list(copy.deepcopy(fixtures()))
                change(args)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    verify_evidence(*args, IMAGE_ID, IMAGE)

    def test_accepted_scan_with_zero_findings_is_never_a_release_approval(self):
        args=list(fixtures())
        args[0]["Results"][0]["Vulnerabilities"]=[]
        report=verify_evidence(*args, IMAGE_ID, IMAGE)
        self.assertEqual(report["status"], "evidence_valid_release_blocked")
        self.assertEqual(report["blocking_scan_high"],0)
        self.assertFalse(report["release_authorized"])

    def test_offline_native_inventory_measures_elf_and_rejects_untrusted_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            library=root/"usr/lib/x86_64-linux-gnu/libexpat.so.1"
            library.parent.mkdir(parents=True)
            (root/"lib").symlink_to(root/"usr/lib", target_is_directory=True)
            library.write_bytes(b"\x7fELF"+bytes(range(128)))
            library.chmod(0o644)
            path=root/"opt/folio-expat-package/source-provenance.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({
                "name":"expat","upstream_version":"2.10.0",
                "local_package_version":EX_VERSION,"source_sha256":SOURCE_SHA,
                "patch_sha256":PATCH_SHA,"release_authorized":False
            }))
            def fake_run(argv, **kwargs):
                if argv[0]=="dpkg-query":
                    return subprocess.CompletedProcess(argv,0,stdout=EX_VERSION,stderr="")
                if argv[0]=="ldd":
                    return subprocess.CompletedProcess(argv,0,stdout=(
                        "libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00123)\n"
                    ),stderr="")
                if argv[0]=="/bin/sh":
                    # Debian dash may return 127 for a missing command.
                    return subprocess.CompletedProcess(argv,127,stdout="",stderr="")
                raise AssertionError(argv)
            with patch("expat_runtime_inventory.subprocess.run",side_effect=fake_run), patch(
                "expat_runtime_inventory.ctypes.CDLL"
            ) as load:
                load.return_value.XML_ExpatVersion.return_value=b"expat_2.10.0"
                value=gather(root)
            self.assertEqual(value["package_version"],EX_VERSION)
            self.assertEqual(len(value["library_sha256"]),64)
            self.assertEqual(value["linked_poppler_tools"],list(TOOLS))
            self.assertFalse(value["xmlwf_present"])
            library.chmod(0o666)
            with patch("expat_runtime_inventory.subprocess.run",side_effect=fake_run):
                with self.assertRaises(ValueError):
                    gather(root)

    def test_cli_fails_when_one_saved_evidence_file_is_tampered(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            scan, sbom, native, expat=fixtures()
            files={
                "vulnerabilities":base/"vulns.json", "sbom":base/"sbom.json",
                "source-inventory":base/"native.json",
                "expat-inventory":base/"expat.json",
            }
            for name, content in zip(files, (scan, sbom, native, expat)):
                files[name].write_text(json.dumps(content))
            argv=["python3","apps/inspector/expat_evidence.py"]
            for name,path in files.items():
                argv.extend([f"--{name}",str(path)])
            argv.extend(["--image-id", IMAGE_ID,"--image",IMAGE])
            result=subprocess.run(argv,cwd=Path(__file__).resolve().parents[3],
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0)
            self.assertFalse(json.loads(result.stdout)["release_authorized"])

            sbom["components"][0]["version"]="2.9.0"
            files["sbom"].write_text(json.dumps(sbom))
            corrupted=subprocess.run(argv,cwd=Path(__file__).resolve().parents[3],
                                     capture_output=True,text=True,timeout=10)
            self.assertEqual(corrupted.returncode,3)
            self.assertEqual(json.loads(corrupted.stdout)["status"],"error")

    def test_audit_script_collects_cyclonedx_and_native_in_immutable_image(self):
        script=(Path(__file__).resolve().parents[1]/"scan_expat_experiment.sh").read_text()
        for token in ("--format cyclonedx", "source_inventory.py",
                      "expat_runtime_inventory.py", "expat_evidence.py",
                      "--source-inventory", "--expat-inventory",
                      "--image-id", "docker image inspect",
                      "--network none --read-only --cap-drop ALL",
                      "image_changed_during_scan"):
            self.assertIn(token, script)
        self.assertLess(script.index("expat_evidence.py"),script.index("expat_prototype_scan.py"))
        self.assertNotIn("--ignore-unfixed",script)
        self.assertNotIn("--ignorefile",script)


if __name__=="__main__":
    unittest.main()
