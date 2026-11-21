"""R1.51: research-only sixth Poppler CLI binds to the legacy v1 inventory."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

INSPECTOR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(INSPECTOR))
from test_source_inventory import provision, checked_version
import pdfimages_elf_provenance as audit

VALID_ID = "sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a"


def base_fixture(root: Path) -> Path:
    provision(root, "tesseract")
    provision(root, "poppler")
    (root / "opt/folio-poppler/lib/libpoppler.so.147").chmod(0o644)
    tool = root / "opt/folio-poppler/bin/pdfimages"
    tool.write_bytes(b"\x7fELF" + b"folio-pdfimages-synthetic" * 240)
    tool.chmod(0o755)
    return tool


def subprocess_fixture(argv, **kwargs):
    if argv[0] == "ldd":
        return subprocess.CompletedProcess(argv, 0, stdout=(
            "libpoppler.so.147 => /opt/folio-poppler/lib/libpoppler.so.147 (0x1234)\n"
            "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x5678)\n"
        ), stderr="")
    if argv[0].endswith("/pdfimages"):
        return subprocess.CompletedProcess(
            argv, 0, stdout="", stderr="pdfimages version 25.03.0\n"
        )
    return checked_version(argv, **kwargs)


class SixthPopplerCliProvenanceTests(unittest.TestCase):
    def test_pinned_image_legacy_v1_and_pdfimages_sixth_elf_are_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pdfimages = base_fixture(root)
            with patch.object(audit.subprocess, "run", side_effect=subprocess_fixture):
                result = audit.inspect(root, image_id=VALID_ID)
            self.assertEqual(result["source"], "folio-r151-pdfimages-elf-provenance-v1")
            self.assertEqual(result["legacy_source"], "folio-local-elf-provenance-v1")
            self.assertEqual(
                result["legacy_inventory_script_sha256"],
                hashlib.sha256((INSPECTOR / "source_inventory.py").read_bytes()).hexdigest(),
            )
            self.assertEqual(result["image_id"], VALID_ID)
            self.assertEqual(result["status"], "verified_local_elf_identity_release_blocked")
            self.assertEqual(result["pdfimages_sha256"], hashlib.sha256(pdfimages.read_bytes()).hexdigest())
            self.assertEqual(set(result["other_poppler_tools_sha256"]), {
                "pdfinfo", "pdftotext", "pdftoppm", "pdfdetach", "pdfattach"
            })
            self.assertEqual(len(result["poppler_library_sha256"]), 64)
            self.assertTrue(result["same_poppler_library_link_verified"])
            self.assertEqual(result["source_cve_coverage"], "unassessed")
            self.assertEqual(result["scanner_gate"], "blocked")
            self.assertFalse(result["release_authorized"])
            self.assertFalse(result["source_to_elf_reproducible_build_attested"])

    def test_tampered_historical_inventory_script_is_not_accepted_as_v1(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "image"
            root.mkdir()
            base_fixture(root)
            (Path(folder) / "source_inventory.py").write_text("tampered legacy inventory")
            with patch.object(audit, "__file__", str(Path(folder) / "pdfimages_elf_provenance.py")), \
                 patch.object(audit.subprocess, "run", side_effect=subprocess_fixture):
                with self.assertRaisesRegex(ValueError, "Legacy inventory script SHA mismatch"):
                    audit.inspect(root, image_id=VALID_ID)

    def test_missing_mutable_symlink_or_non_elf_sixth_cli_cannot_pass(self):
        for defect in ("missing", "world_writable", "symlink", "non_elf", "multiple_links"):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                binary = base_fixture(root)
                if defect == "missing":
                    binary.unlink()
                elif defect == "world_writable":
                    binary.chmod(0o777)
                elif defect == "symlink":
                    binary.rename(binary.with_suffix(".real"))
                    binary.symlink_to(binary.with_suffix(".real"))
                elif defect == "non_elf":
                    binary.write_bytes(b"not-an-elf")
                else:
                    extra = binary.with_suffix(".hardlink")
                    extra.hardlink_to(binary)
                with self.subTest(defect=defect), patch.object(
                    audit.subprocess, "run", side_effect=subprocess_fixture
                ), self.assertRaises(ValueError):
                    audit.inspect(root, image_id=VALID_ID)

    def test_wrong_id_or_tampered_legacy_five_tool_contract_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            base_fixture(root)
            for bad in ("sha256:" + "a" * 64, "folio-image:latest", "", None):
                with self.subTest(image_id=bad), self.assertRaises(ValueError):
                    audit.inspect(root, image_id=bad)
            (root / "opt/folio-poppler/bin/pdfattach").unlink()
            with patch.object(audit.subprocess, "run", side_effect=subprocess_fixture), self.assertRaises(ValueError):
                audit.inspect(root, image_id=VALID_ID)

    def test_mutable_or_escaped_poppler_soname_target_fails(self):
        for defect in ("mutable_target", "escaped_target"):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / "image"
                root.mkdir()
                base_fixture(root)
                soname = root / "opt/folio-poppler/lib/libpoppler.so.147"
                target = soname.with_suffix(".real")
                soname.rename(target)
                if defect == "mutable_target":
                    target.chmod(0o666)
                    soname.symlink_to(target.name)
                else:
                    external = Path(folder) / "outside"
                    external.write_bytes(target.read_bytes())
                    soname.symlink_to(external)
                with self.subTest(defect=defect), patch.object(
                    audit.subprocess, "run", side_effect=subprocess_fixture
                ), self.assertRaises(ValueError):
                    audit.inspect(root, image_id=VALID_ID)

    def test_missing_wrong_or_forbidden_runtime_linkage_rejects_attestation(self):
        for failure in ("wrong_path", "not_found", "network_dependency", "duplicate", "nonzero"):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                base_fixture(root)
                def run(argv, **kwargs):
                    result = subprocess_fixture(argv, **kwargs)
                    if argv[0] != "ldd" or not argv[1].endswith("/pdfimages"):
                        return result
                    stdout = result.stdout
                    code = 0
                    if failure == "wrong_path":
                        stdout = stdout.replace("/opt/folio-poppler/lib/libpoppler.so.147",
                                                "/usr/lib/libpoppler.so.147")
                    elif failure == "not_found":
                        stdout += "libmissing.so => not found\n"
                    elif failure == "network_dependency":
                        stdout += "libcurl.so.4 => /usr/lib/libcurl.so.4 (0x9999)\n"
                    elif failure == "duplicate":
                        stdout += "libpoppler.so.147 => /opt/folio-poppler/lib/libpoppler.so.147 (0xaaaa)\n"
                    else:
                        code = 1
                    return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr="")
                with self.subTest(failure=failure), patch.object(
                    audit.subprocess, "run", side_effect=run
                ), self.assertRaises(ValueError):
                    audit.inspect(root, image_id=VALID_ID)

    def test_pdfimages_version_and_cli_failure_never_attest(self):
        for version, status in (("pdfimages version 25.04.0\n", 0), ("garbage", 0),
                                ("pdfimages version 25.03.0\n", 2)):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                base_fixture(root)
                def run(argv, **kwargs):
                    if argv[0].endswith("/pdfimages"):
                        return subprocess.CompletedProcess(argv, status, stdout="", stderr=version)
                    return subprocess_fixture(argv, **kwargs)
                with self.subTest(version=version, exit=status), patch.object(
                    audit.subprocess, "run", side_effect=run
                ), self.assertRaises(ValueError):
                    audit.inspect(root, image_id=VALID_ID)

    def test_wrapper_is_offline_non_root_digest_pinned_and_never_deploys(self):
        script = (INSPECTOR / "scan_pdfimages_elf_provenance_r151.sh").read_text()
        for marker in (
            VALID_ID, "--pull never", "--network none", "--read-only",
            "--user 65534:65534", "--cap-drop ALL",
            "--security-opt no-new-privileges", "image inspect",
            "source_inventory.py", "pdfimages_elf_provenance.py",
        ):
            self.assertIn(marker, script)
        for forbidden in ("wrangler deploy", "--remote", "docker push", "--ignore-unfixed",
                          "--severity HIGH", "curl ", "wget "):
            self.assertNotIn(forbidden, script)
        self.assertNotIn("apps/inspector/Dockerfile", script)


if __name__ == "__main__":
    unittest.main()
