"""R1.38: private SHA-pinned ABI-consumer research, no host installation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))

from util_linux_folio2_binary import EXPECTED_PACKAGES, SOURCE_VERSION, SOURCE_HASHES
from util_linux_folio2_consumer_smoke import (
    PINNED_DEBS, MANIFEST_NAME, STOCK_CONSUMERS, PROVEN_LOADED_DSOS,
    verify_binary_handoff, verify_stock_packages, run_consumer_smoke,
)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class Consumers(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="folio-r138-consumers-")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name) / "private"
        self.folder.mkdir(mode=0o700)
        self.blobs = {
            name: f"mocked-{name}".encode("utf-8") for name in PINNED_DEBS
        }
        self.pins = {name: digest(blob) for name, blob in self.blobs.items()}
        for name, blob in self.blobs.items():
            f = self.folder / f"{name}_{SOURCE_VERSION}_amd64.deb"
            f.write_bytes(blob)
            f.chmod(0o600)
        self.doc = {
            "status": "folio2_debian13_binary_research_release_blocked",
            "source_version": SOURCE_VERSION,
            "source_sha256": SOURCE_HASHES,
            "binary_package_count": 43,
            "debian_binary_packages_built": True,
            "debian_trixie_abi_validated": False,
            "cve_remediated": False,
            "release_authorized": False,
            "security_gate": "blocked",
            "packages": [{
                "name": name,
                "file": f"{name}_{SOURCE_VERSION}_amd64.deb",
                "version": SOURCE_VERSION,
                "architecture": "amd64",
                "sha256": self.pins.get(name, "0" * 64),
            } for name in sorted(EXPECTED_PACKAGES)],
        }
        self._save()

    def _save(self):
        f = self.folder / MANIFEST_NAME
        f.write_text(json.dumps(self.doc), encoding="utf-8")
        f.chmod(0o600)

    def _verified(self):
        with patch("util_linux_folio2_consumer_smoke.PINNED_DEBS", self.pins):
            return verify_binary_handoff(self.folder)

    def test_five_exact_libraries_and_five_stock_consumers(self):
        self.assertEqual(len(PINNED_DEBS), 5)
        self.assertEqual(len(STOCK_CONSUMERS), 5)
        self.assertEqual(len(PROVEN_LOADED_DSOS), 3)
        self.assertIn("findmnt", STOCK_CONSUMERS)
        self.assertIn("libmount1", PROVEN_LOADED_DSOS)

    def test_valid_pinned_private_handoff_never_approves(self):
        report = self._verified()
        self.assertEqual(len(report["pinned_dso_packages"]), 5)
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["cve_remediated"])

    def test_wrong_hash_rejected_even_if_manifest_modified(self):
        name = "libmount1"
        f = self.folder / f"{name}_{SOURCE_VERSION}_amd64.deb"
        f.write_bytes(b"unauthorized-change")
        self.doc["packages"] = [
            {**r, "sha256": digest(b"unauthorized-change")}
            if r["name"] == name else r for r in self.doc["packages"]
        ]
        self._save()
        with self.assertRaises(ValueError):
            self._verified()

    def test_release_claim_or_missing_package_rejected(self):
        for key, value in [
            ("release_authorized", True),
            ("source_version", "2.41.6-0+folio1~deb13u1"),
            ("cve_remediated", True),
            ("binary_package_count", 42),
        ]:
            old = self.doc[key]
            self.doc[key] = value
            self._save()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self._verified()
            self.doc[key] = old
        self.doc["packages"] = self.doc["packages"][:-1]
        self._save()
        with self.assertRaises(ValueError):
            self._verified()

    def test_folder_and_file_permissions_enforced(self):
        f = self.folder / f"libuuid1_{SOURCE_VERSION}_amd64.deb"
        f.chmod(0o644)
        with self.assertRaises(ValueError):
            self._verified()
        f.chmod(0o600)
        self.folder.chmod(0o755)
        with self.assertRaises(ValueError):
            self._verified()

    def test_isolated_docker_contract_with_mocked_execution(self):
        with patch("util_linux_folio2_consumer_smoke.PINNED_DEBS", self.pins), \
             patch("util_linux_folio2_consumer_smoke._command", side_effect=[
                 "unix:///var/run/docker.sock\n", "{}",
                 "folio2_stock_debian_consumers_and_three_dynamic_library_loads=pass\n"
             ]) as command:
            report = run_consumer_smoke(self.folder)
        self.assertEqual(command.call_count, 3)
        docker_run_args = command.call_args_list[-1].args[0]
        joined = " ".join(docker_run_args)
        self.assertIn("--network none", joined)
        self.assertIn("--cap-drop ALL", joined)
        self.assertIn("--read-only", joined)
        self.assertIn("--security-opt no-new-privileges", joined)
        self.assertIn("dst=/artifacts,readonly", joined)
        self.assertNotIn("--privileged", joined)
        self.assertNotIn("docker push", joined)
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["debian_trixie_abi_validated"])
        self.assertFalse(report["runtime_cve_regressions_passed"])

    def test_signed_apt_consumer_reference_must_match_private_pins(self):
        stock = self.folder.parent / "stock"
        stock.mkdir(mode=0o700)
        blobs = {name: (name + "\n").encode()
                 for name in ("fdisk.deb", "uuid.deb")}
        hashes = {name: digest(blob) for name, blob in blobs.items()}
        for name, blob in blobs.items():
            f = stock / name
            f.write_bytes(blob)
            f.chmod(0o600)
        with patch("util_linux_folio2_consumer_smoke.STOCK_PINS", hashes):
            verified = verify_stock_packages(stock)
            self.assertEqual(verified["stock_consumer_sha256"], hashes)
            (stock / "uuid.deb").write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                verify_stock_packages(stock)

    def test_full_seven_debian_consumers_require_extra_libs_evidence(self):
        stock = self.folder.parent / "stock"
        stock.mkdir(mode=0o700)
        blobs = {"fdisk.deb": b"fdisk", "uuid.deb": b"uuid"}
        hashes = {name: digest(blob) for name, blob in blobs.items()}
        for name, blob in blobs.items():
            f = stock / name
            f.write_bytes(blob)
            f.chmod(0o600)
        markers = (
            "folio2_stock_debian_consumers_and_three_dynamic_library_loads=pass\n"
            "folio2_stock_fdisk_uuidgen_two_more_library_loads=pass\n"
        )
        with patch("util_linux_folio2_consumer_smoke.PINNED_DEBS", self.pins), \
             patch("util_linux_folio2_consumer_smoke.STOCK_PINS", hashes), \
             patch("util_linux_folio2_consumer_smoke._command", side_effect=[
                 "unix:///var/run/docker.sock\n", "{}", markers,
             ]) as command:
            report = run_consumer_smoke(self.folder, stock)
        self.assertEqual(len(report["candidate_libraries_proven_loaded"]), 5)
        self.assertEqual(report["consumer_abi_coverage"],
                         "seven_stock_debian_commands_five_candidate_dsos_only")
        self.assertIn("dst=/stock,readonly", " ".join(command.call_args_list[-1].args[0]))
        self.assertFalse(report["debian_trixie_abi_validated"])

    def test_foreign_package_name_rejected_even_when_count_43(self):
        old = self.doc["packages"][-1]["name"]
        self.doc["packages"][-1]["name"] = "unexpected-foreign-package"
        self._save()
        with self.assertRaises(ValueError):
            self._verified()
        self.doc["packages"][-1]["name"] = old

    def test_host_root_operator_rejected(self):
        with patch("util_linux_folio2_consumer_smoke.os.geteuid",
                   return_value=0), \
             self.assertRaises(ValueError):
            self._verified()

    def test_no_mutating_mount_or_namespaces_in_fixed_script(self):
        source = (ROOT / "apps/inspector/util_linux_folio2_consumer_smoke.py").read_text()
        self.assertIn("LD_DEBUG=libs", source)
        self.assertIn("dpkg-deb -x", source)
        for forbidden in ("dpkg -i", "apt-get install", "mount -o",
                          "unshare -", "setns(", "docker build",
                          "wrangler deploy", "docker push"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
