"""R1.37: direct Debian quilt -> binary research, never a runtime release."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))

from util_linux_folio2_binary import (
    SOURCE_FILES, SOURCE_VERSION, SOURCE_MANIFEST_NAME, EXPECTED_PACKAGES,
    expected_binary_version, validate_source, validate_binary_inventory,
)

def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


class Folio2BinaryTDD(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="folio-r137-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        self.contents = {name: (name + "\n").encode() for name in SOURCE_FILES}
        for name, content in self.contents.items():
            f = self.source / name
            f.write_bytes(content)
            f.chmod(0o600)
        self.manifest = {
            "status": "unsigned_versioned_debian_source_roundtrip_release_blocked",
            "versioned_debian_source_version": SOURCE_VERSION,
            "versioned_dsc_signed": False,
            "source_roundtrip_verified": True,
            "release_authorized": False,
            "security_gate": "blocked",
            "cve_remediated": False,
            "debian_binary_packages_built": False,
            "quilt_patch_count": 11,
            "additional_quilt_patch_sha256": "cf8166e6d0cc5472bf7e78753f81e7c6b68f43a5784668c1a748baed4508a179",
            "patched_idmap_sha256": "e12678246515279507185598710821dc23387b08b84b4eeb9b4977e733e391c1",
            "source_date_epoch": 1795190400,
            "vex": "not_issued",
            "source_sha256": {name: digest(blob) for name, blob in self.contents.items()}
        }
        self._save()

    def _save(self):
        p = self.source / SOURCE_MANIFEST_NAME
        p.write_text(json.dumps(self.manifest))
        p.chmod(0o600)

    def _valid(self):
        with patch("util_linux_folio2_binary.SOURCE_HASHES",
                   self.manifest["source_sha256"]):
            return validate_source(self.source)

    def test_strict_version_epoch_and_exact_package_names(self):
        self.assertEqual(SOURCE_VERSION, "2.41.6-0+folio2~deb13u1")
        self.assertEqual(len(EXPECTED_PACKAGES), 43)
        self.assertIn("util-linux", EXPECTED_PACKAGES)
        self.assertEqual(expected_binary_version("login"),
            "1:4.16.0-2+really" + SOURCE_VERSION)
        self.assertEqual(expected_binary_version("bsdutils"), "1:" + SOURCE_VERSION)
        self.assertEqual(expected_binary_version("mount"), SOURCE_VERSION)

    def test_private_source_admitted_but_blocked(self):
        report = self._valid()
        self.assertIs(report["release_authorized"], False)
        self.assertIs(report["cve_remediated"], False)
        self.assertEqual(report["source_sha256"], self.manifest["source_sha256"])

    def test_tamper_or_release_claim_is_rejected(self):
        for k,v in (("release_authorized", True),
                    ("source_roundtrip_verified", False),
                    ("quilt_patch_count", 10),
                    ("versioned_dsc_signed", True),
                    ("security_gate", "open"),
                    ("versioned_debian_source_version", "2.41.6-0+folio1~deb13u1")):
            old = self.manifest[k]
            self.manifest[k] = v
            self._save()
            with self.subTest(k=k), self.assertRaises(ValueError):
                self._valid()
            self.manifest[k] = old
        self._save()
        a = self.source / next(iter(SOURCE_FILES))
        a.write_text("CHANGED")
        with self.assertRaises(ValueError):
            self._valid()

    def test_unexpected_files_or_perms_block_admission(self):
        extra = self.source / "unapproved.deb"
        extra.write_text("bad")
        with self.assertRaises(ValueError):
            self._valid()
        extra.unlink()
        self.source.chmod(0o755)
        with self.assertRaises(ValueError):
            self._valid()

    def test_symlink_inputs_block_admission(self):
        f = self.source / next(iter(SOURCE_FILES))
        f.unlink()
        f.symlink_to(self.source / SOURCE_MANIFEST_NAME)
        with self.assertRaises(ValueError):
            self._valid()

    def _pkg(self, name: str, version: str, src: str = "util-linux"):
        control = self.root / ("pkg-" + name) / "DEBIAN"
        control.mkdir(parents=True, exist_ok=True)
        (control / "control").write_text(
            f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
            f"Source: {src}\nMaintainer: R137 <test@invalid>\n"
            "Description: Synthetic fixture\n"
        )
        return control.parent

    def test_binary_verifier_fails_on_missing_package_or_version(self):
        out = self.root / "bins"
        out.mkdir(mode=0o700)
        out.joinpath("NOT_FOR_RELEASE.txt").write_text("NO")
        with self.assertRaises(ValueError):
            validate_binary_inventory(out, self._valid())
        one = self._pkg("util-linux", SOURCE_VERSION)
        subprocess.run(["dpkg-deb", "--build", str(one),
                        str(out / "util-linux_test_amd64.deb")],
                       check=True, capture_output=True)
        # One valid package is not the required set of 43.
        with self.assertRaises(ValueError):
            validate_binary_inventory(out, self._valid())

    def _full_synthetic_output(self):
        out = self.root / "complete"
        out.mkdir(mode=0o700)
        (out / "NOT_FOR_RELEASE.txt").write_text("NOT RELEASED")
        (out / "QUILT_SOURCE_SHA256.txt").write_text(
            "e12678246515279507185598710821dc23387b08b84b4eeb9b4977e733e391c1"
            "  libmount/src/hook_idmap.c\n")
        for name in sorted(EXPECTED_PACKAGES):
            folder = self._pkg(name, expected_binary_version(name))
            control = folder / "DEBIAN/control"
            if name == "util-linux-locales":
                control.write_text(control.read_text().replace(
                    "Architecture: amd64", "Architecture: all"))
            deb = out / f"{name}_synthetic.deb"
            subprocess.run(["dpkg-deb", "--build", str(folder), str(deb)],
                           check=True, capture_output=True, timeout=15)
            deb.chmod(0o600)
        return out

    def test_all_43_synthetic_packages_are_required_and_never_approve(self):
        out = self._full_synthetic_output()
        with patch("util_linux_folio2_binary.SOURCE_HASHES",
                   self.manifest["source_sha256"]):
            report = validate_binary_inventory(out, self._valid())
        self.assertEqual(report["binary_package_count"], 43)
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["debian_trixie_abi_validated"])
        self.assertFalse(report["cve_remediated"])
        self.assertTrue((out / "UNSIGNED_FOLIO2_BINARY_RESEARCH_ONLY.json").is_file())
        with patch("util_linux_folio2_binary.SOURCE_HASHES",
                   self.manifest["source_sha256"]):
            with self.assertRaises(ValueError):
                validate_binary_inventory(out, self._valid())

    def test_wrong_bsdutils_epoch_blocks_even_with_all_43_packages(self):
        out = self._full_synthetic_output()
        wrong = out / "bsdutils_synthetic.deb"
        wrong.unlink()
        # Replace only one of the complete 43 fixture packages.
        folder = self._pkg("bsdutils", SOURCE_VERSION)
        subprocess.run(["dpkg-deb", "--build", str(folder), str(wrong)],
                       check=True, capture_output=True, timeout=15)
        wrong.chmod(0o600)
        with patch("util_linux_folio2_binary.SOURCE_HASHES",
                   self.manifest["source_sha256"]):
            with self.assertRaises(ValueError):
                validate_binary_inventory(out, self._valid())

    def test_builder_has_isolation_and_no_external_patch(self):
        script = (ROOT / "apps/inspector/build_util_linux_folio2_binary.sh").read_text()
        for x in ("sha256sum --check -", "--cap-drop ALL", "--security-opt no-new-privileges",
                  "--read-only", "--network none", "dpkg-buildpackage",
                  "preflight.py", "util_linux_folio2_binary.py"):
            self.assertIn(x,script)
        for x in ("git apply", "/research/patch", "docker push",
                  "wrangler deploy", "docker build", "dpkg -i",
                  "docker system prune", "apt-get upgrade"):
            self.assertNotIn(x, script)


if __name__ == "__main__":
    unittest.main()
