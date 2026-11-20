"""R1.34: source-only, unsigned candidate handoff for isolated Debian 13 builds.

The default R1.33 proof must remain ephemeral and fail closed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))

from util_linux_debian_source_overlay import (
    EXPERIMENT_VERSION, PATCHED_NSENTER_SHA256,
    EXPECTED_OVERLAY_SERIES, _export_unsigned_source_bundle,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BinaryHandoffTDD(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.work = self.parent / "verified"
        self.work.mkdir()
        self.orig = self.work / "util-linux_2.41.6.orig.tar.xz"
        self.dsc = self.work / f"util-linux_{EXPERIMENT_VERSION}.dsc"
        self.debian = self.work / f"util-linux_{EXPERIMENT_VERSION}.debian.tar.xz"
        self.orig.write_bytes(b"vendor signed tar")
        self.orig_digest = _sha(self.orig.read_bytes())
        self.dsc.write_bytes(b"experimental unsigned dsc")
        self.debian.write_bytes(b"verified quilt")
        self.evidence = {
            "source_roundtrip_verified": True,
            "debian_dsc_signed": True,
            "upstream_signatures_verified": True,
            "release_authorized": False,
            "experimental_dsc_signed": False,
            "cve_78408_backport_added": True,
            "new_quilt_patch_count": len(EXPECTED_OVERLAY_SERIES),
            "patched_nsenter_sha256": PATCHED_NSENTER_SHA256,
            "experimental_dsc_sha256": _sha(self.dsc.read_bytes()),
            "experimental_debian_tar_sha256": _sha(self.debian.read_bytes()),
        }
        self.destination = self.parent / "source-handoff-r134"

    def _export(self):
        with patch("util_linux_debian_source_overlay.TAR_SHA256", self.orig_digest):
            return _export_unsigned_source_bundle(
                self.work, self.destination, self.evidence
            )

    def test_exported_handoff_is_private_complete_and_never_a_release(self):
        manifest = self._export()
        self.assertFalse(manifest["release_authorized"])
        self.assertFalse(manifest["debian_binary_packages_built"])
        self.assertFalse(manifest["experimental_dsc_signed"])
        self.assertTrue(manifest["source_roundtrip_verified"])
        self.assertEqual(
            stat.S_IMODE(self.destination.stat().st_mode), 0o700
        )
        expected = {p.name for p in (self.orig, self.dsc, self.debian)}
        self.assertEqual(set(manifest["sha256"]), expected)
        self.assertEqual(
            set(p.name for p in self.destination.iterdir()),
            expected | {"UNSIGNED_SOURCE_ONLY.json"},
        )
        for name in expected:
            output = self.destination / name
            self.assertEqual(output.read_bytes(), (self.work / name).read_bytes())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(manifest["sha256"][name], _sha(output.read_bytes()))
        self.assertEqual(json.loads(
            (self.destination / "UNSIGNED_SOURCE_ONLY.json").read_text()
        ), manifest)

    def test_existing_directory_is_never_overwritten(self):
        self.destination.mkdir()
        keep = self.destination / "existing"
        keep.write_text("other agent")
        with self.assertRaises(ValueError):
            self._export()
        self.assertEqual(keep.read_text(), "other agent")

    def test_corrupt_or_unverified_handoff_is_rejected_without_outputs(self):
        for key, value in [
            ("source_roundtrip_verified", False),
            ("debian_dsc_signed", False),
            ("upstream_signatures_verified", False),
            ("release_authorized", True),
            ("experimental_dsc_signed", True),
            ("cve_78408_backport_added", False),
            ("new_quilt_patch_count", 11),
            ("patched_nsenter_sha256", "0" * 64),
            ("experimental_dsc_sha256", "0" * 64),
            ("experimental_debian_tar_sha256", "0" * 64),
        ]:
            with self.subTest(key=key):
                data = dict(self.evidence, **{key: value})
                with patch("util_linux_debian_source_overlay.TAR_SHA256", _sha(self.orig.read_bytes())):
                    with self.assertRaises(ValueError):
                        _export_unsigned_source_bundle(self.work, self.destination, data)
                self.assertFalse(self.destination.exists())

    def test_missing_source_and_existing_symlink_are_rejected(self):
        self.orig.unlink()
        with self.assertRaises(ValueError):
            self._export()
        self.assertFalse(self.destination.exists())
        self.orig.write_bytes(b"vendor signed tar")
        link = self.parent / "link"
        link.symlink_to(self.parent, target_is_directory=True)
        with patch("util_linux_debian_source_overlay.TAR_SHA256", _sha(self.orig.read_bytes())):
            with self.assertRaises(ValueError):
                _export_unsigned_source_bundle(self.work, link / "handoff", self.evidence)
        self.assertFalse((self.parent / "handoff").exists())

    def test_production_scripts_remain_fail_closed_and_no_docker_build(self):
        source = (ROOT / "apps/inspector/util_linux_debian_source_overlay.py").read_text()
        fetch = (ROOT / "apps/inspector/fetch_util_linux_debian_source_overlay.sh").read_text()
        self.assertIn("--export-dir", source)
        self.assertIn("--export-dir", fetch)
        self.assertNotIn("docker build", fetch)
        self.assertNotIn("dpkg -i", fetch)
        self.assertNotIn("docker push", fetch)
        self.assertNotIn("wrangler deploy", fetch)


if __name__ == "__main__":
    unittest.main()
