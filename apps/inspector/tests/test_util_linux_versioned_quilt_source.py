"""R1.36: new independent Debian source version, never a release."""
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

from util_linux_versioned_quilt_source import (
    VERSIONED_SOURCE_VERSION, VERSIONED_PATCH_NAME, VERSIONED_SERIES,
    VERSIONED_MANIFEST_NAME, UNPATCHED_IDMAP_SHA256,
    validate_output_path, validate_quilt_tree, validate_versioned_dsc,
    build_versioned_source, _source_changelog,
)
from util_linux_trixie_binary_experiment import (
    PATCHED_IDMAP_SHA256, BUILD_PATCH, BUILD_PATCH_SHA256
)
from util_linux_debian_source_overlay import (
    EXPERIMENT_VERSION, EXPECTED_OVERLAY_SERIES
)

def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()

class VersionedSourceTDD(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.base = Path(t.name)
        self.src = self.base / "input"
        self.src.mkdir(mode=0o700)
        self.dest = self.base / "versioned"

    def test_source_version_is_strictly_newer_and_distinct(self):
        self.assertEqual(VERSIONED_SOURCE_VERSION, "2.41.6-0+folio2~deb13u1")
        p = subprocess.run(
            ["dpkg", "--compare-versions", VERSIONED_SOURCE_VERSION, "gt",
             EXPERIMENT_VERSION], timeout=10)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(VERSIONED_SERIES[:-1], EXPECTED_OVERLAY_SERIES)
        self.assertEqual(VERSIONED_SERIES[-1], VERSIONED_PATCH_NAME)
        self.assertEqual(len(VERSIONED_SERIES), 11)
        self.assertEqual(VERSIONED_MANIFEST_NAME, "UNSIGNED_VERSIONED_SOURCE_ONLY.json")
        self.assertEqual(len(UNPATCHED_IDMAP_SHA256), 64)

    def test_experimental_patch_is_exact_and_not_release_approval(self):
        self.assertEqual(sha(BUILD_PATCH.read_bytes()), BUILD_PATCH_SHA256)
        self.assertIn("openat2.h", BUILD_PATCH.read_text())

    def test_output_dir_must_be_new_private_and_nonoverlapping(self):
        self.assertEqual(validate_output_path(self.src, self.dest), self.dest)
        for bad in (self.src, self.src / "nested", self.base,
                    Path("/tmp"), Path("relative"), Path("/")):
            with self.subTest(path=str(bad)), self.assertRaises(ValueError):
                validate_output_path(self.src, bad)
        self.dest.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            validate_output_path(self.src, self.dest)

    def test_symlinked_output_parent_is_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.src, target_is_directory=True)
        with self.assertRaises(ValueError):
            validate_output_path(self.src, alias / "result")

    def _make_tree(self, version=VERSIONED_SOURCE_VERSION,
                   series=VERSIONED_SERIES, idmap=b"patched",
                   nsenter=b"nsenter"):
        root = self.base / "tree"
        for name in ("debian/patches", "libmount/src", "sys-utils"):
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / "debian/patches/series").write_text(
            "\n".join(series) + "\n", encoding="utf-8")
        (root / "debian/changelog").write_text(
            f"util-linux ({version}) UNRELEASED; urgency=low\n",
            encoding="utf-8")
        (root / "libmount/src/hook_idmap.c").write_bytes(idmap)
        (root / "sys-utils/nsenter.c").write_bytes(nsenter)
        patch_path = root / "debian/patches" / VERSIONED_PATCH_NAME
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_bytes(BUILD_PATCH.read_bytes())
        return root

    def test_tree_requires_source_id_patch_and_order(self):
        tree = self._make_tree()
        with patch("util_linux_versioned_quilt_source.PATCHED_IDMAP_SHA256",
                   sha(b"patched")), \
             patch("util_linux_versioned_quilt_source.PATCHED_NSENTER_SHA256",
                   sha(b"nsenter")):
            validate_quilt_tree(tree)
            (tree / "debian/patches/series").write_text(
                "\n".join(reversed(VERSIONED_SERIES)) + "\n")
            with self.assertRaises(ValueError):
                validate_quilt_tree(tree)
            (tree / "debian/patches/series").write_text(
                "\n".join(VERSIONED_SERIES) + "\n")
            (tree / "debian/changelog").write_text(
                f"util-linux ({VERSIONED_SOURCE_VERSION}) trixie-security;\n")
            with self.assertRaises(ValueError):
                validate_quilt_tree(tree)

    def test_new_changelog_keeps_old_history_but_never_impersonates_debian(self):
        old = f"util-linux ({EXPERIMENT_VERSION}) UNRELEASED; urgency=low\n"
        value = _source_changelog(old)
        self.assertTrue(value.startswith(
            f"util-linux ({VERSIONED_SOURCE_VERSION}) UNRELEASED; urgency=low"
        ))
        self.assertIn(old, value)
        self.assertIn("NOT A RELEASE", value)
        with self.assertRaises(ValueError):
            _source_changelog("util-linux (2.41.5-0+deb13u1) trixie-security;\n")

    def test_tree_rejects_tampered_quilt_patch(self):
        tree = self._make_tree()
        with patch("util_linux_versioned_quilt_source.PATCHED_IDMAP_SHA256",
                   sha(b"patched")), \
             patch("util_linux_versioned_quilt_source.PATCHED_NSENTER_SHA256",
                   sha(b"nsenter")):
            target = tree / "debian/patches" / VERSIONED_PATCH_NAME
            target.write_bytes(target.read_bytes() + b"unauthorized edit")
            with self.assertRaises(ValueError):
                validate_quilt_tree(tree)

    def test_tree_rejects_missing_include_or_changed_cve_backport(self):
        tree = self._make_tree()
        with patch("util_linux_versioned_quilt_source.PATCHED_IDMAP_SHA256",
                   sha(b"patched")), \
             patch("util_linux_versioned_quilt_source.PATCHED_NSENTER_SHA256",
                   sha(b"nsenter")):
            (tree / "libmount/src/hook_idmap.c").write_bytes(b"other")
            with self.assertRaises(ValueError):
                validate_quilt_tree(tree)
            (tree / "libmount/src/hook_idmap.c").write_bytes(b"patched")
            (tree / "sys-utils/nsenter.c").write_bytes(b"altered cve backport")
            with self.assertRaises(ValueError):
                validate_quilt_tree(tree)

    def _make_dsc(self, sha_orig="a" * 64, sha_quilt="b" * 64,
                  version=VERSIONED_SOURCE_VERSION, extra=""):
        return (
            "Format: 3.0 (quilt)\n"
            "Source: util-linux\n"
            f"Version: {version}\n"
            "Checksums-Sha256:\n"
            f" {sha_orig} 123 util-linux_2.41.6.orig.tar.xz\n"
            f" {sha_quilt} 456 util-linux_{version}.debian.tar.xz\n"
            + extra
        )

    def test_dsc_metadata_requires_exact_identity_and_manifest(self):
        output = validate_versioned_dsc(
            self._make_dsc(), {"util-linux_2.41.6.orig.tar.xz": ("a" * 64, 123),
                                "util-linux_2.41.6-0+folio2~deb13u1.debian.tar.xz":
                                    ("b" * 64, 456)})
        self.assertEqual(output["version"], VERSIONED_SOURCE_VERSION)
        for bad in (
            self._make_dsc(version=EXPERIMENT_VERSION),
            self._make_dsc(extra=" " + "c" * 64 + " 42 extra.tar.xz\n"),
            self._make_dsc().replace("Format: 3.0 (quilt)", "Format: 1.0"),
        ):
            with self.subTest(bad=bad[:70]), self.assertRaises(ValueError):
                validate_versioned_dsc(
                    bad, {"util-linux_2.41.6.orig.tar.xz": ("a" * 64, 123),
                          "util-linux_2.41.6-0+folio2~deb13u1.debian.tar.xz":
                              ("b" * 64, 456)})

    def test_dsc_rejects_changed_sha_or_duplicate_sha_entries(self):
        names = {"util-linux_2.41.6.orig.tar.xz": ("a" * 64, 123),
                 f"util-linux_{VERSIONED_SOURCE_VERSION}.debian.tar.xz":
                     ("b" * 64, 456)}
        good = self._make_dsc()
        for bad in (
            good.replace("a" * 64, "0" * 64),
            good + f" {'b' * 64} 456 util-linux_{VERSIONED_SOURCE_VERSION}.debian.tar.xz\n",
            good.replace("Format: 3.0 (quilt)", "Format: 3.0 (quilt)\nFormat: 3.0 (quilt)"),
        ):
            with self.subTest(case=bad[:80]), self.assertRaises(ValueError):
                validate_versioned_dsc(bad, names)

    def test_failed_source_admission_does_not_create_output(self):
        with self.assertRaises(ValueError):
            build_versioned_source(self.src, self.dest)
        self.assertFalse(self.dest.exists())

    def test_cli_fails_closed_without_source(self):
        p = subprocess.run(
            ["python3", "apps/inspector/util_linux_versioned_quilt_source.py",
             "--source-dir", str(self.src),
             "--output-dir", str(self.dest)],
            cwd=ROOT, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(p.returncode, 3)
        self.assertFalse(json.loads(p.stdout)["release_authorized"])
        self.assertFalse(self.dest.exists())

    def test_manifest_research_only_and_no_binary_build(self):
        script = (
            ROOT / "apps/inspector/util_linux_versioned_quilt_source.py"
        ).read_text()
        for token in ("--before-build", "--no-check", "dpkg-source",
                      "UNRELEASED", "SOURCE_DATE_EPOCH",
                      "git", "sha256", "release_authorized"):
            self.assertIn(token, script)
        for token in ("dpkg-buildpackage", "docker push", "docker run",
                      "apt-get", "curl", "dpkg -i", "wrangler deploy",
                      "ignore-unfixed", "vex_issued"):
            self.assertNotIn(token, script)

if __name__ == "__main__":
    unittest.main()
