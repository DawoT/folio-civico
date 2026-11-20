"""R1.33: signed Trixie packaging can be rebased on 2.41.6 without reverse patches.

No binary package, Docker image, installed library, VEX or release approval.
"""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"apps/inspector"))

from util_linux_debian_source_overlay import (
    DEBIAN_VERSION, DEBIAN_DSC_SHA256, DEBIAN_SOURCE_FILES,
    DEBIAN_SOURCE_MD5,
    DEBIAN_SIGNER_FINGERPRINT, UPSTREAM_PATCH_SERIES,
    SOURCE_DATE_EPOCH, _normalize_debian_mtimes,
    RETAINED_DEBIAN_PATCHES, CVE_FOLLOWUP_NAME, EXPERIMENT_VERSION,
    _debian_signed_manifest, _expected_overlay_series, _local_changelog,
    _check_duplicate_upstream_patches, _assert_roundtrip_tree,
)
from util_linux_source_candidate import PATCHED_NSENTER_SHA256


def signed_dsc_content():
    return (
        "Format: 3.0 (quilt)\nSource: util-linux\n"
        "Version: 2.41.5-0+deb13u1\n"
        "Maintainer: Chris Hofstaedtler <zeha@debian.org>\n"
        "Checksums-Sha256:\n"+
        "".join(f" {digest} {size} {name}\n"
                for name,(digest,size) in DEBIAN_SOURCE_FILES.items())+
        "Files:\n"+
        "".join(
            f" {digest} {DEBIAN_SOURCE_FILES[name][1]} {name}\n"
            for name,digest in DEBIAN_SOURCE_MD5.items()
        )
    )


class DebianSourceOverlayTDD(unittest.TestCase):
    def test_signed_debian_release_and_source_pins(self):
        self.assertEqual(DEBIAN_VERSION,"2.41.5-0+deb13u1")
        self.assertEqual(DEBIAN_SIGNER_FINGERPRINT,
                         "7D1ACFFAD9E0806C9C4CD3925C13D6DB93052E03")
        self.assertEqual(DEBIAN_DSC_SHA256,
                         "43e9b2cbebd10fdc598c4ad10217c8202c28de53af6eafc892c8e9b5cbf3a3a5")
        self.assertEqual(len(DEBIAN_SOURCE_FILES),2)
        self.assertEqual(len(RETAINED_DEBIAN_PATCHES),9)
        self.assertEqual(len(UPSTREAM_PATCH_SERIES),2)
        self.assertEqual(EXPERIMENT_VERSION,"2.41.6-0+folio1~deb13u1")
        self.assertTrue(CVE_FOLLOWUP_NAME.endswith(".patch"))

    def test_debian_dsc_sha_manifest_exact(self):
        original=signed_dsc_content()
        self.assertEqual(_debian_signed_manifest(original),DEBIAN_SOURCE_FILES)
        for bad in (
            original.replace("Version: 2.41.5-0+deb13u1","Version: 2.42.4-1"),
            original.replace("Format: 3.0 (quilt)","Format: 1.0"),
            original.replace("Source: util-linux","Source: different"),
            original.replace("Maintainer: Chris Hofstaedtler",
                             "Maintainer: Changed Person"),
            original.replace(list(DEBIAN_SOURCE_FILES.values())[0][0],"f"*64),
            original+" "+next(iter(DEBIAN_SOURCE_FILES.values()))[0]+" 2 unexpected\n",
        ):
            with self.subTest(fragment=bad[:90]):
                with self.assertRaises(ValueError):
                    _debian_signed_manifest(bad)

    def test_exact_patch_series_drop_two_upstream_then_add_one_backport(self):
        official=(*RETAINED_DEBIAN_PATCHES,*UPSTREAM_PATCH_SERIES)
        expected=(*RETAINED_DEBIAN_PATCHES,CVE_FOLLOWUP_NAME)
        self.assertEqual(_expected_overlay_series(list(official)),list(expected))
        for bad in (
            list(official[:-1]),
            list(reversed(official)),
            list(official)+[official[0]],
            ["upstream/not-a-trixie-patch.patch",*official],
        ):
            with self.subTest(bad=str(bad)[:80]):
                with self.assertRaises(ValueError):
                    _expected_overlay_series(bad)

    def test_experimental_changelog_never_impersonates_debian(self):
        value=_local_changelog("util-linux (2.41.5-0+deb13u1) trixie-security;\n")
        self.assertIn("UNRELEASED",value)
        self.assertIn("LOCAL RESEARCH ONLY",value)
        self.assertIn(EXPERIMENT_VERSION,value)
        self.assertIn("noreply@invalid",value)
        self.assertTrue(value.endswith("trixie-security;\n"))
        with self.assertRaises(ValueError):
            _local_changelog("util-linux (2.42.4-1) unstable;\n")

    def test_duplicate_upstream_patch_guard_checks_forward_failure_and_reverse_success(self):
        class FakeRunner:
            def __init__(self,forward:int,reverse:int):
                self.forward=forward
                self.reverse=reverse
                self.calls=[]
            def __call__(self,patch:Path,reverse:bool)->int:
                self.calls.append((str(patch),reverse))
                return self.reverse if reverse else self.forward
        with tempfile.TemporaryDirectory() as d:
            paths=[Path(d)/name.replace("/","_") for name in UPSTREAM_PATCH_SERIES]
            for path in paths:
                path.write_text("diff --git a/a b/a\n")
            good=FakeRunner(1,0)
            _check_duplicate_upstream_patches(paths,good)
            self.assertEqual(len(good.calls),4)
            for fake in (FakeRunner(0,0),FakeRunner(1,1)):
                with self.assertRaises(ValueError):
                    _check_duplicate_upstream_patches(paths,fake)

    def test_reproducible_debian_source_timestamps_without_touching_upstream(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            debian=root/"debian"
            debian.mkdir()
            patches=debian/"patches"
            patches.mkdir()
            series=patches/"series"
            series.write_text("patched\n")
            vendor=root/"signed-upstream.tar.xz"
            vendor.write_bytes(b"upstream vendor archive unchanged")
            os.utime(series,(30,30))
            os.utime(vendor,(40,40))
            _normalize_debian_mtimes(debian)
            for path in (debian,patches,series):
                self.assertEqual(int(path.stat().st_mtime),SOURCE_DATE_EPOCH)
            self.assertEqual(int(vendor.stat().st_mtime),40)
            with self.assertRaises(ValueError):
                _normalize_debian_mtimes(vendor)

    def test_source_roundtrip_verifies_debian_patches_and_cve_semantics(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for path in ("debian/patches","sys-utils"):
                (root/path).mkdir(parents=True)
            (root/"debian/patches/series").write_text(
                "\n".join((*RETAINED_DEBIAN_PATCHES,CVE_FOLLOWUP_NAME))+"\n")
            (root/"debian/changelog").write_text(
                _local_changelog("util-linux (2.41.5-0+deb13u1) trixie-security;\n"))
            (root/"sys-utils/nsenter.c").write_bytes(b"placeholder")
            with self.assertRaises(ValueError):
                _assert_roundtrip_tree(root)
            (root/"debian/patches/series").write_text("unexpected\n")
            with self.assertRaises(ValueError):
                _assert_roundtrip_tree(root)

    def test_local_script_is_source_only_no_release_or_docker_build(self):
        script=(ROOT/"apps/inspector/fetch_util_linux_debian_source_overlay.sh").read_text()
        for string in (
            "util-linux_2.41.5-0","2.41.6.tar.xz",
            "debian_source_overlay.py","--proto '=https'",
            "485dbb67","exit 2",
        ):
            self.assertIn(string,script)
        for disallowed in (
            "docker build","docker push","docker system prune",
            "apt-get install","dpkg -i","dpkg-buildpackage","--ignorefile",
            "wrangler deploy","rm -rf /var","--ignore-unfixed",
        ):
            self.assertNotIn(disallowed,script)
        p=subprocess.run(
            ["bash","apps/inspector/fetch_util_linux_debian_source_overlay.sh","--bad"],
            cwd=ROOT,capture_output=True,text=True,timeout=8,
        )
        self.assertEqual(p.returncode,3)

    def test_missing_signed_artifacts_are_fail_closed_and_never_release(self):
        with tempfile.TemporaryDirectory() as d:
            p=subprocess.run(
                ["python3","apps/inspector/util_linux_debian_source_overlay.py",
                 "--artifacts-dir",d],
                cwd=ROOT,capture_output=True,text=True,timeout=10,
            )
            self.assertEqual(p.returncode,3)
            self.assertIn("release_authorized",p.stdout)
            self.assertFalse(json.loads(p.stdout)["release_authorized"])


if __name__=="__main__":
    unittest.main()
