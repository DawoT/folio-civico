"""R1.35: admit only the exact unsigned R1.34 source handoff, never a release."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))

from util_linux_trixie_binary_experiment import validate_handoff, verify_binary_inventory, IMAGE_DIGEST, BUILD_PATCH, BUILD_PATCH_SHA256, LOGIN_VERSION, BSDUTILS_VERSION, PATCHED_IDMAP_SHA256
from util_linux_debian_source_overlay import EXPERIMENT_VERSION, VERSION, TAR_SHA256

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class TrixieBinaryGateTDD(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.src = self.root / "input"
        self.src.mkdir(mode=0o700)
        self.payloads = {
            f"util-linux_{VERSION}.orig.tar.xz": b"original",
            f"util-linux_{EXPERIMENT_VERSION}.dsc": b"unsigned dsc",
            f"util-linux_{EXPERIMENT_VERSION}.debian.tar.xz": b"quilt",
        }
        for name, payload in self.payloads.items():
            p = self.src / name
            p.write_bytes(payload)
            p.chmod(0o600)
        self.manifest = {
            "status": "unsigned_source_only_handoff_release_blocked",
            "experimental_debian_version": EXPERIMENT_VERSION,
            "source_roundtrip_verified": True,
            "upstream_signatures_verified": True,
            "debian_original_dsc_signed": True,
            "experimental_dsc_signed": False,
            "debian_binary_packages_built": False,
            "runtime_image_replaced": False,
            "vex": "not_issued",
            "release_authorized": False,
            "source_date_epoch": 1795190400,
            "sha256": {name: sha(payload) for name,payload in self.payloads.items()},
        }
        self.report = self.src / "UNSIGNED_SOURCE_ONLY.json"
        self._save()

    def _save(self):
        self.report.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.report.chmod(0o600)

    def valid(self):
        # The test substitutes only the signed upstream source digest;
        # real executions use the immutable production SHA-256 constant.
        from unittest.mock import patch
        with patch("util_linux_trixie_binary_experiment.TAR_SHA256",
                   sha(self.payloads[f"util-linux_{VERSION}.orig.tar.xz"])), \
             patch("util_linux_trixie_binary_experiment.PINNED", tuple(self.manifest["sha256"].values())):
            return validate_handoff(self.src)

    def test_exact_handoff_admitted_only_as_blocked_candidate(self):
        result = self.valid()
        self.assertEqual(set(result["source_sha256"]), set(self.payloads))
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["builder_image_digest"], IMAGE_DIGEST)
        self.assertFalse(result["debian_binary_packages_built"])

    def test_tampered_or_incomplete_manifest_is_rejected(self):
        mutations = [
            ("release_authorized", True),
            ("upstream_signatures_verified", False),
            ("debian_original_dsc_signed", False),
            ("source_roundtrip_verified", False),
            ("experimental_dsc_signed", True),
            ("debian_binary_packages_built", True),
            ("source_date_epoch", 42),
            ("experimental_debian_version", "2.42.4-1"),
            ("vex", "not_affected"),
        ]
        for key, value in mutations:
            with self.subTest(key=key):
                previous = self.manifest[key]
                self.manifest[key] = value
                self._save()
                with self.assertRaises(ValueError):
                    self.valid()
                self.manifest[key] = previous
        self._save()

    def test_reject_unknown_files_and_modified_payloads(self):
        extra = self.src / "x.deb"
        extra.write_bytes(b"do-not-install")
        with self.assertRaises(ValueError):
            self.valid()
        extra.unlink()
        orig = self.src / next(iter(self.payloads))
        orig.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.valid()

    def test_reject_symlinked_sources_and_excessive_permissions(self):
        self.src.chmod(0o755)
        with self.assertRaises(ValueError):
            self.valid()
        self.src.chmod(0o700)
        first = self.src / next(iter(self.payloads))
        first.unlink()
        first.symlink_to(self.report)
        with self.assertRaises(ValueError):
            self.valid()

    def _synthetic_binary(self, version=EXPERIMENT_VERSION, source="", package="util-linux"):
        # Minimal testing-only archive produced without installing software.
        data = self.root / "fake_pkg"
        (data / "DEBIAN").mkdir(parents=True, exist_ok=True)
        (data / "DEBIAN/control").write_text(
            f"Package: {package}\n"
            f"Version: {version}\n"
            "Architecture: amd64\n"
            "Maintainer: Local test <test@invalid>\n"
            f"{'Source: ' + source + chr(10) if source else ''}"
            "Description: Synthetic test-only package\n"
        )
        out = self.root / "binary"
        out.mkdir(mode=0o700, exist_ok=True)
        (out / "NOT_FOR_RELEASE.txt").write_text("NOT FOR RELEASE")
        (out / "BINARY_RESEARCH_ONLY.txt").write_text("SYNTHETIC")
        (out / "BUILD_ONLY_OPENAT2_SOURCE_SHA256.txt").write_text(
            PATCHED_IDMAP_SHA256 + "  libmount/src/hook_idmap.c\n")
        deb = out / f"{package}_synthetic_amd64.deb"
        subprocess.run(["dpkg-deb", "--build", str(data), str(deb)],
                       check=True, capture_output=True, timeout=15)
        return out, deb

    def test_synthetic_binary_inventory_never_claims_abi_or_release(self):
        output, _ = self._synthetic_binary()
        report = verify_binary_inventory(output, self.valid())
        self.assertTrue(report["debian_binary_packages_built"])
        self.assertFalse(report["debian_trixie_abi_validated"])
        self.assertFalse(report["cve_remediated"])
        self.assertFalse(report["release_authorized"])
        self.assertEqual(len(report["packages"]), 1)
        self.assertEqual(report["packages"][0]["name"], "util-linux")
        self.assertTrue((output / "UNSIGNED_BINARY_RESEARCH_ONLY.json").exists())
        with self.assertRaises(ValueError):
            verify_binary_inventory(output, self.valid())

    def test_debian_login_special_version_is_explicit_and_bounded(self):
        output, _ = self._synthetic_binary()
        _, login = self._synthetic_binary(LOGIN_VERSION, source="util-linux",
                                         package="login")
        report = verify_binary_inventory(output, self.valid())
        versions = {item["name"]: item["version"] for item in report["packages"]}
        self.assertEqual(versions["login"], LOGIN_VERSION)
        self.assertEqual(versions["util-linux"], EXPERIMENT_VERSION)
        self.assertEqual(report["debian_login_binary_version"], LOGIN_VERSION)

        # An incorrectly versioned login package must never pass admission.
        login.unlink()
        manifest = output / "UNSIGNED_BINARY_RESEARCH_ONLY.json"
        manifest.unlink()
        self._synthetic_binary(EXPERIMENT_VERSION, source="util-linux",
                               package="login")
        with self.assertRaises(ValueError):
            verify_binary_inventory(output, self.valid())

    def test_tampered_build_patch_provenance_blocks_binary_inventory(self):
        output, _ = self._synthetic_binary()
        marker = output / "BUILD_ONLY_OPENAT2_SOURCE_SHA256.txt"
        marker.write_text("0" * 64 + "  libmount/src/hook_idmap.c\n")
        with self.assertRaises(ValueError):
            verify_binary_inventory(output, self.valid())

    def test_debian_bsdutils_epoch_is_explicit_and_bounded(self):
        output, _ = self._synthetic_binary()
        self._synthetic_binary(BSDUTILS_VERSION, source="util-linux",
                               package="bsdutils")
        report = verify_binary_inventory(output, self.valid())
        versions = {item["name"]: item["version"] for item in report["packages"]}
        self.assertEqual(versions["bsdutils"], BSDUTILS_VERSION)
        self.assertEqual(report["debian_bsdutils_binary_version"], BSDUTILS_VERSION)
        (output / "UNSIGNED_BINARY_RESEARCH_ONLY.json").unlink()
        (output / "bsdutils_synthetic_amd64.deb").unlink()
        self._synthetic_binary(EXPERIMENT_VERSION, source="util-linux",
                               package="bsdutils")
        with self.assertRaises(ValueError):
            verify_binary_inventory(output, self.valid())

    def test_wrong_version_and_foreign_files_block_binary_inventory(self):
        output, deb = self._synthetic_binary("2.41.5-0+deb13u1")
        with self.assertRaises(ValueError):
            verify_binary_inventory(output, self.valid())
        deb.unlink()
        # A valid source version with an unexpected Source field is rejected.
        _, deb = self._synthetic_binary(source="unrelated-source")
        with self.assertRaises(ValueError):
            verify_binary_inventory(output, self.valid())
        deb.unlink()
        _, deb = self._synthetic_binary()
        (output / "foreign-file").write_text("unsafe")
        with self.assertRaises(ValueError):
            verify_binary_inventory(output, self.valid())

    def test_build_only_include_patch_is_pinned_and_forward_only(self):
        self.assertEqual(sha(BUILD_PATCH.read_bytes()), BUILD_PATCH_SHA256)
        self.assertEqual(BUILD_PATCH.read_text().count("+# include <linux/openat2.h>"), 1)
        from unittest.mock import patch
        with patch("util_linux_trixie_binary_experiment.BUILD_PATCH_SHA256", "0" * 64):
            with self.assertRaises(ValueError):
                self.valid()

        src = self.root / "temp-source"
        target = src / "libmount/src/hook_idmap.c"
        target.parent.mkdir(parents=True)
        target.write_text(
            "/* test-only source */\n" * 17
            + "#include <stdbool.h>\n"
            + "#include <sys/socket.h>\n"
            + "#include <sys/wait.h>\n"
            + "#include <sys/ioctl.h>\n"
            + "#include <sys/mount.h>\n"
            + '\n#include "strutils.h"\n#include "all-io.h"\n'
        )
        before = target.read_text()
        def git(*args):
            return subprocess.run(["git", "apply", *args, str(BUILD_PATCH)],
                                  cwd=src, capture_output=True, timeout=10).returncode
        self.assertEqual(git("--check"), 0)
        self.assertEqual(git(), 0)
        self.assertIn("# include <linux/openat2.h>", target.read_text())
        self.assertNotEqual(git("--check"), 0)
        self.assertEqual(git("--reverse", "--check"), 0)
        self.assertNotEqual(before, target.read_text())

    def test_binary_builder_is_isolated_and_never_publishes(self):
        script = (ROOT / "apps/inspector/build_util_linux_trixie_binary_experiment.sh").read_text()
        for token in ("--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                      "--network", "--memory", "dpkg-buildpackage",
                      "--tmpfs /tmp:", '--user "$(id -u):$(id -g)"',
                      "util_linux_trixie_binary_experiment.py", "preflight.py"):
            self.assertIn(token, script)
        for forbidden in ("docker push", "wrangler deploy", "docker system prune",
                          "docker volume prune", "docker build", "dpkg -i", "--ignore-unfixed"):
            self.assertNotIn(forbidden, script)

if __name__ == "__main__":
    unittest.main()
