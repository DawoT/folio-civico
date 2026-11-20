"""R1.37 static ELF surface cannot imply Debian ABI/release certification."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))

from util_linux_folio2_elf_surface import elf_surface, compare_elf_surfaces, LIBRARIES

class ELFStaticTDD(unittest.TestCase):
    def test_parser_captures_abi_visible_symbols_and_dependencies(self):
        dynamic = """
 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]
 0x000000000000000e (SONAME) Library soname: [libmount.so.1]
"""
        exports = """0000000 A MOUNT_2.40
0000100 T mnt_open@@MOUNT_2.40
0000200 W mnt_close@MOUNT_2.20
"""
        with patch("util_linux_folio2_elf_surface._run",
                   side_effect=[dynamic, exports]):
            result = elf_surface(Path("/tmp/unexecuted.so"))
        self.assertEqual(result["soname"], "libmount.so.1")
        self.assertEqual(result["needed"], ["libc.so.6"])
        self.assertIn("mnt_open@@MOUNT_2.40", result["symbols"])
        self.assertIn("mnt_close@MOUNT_2.20", result["symbols"])

    def test_missing_soname_rejected(self):
        with patch("util_linux_folio2_elf_surface._run",
                   side_effect=["(NEEDED) Shared library: [libc.so.6]", "1 T a"]):
            with self.assertRaises(ValueError):
                elf_surface(Path("/tmp/unexecuted.so"))

    def test_incomplete_or_public_baseline_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "prev"
            candidate = root / "next"
            baseline.mkdir(mode=0o700)
            candidate.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                compare_elf_surfaces(baseline, candidate)
            candidate.chmod(0o755)
            with self.assertRaises(ValueError):
                compare_elf_surfaces(baseline, candidate)

    def test_removed_versioned_symbol_is_recorded_as_regression(self):
        with tempfile.TemporaryDirectory() as temp:
            b = Path(temp) / "base"
            c = Path(temp) / "candidate"
            b.mkdir(mode=0o700)
            c.mkdir(mode=0o700)
            surfaces = []
            for idx, soname in enumerate(LIBRARIES.values()):
                surfaces.append({"soname": soname, "needed": ["libc.so.6"],
                                 "symbols": ["legacy@@VERSION", "stable@@VERSION"]})
                surfaces.append({"soname": soname, "needed": ["libc.so.6"],
                                 "symbols": (["stable@@VERSION"] if idx == 0
                                             else ["legacy@@VERSION", "stable@@VERSION"])})
            from util_linux_folio2_elf_surface import compare_elf_surfaces
            with patch("util_linux_folio2_elf_surface._extract",
                       return_value=Path("/tmp/never-executed.so")), \
                 patch("util_linux_folio2_elf_surface.elf_surface",
                       side_effect=surfaces):
                report = compare_elf_surfaces(b, c)
        self.assertTrue(report["static_elf_regression_detected"])
        self.assertIn("legacy@@VERSION", report["libraries"][0]["removed_exports"])
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["debian_trixie_abi_validated"])

    def test_dso_set_fixed_and_never_claims_abi_approval(self):
        self.assertEqual(len(LIBRARIES), 5)
        source = (ROOT / "apps/inspector/util_linux_folio2_elf_surface.py").read_text()
        self.assertIn('"debian_trixie_abi_validated": False', source)
        self.assertIn('"release_authorized": False', source)
        self.assertIn('"folio1_experimental_not_official_debian"', source)
        self.assertIn('"debian_trixie_2.41.5_signed_apt"', source)
        for forbidden in ("dpkg -i", "docker push", "wrangler deploy"):
            self.assertNotIn(forbidden, source)

if __name__ == "__main__":
    unittest.main()
