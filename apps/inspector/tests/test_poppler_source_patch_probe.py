"""Fail-closed offline checks for the actual Debian-patched Poppler source package."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_source_patch_probe import (
    ARCHIVE_HASHES, ARCHIVE_NAMES, CODE_SYMBOLS, PATCH_SERIES,
    CVE_SOURCE_PATHS, inspect_archives, main,
)


def fake_package(*, bad_series=False, bad_patch=False, dsc_version=None):
    """Build simple in-memory stand-ins; test only policy, not dpkg mechanics."""
    import io
    import tarfile
    debian=io.BytesIO()
    with tarfile.open(fileobj=debian,mode="w:xz") as archive:
        patches="\n".join(PATCH_SERIES)+"\n"
        if bad_series:
            patches=patches.replace(PATCH_SERIES[0]+"\n","")
        records=[("debian/patches/series",patches)]
        records += [
            ("debian/patches/" + name,(
                "Bug-Debian-Security: https://security-tracker.debian.org/tracker/CVE-2026-10118\n"
                "poppler/SplashOutputDev.cc\n"
                "checkedMultiply(surface_width, repeatX, &result_width)"
                if not bad_patch else "Missing CVE and guard")
             if "SplashOutputDev-" in name else "synthetic non-target patch")
            for name in PATCH_SERIES
        ]
        for name, body in records:
            data=body.encode()
            member=tarfile.TarInfo(name)
            member.size=len(data)
            archive.addfile(member,io.BytesIO(data))
    orig=b"test original tarball fixture"
    deb=debian.getvalue()
    sha={ARCHIVE_NAMES["orig"]:hashlib.sha256(orig).hexdigest(),
         ARCHIVE_NAMES["debian"]:hashlib.sha256(deb).hexdigest()}
    dsc=(
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        "Format: 3.0 (quilt)\nSource: poppler\n"
        "Version: "+(dsc_version or "25.03.0-5+deb13u4")+"\n"
        "Checksums-Sha256:\n"
        + "".join(f" {sha[name]} {len(data)} {name}\n"
                  for name,data in ((ARCHIVE_NAMES["orig"],orig),
                                    (ARCHIVE_NAMES["debian"],deb)))
        +"-----BEGIN PGP SIGNATURE-----\nsynthetic\n"
    ).encode()
    archives={ARCHIVE_NAMES["dsc"]:dsc,ARCHIVE_NAMES["orig"]:orig,
              ARCHIVE_NAMES["debian"]:deb}
    expected={key:hashlib.sha256(data).hexdigest() for key,data in archives.items()}
    return archives,expected


def fake_dpkg_source(argv, **kwargs):
    """Exercise the real report code without invoking dpkg for tiny fake tars."""
    dest=Path(argv[-1])
    for source, symbols in CODE_SYMBOLS.items():
        file=dest/source
        file.parent.mkdir(parents=True,exist_ok=True)
        text="\n".join(symbols)
        if source=="poppler/SplashOutputDev.cc":
            text += "\ncheckedMultiply(surface_width, repeatX, &result_width)"
        file.write_text(text,encoding="utf-8")
    return subprocess.CompletedProcess(argv,0,stdout="synthetic dpkg-source",stderr="")


class PopplerSourceProbeTests(unittest.TestCase):
    def test_pinned_package_and_quilt_guard_do_not_clear_selected_cves(self):
        sources,digests=fake_package()
        report=inspect_archives(sources,expected_hashes=digests,runner=fake_dpkg_source)
        self.assertEqual(report["status"],"debian_source_evidence_partial")
        self.assertEqual(report["version"],"25.03.0-5+deb13u4")
        self.assertEqual(report["patch_count"],9)
        self.assertEqual(report["distinct_related_fix_cve"],"CVE-2026-10118")
        self.assertTrue(report["related_fix_present_in_extracted_source"])
        self.assertEqual(len(report["source_sha256"]),6)
        self.assertEqual(len(report["selected_cve_sources"]),10)
        self.assertEqual(set(report["selected_cve_sources"]),set(CVE_SOURCE_PATHS))
        self.assertEqual(report["selected_cve_sources"]["CVE-2026-93653"],
                         "poppler/SplashOutputDev.cc")
        self.assertEqual(report["selected_cve_sources"]["CVE-2026-102621"],
                         "splash/SplashClip.cc")
        self.assertFalse(report["jbig2_rewind_symbol_observed"])
        self.assertFalse(report["binary_equivalence_verified"])
        self.assertFalse(report["dsc_signature_verified_by_probe"])
        self.assertFalse(report["selected_cve_fixes_verified"])
        self.assertFalse(report["complete_source_advisory_coverage"])
        self.assertFalse(report["release_authorized"])

    def test_mutated_archive_wrong_dsc_version_and_quilt_metadata_fail_closed(self):
        cases=[("missing",{"omit":True}),
               ("bad_series",{"bad_series":True}),
               ("bad_patch",{"bad_patch":True}),
               ("wrong_version",{"dsc_version":"25.03.0-5+deb13u3"})]
        for label,options in cases:
            with self.subTest(label=label):
                args={key:value for key,value in options.items() if key not in ("omit",)}
                sources,digests=fake_package(**args)
                if "omit" in options:
                    del sources[ARCHIVE_NAMES["debian"]]
                with self.assertRaises(ValueError):
                    inspect_archives(sources,expected_hashes=digests,
                                     runner=fake_dpkg_source)
        sources,digests=fake_package()
        sources[ARCHIVE_NAMES["orig"]]=b"tampered-content"
        with self.assertRaises(ValueError):
            inspect_archives(sources,expected_hashes=digests,runner=fake_dpkg_source)

    def test_missing_symbol_or_unapplied_patch_never_reports_success(self):
        sources,digests=fake_package()
        def no_guard(argv,**kwargs):
            result=fake_dpkg_source(argv,**kwargs)
            dest=Path(argv[-1])
            file=dest/"poppler/SplashOutputDev.cc"
            file.write_text("\n".join(CODE_SYMBOLS["poppler/SplashOutputDev.cc"]))
            return result
        with self.assertRaises(ValueError):
            inspect_archives(sources,expected_hashes=digests,runner=no_guard)
        def absent_binary(argv,**kwargs):
            return subprocess.CompletedProcess(argv,1,stdout="",stderr="bad source")
        with self.assertRaises(ValueError):
            inspect_archives(sources,expected_hashes=digests,runner=absent_binary)

    def test_cli_never_claims_success_for_missing_offline_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            with (patch.object(sys,"argv",["poppler_source_patch_probe.py",
                                           "--directory",folder]),
                  patch("builtins.print") as output):
                self.assertEqual(main(),3)
                self.assertEqual(json.loads(output.call_args.args[0]),{
                    "status":"error","reason":"poppler_source_evidence_incomplete"})


if __name__=="__main__":
    unittest.main()
