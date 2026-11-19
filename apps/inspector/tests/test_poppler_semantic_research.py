"""R1.13: semantic evidence is not CVE repair or runtime admission."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_semantic_research import (
    CHANGED_PATHS, DIRECT_FIXES, RESEARCH_PROTOTYPES,
    REQUIRED_MARKERS, UNRESOLVED_MARKERS,
    _run, inspect_semantic_prototypes, main,
    semantic_markers, validate_research_patches,
)
from poppler_source_patch_probe import CVE_SOURCE_PATHS
from test_poppler_backport_feasibility import fake_fixes
from test_poppler_source_patch_probe import fake_package, fake_dpkg_source


FIXTURES = Path(__file__).resolve().parents[1] / "research_patches"


def prototype_bytes():
    return {
        cve: (FIXTURES / f"{cve}-trixie-prototype.patch").read_bytes()
        for cve in RESEARCH_PROTOTYPES
    }


class FakeSemanticRunner:
    """Only testing report policy, not simulating a real patch application."""
    def __init__(self, *, corrupt_source=False, missing_marker=False, failed=False):
        self.corrupt_source = corrupt_source
        self.missing_marker = missing_marker
        self.failed = failed
        self.called = []

    def __call__(self, argv, **kwargs):
        if argv[0] == "dpkg-source":
            return fake_dpkg_source(argv, **kwargs)
        if argv[0] != "patch":
            raise AssertionError("Unexpected source command")
        if "--fuzz=0" not in argv or "--forward" not in argv:
            raise AssertionError("Strict patch options missing")
        cve = Path(argv[-1]).stem
        self.called.append(cve)
        target = CVE_SOURCE_PATHS[cve]
        if self.failed:
            return subprocess.CompletedProcess(argv, 1, stdout="Hunk #1 FAILED", stderr="")
        file = Path(kwargs["cwd"]) / target
        content = file.read_text()
        if cve == "CVE-2026-102620":
            content += "\ncheckedAdd(length, locaTable[j].len, &length)\n"
            content += "length += 4 - (length & 3);\n"
        elif cve == "CVE-2026-93311":
            content += "\nsampleBits < 1 || sampleBits > 32\n"
            content += "bitMask = static_cast<unsigned int>((1ULL << sampleBits) - 1);\n"
        elif cve == "CVE-2026-102621":
            if not self.missing_marker:
                content += "\ncheckedMultiply(yMinI, splashAASize, &yMinAA)\n"
            content += "return splashErrGeneric;\n"
            content += "yMaxAA = (yMaxI + 1) * splashAASize - 1;\n"
        elif cve == "CVE-2026-93312":
            content += "\nbool JBIG2Stream::reset()\n"
            content += "if (pageBitmap && pageBitmap->isOk()) {\n"
        elif cve == "CVE-2026-93313":
            content += "\ncheckedSubtraction(lowVal, 1, &lowValMinusOne)\n"
            content += "huffTab[i].val = lowValMinusOne;\n"
        else:
            raise AssertionError(cve)
        file.write_text(content)
        if self.corrupt_source:
            Path(kwargs["cwd"], "poppler/Decrypt.cc").write_text("unrelated mutation")
        return subprocess.CompletedProcess(
            argv, 0, stdout="patching file " + target + "\n", stderr=""
        )


class PopplerSemanticResearchTests(unittest.TestCase):
    def _report(self, runner=None):
        original, hashes = fake_package()
        fixes, fix_digests = fake_fixes()
        runner = runner or FakeSemanticRunner()
        result = inspect_semantic_prototypes(
            original, fixes, prototype_bytes(),
            source_hashes=hashes, fix_hashes=fix_digests, runner=runner,
        )
        return result, runner

    def test_research_bundle_has_three_exact_targets_and_fixed_digests(self):
        patches = prototype_bytes()
        self.assertEqual(
            validate_research_patches(patches),
            RESEARCH_PROTOTYPES,
        )
        self.assertEqual(set(CHANGED_PATHS), {
            "fofi/FoFiTrueType.cc", "poppler/Function.cc",
            "splash/SplashClip.cc", "poppler/JBIG2Stream.cc",
        })
        for name in patches:
            self.assertIn(("--- a/" + CVE_SOURCE_PATHS[name]).encode(), patches[name])
        self.assertEqual(len(DIRECT_FIXES), 2)

    def test_patch_tamper_missing_or_untrusted_path_fails_closed(self):
        patches = prototype_bytes()
        chosen = "CVE-2026-102621"
        broken = dict(patches)
        broken[chosen] += b"\n"
        with self.assertRaises(ValueError):
            validate_research_patches(broken)
        broken = dict(patches)
        broken.pop(chosen)
        with self.assertRaises(ValueError):
            validate_research_patches(broken)
        broken = dict(patches)
        broken[chosen] = broken[chosen].replace(
            b"--- a/splash/SplashClip.cc", b"--- a/../../etc/passwd",
        )
        digest = dict(RESEARCH_PROTOTYPES)
        digest[chosen] = hashlib.sha256(broken[chosen]).hexdigest()
        with self.assertRaises(ValueError):
            validate_research_patches(broken, digest)

    def test_staged_source_never_claims_fix_or_release(self):
        report, runner = self._report()
        self.assertEqual(report["status"], "research_source_prototypes_only")
        self.assertEqual(len(runner.called), 5)
        self.assertEqual(runner.called, list(DIRECT_FIXES) + list(RESEARCH_PROTOTYPES))
        self.assertEqual(len(report["prototype_source_sha256"]), 6)
        self.assertTrue(all(report["semantic_markers"].values()))
        for key in ("all_selected_cve_fixes_verified", "cve_remediation_claimed",
                    "runtime_compilation_verified", "binary_equivalence_verified",
                    "backports_approved", "complete_source_advisory_coverage",
                    "release_authorized"):
            self.assertFalse(report[key], key)
        self.assertIn("glyph_alignment_arithmetic_requires_review",
                      report["unresolved_issues"])

    def test_unresolved_arithmetic_hazards_stay_explicit(self):
        report, _ = self._report()
        self.assertTrue(
            REQUIRED_MARKERS | UNRESOLVED_MARKERS <=
            set(k for k, value in report["semantic_markers"].items() if value)
        )
        markers = dict(report["semantic_markers"])
        self.assertTrue(markers["splash_ymax_still_unchecked"])
        self.assertTrue(markers["glyph_alignment_still_unchecked"])
        self.assertTrue(markers["jbig2_rewind_symbol_absent"])

    def test_missing_semantic_guard_or_unrelated_mutation_fails_closed(self):
        with self.assertRaises(ValueError):
            self._report(FakeSemanticRunner(missing_marker=True))
        with self.assertRaises(ValueError):
            self._report(FakeSemanticRunner(corrupt_source=True))
        with self.assertRaises(ValueError):
            self._report(FakeSemanticRunner(failed=True))

    def test_command_failure_and_timeout_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary)
            def fail(*a, **kw):
                return subprocess.CompletedProcess(a[0], 1, stdout="", stderr="")
            with self.assertRaises(ValueError):
                _run(["patch"], cwd, fail, 30)
            def timeout(*a, **kw):
                raise subprocess.TimeoutExpired(a[0], 30)
            with self.assertRaises(ValueError):
                _run(["patch"], cwd, timeout, 30)

    def test_no_unverified_artifacts_cli_exit_three(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(sys, "argv", [
                    "poppler_semantic_research.py",
                    "--source-directory", temporary, "--fix-directory", temporary,
                ]), patch("builtins.print") as output:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(output.call_args.args[0]), {
                    "status": "error",
                    "reason": "poppler_semantic_source_evidence_incomplete",
                })


if __name__ == "__main__":
    unittest.main()
