"""R1.14: source-only research builds must never masquerade as release gates."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_isolated_sanitizer import (
    _sha_manifest,
    build_baseline_args, build_container_args, compare_synthetic_parity,
    clipped_pdf, create_fixture_files, inspect_isolated_build,
    inspect_results, main, sampled_32bit_pdf,
)
from poppler_semantic_research import RESEARCH_PROTOTYPES


ID = "sha256:" + "c" * 64


class PopplerIsolatedSanitizerTests(unittest.TestCase):
    def test_exact_image_identity_and_container_isolation_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            folders = [Path(tmp) / p for p in ("fix", "research", "fixtures", "results")]
            for folder in folders:
                folder.mkdir()
            cmd = build_container_args(ID, *folders)
        self.assertEqual(cmd[0:3], ["docker", "run", "--rm"])
        self.assertEqual(cmd[cmd.index("--pull") + 1], "never")
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertEqual(cmd[cmd.index("--user") + 1], "65534:65534")
        self.assertIn("--read-only", cmd)
        self.assertEqual(cmd[cmd.index("--cap-drop") + 1], "ALL")
        self.assertEqual(cmd[cmd.index("--security-opt") + 1], "no-new-privileges")
        self.assertEqual(cmd[-2:], [ID, "/prototypes/build_sanitized_poppler.sh"])
        self.assertEqual(sum("readonly" in x for x in cmd), 3)
        self.assertNotIn("push", cmd)
        self.assertNotIn("--privileged", cmd)

    def test_baseline_is_readonly_offline_and_unprivileged(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixtures, results = Path(tmp) / "fixtures", Path(tmp) / "results"
            fixtures.mkdir()
            results.mkdir()
            args = build_baseline_args(ID, fixtures, results)
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--pull") + 1], "never")
        self.assertEqual(args[args.index("--user") + 1], "65534:65534")
        self.assertIn("--read-only", args)
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        self.assertNotIn("push", args)
        with tempfile.TemporaryDirectory() as tmp:
            suspicious = Path(tmp) / "comma,name"
            suspicious.mkdir()
            with self.assertRaises(ValueError):
                build_baseline_args(ID, suspicious, suspicious)

    def test_unpinned_builder_or_mount_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inputs = [base / x for x in ("fix", "patches", "input", "results")]
            for d in inputs:
                d.mkdir()
            for value in ("folio-civico-inspector:validation", "sha256:xyz", ""):
                with self.assertRaises(ValueError):
                    build_container_args(value, *inputs)
            link = base / "link"
            link.symlink_to(inputs[0], target_is_directory=True)
            with self.assertRaises(ValueError):
                build_container_args(ID, link, *inputs[1:])
            suspicious = base / "comma,name"
            suspicious.mkdir()
            with self.assertRaises(ValueError):
                build_container_args(ID, suspicious, *inputs[1:])

    def test_source_and_patch_manifest_blocks_traversal(self):
        digest = hashlib.sha256(b"test-only").hexdigest()
        self.assertEqual(
            _sha_manifest({"foo/bar.cc": digest}),
            f"{digest}  foo/bar.cc\n".encode(),
        )
        for key in ("../escape", "/absolute", "space name", "bad\nname"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                _sha_manifest({key: digest})
        with self.assertRaises(ValueError):
            _sha_manifest({"foo": "invalid"})

    def test_synthetic_input_corpus_is_local_bounded_and_reproducible(self):
        for make in (clipped_pdf, sampled_32bit_pdf):
            blob = make()
            self.assertEqual(blob, make())
            self.assertTrue(blob.startswith(b"%PDF-"))
            self.assertLess(len(blob), 8192)
        sampled = sampled_32bit_pdf()
        self.assertIn(b"/BitsPerSample 32", sampled)
        self.assertIn(b"/FunctionType 0", sampled)
        clipped = clipped_pdf()
        self.assertIn(b"W n", clipped)
        with tempfile.TemporaryDirectory() as tmp:
            fake = {
                "baseline_sha256": {"poppler/Function.cc": hashlib.sha256(b"a").hexdigest()},
                "prototype_source_sha256": {"poppler/Function.cc": hashlib.sha256(b"b").hexdigest()},
            }
            path = Path(tmp)
            create_fixture_files(path, fake)
            self.assertEqual(sorted(p.name for p in path.glob("*.pdf")), [
                "clipped.pdf", "native.pdf", "sampled32.pdf",
                "scanned.pdf", "truncated.pdf",
            ])

    def test_missing_or_blank_raster_and_fake_text_layer_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            def write(name, pixels):
                (folder / (name + ".pgm")).write_bytes(b"P5\n10 10\n255\n" + pixels)
            for name in ("native", "scanned", "clipped", "sampled32"):
                write(name, b"\x00" * 100)
            (folder / "native.txt").write_text("EXPEDIENTE OBRA 2026\n")
            (folder / "scanned.txt").write_text("\f")
            report = inspect_results(folder)
            self.assertEqual(len(report), 4)
            write("native", b"\xff" * 100)
            with self.assertRaises(RuntimeError):
                inspect_results(folder)
            write("native", b"\x00" * 100)
            (folder / "scanned.txt").write_text("Falsified text\n")
            with self.assertRaises(ValueError):
                inspect_results(folder)
            (folder / "scanned.txt").unlink()
            (folder / "scanned.txt").symlink_to(folder / "native.txt")
            with self.assertRaises(ValueError):
                inspect_results(folder)

    def test_pixel_or_text_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline, patched = root / "baseline", root / "patched"
            baseline.mkdir()
            patched.mkdir()
            def fixtures(folder):
                for name in ("native", "scanned", "clipped", "sampled32"):
                    (folder / (name + ".pgm")).write_bytes(
                        b"P5\n10 10\n255\n" + b"\x00" * 100
                    )
                (folder / "native.txt").write_text("EXPEDIENTE OBRA 2026\n")
                (folder / "scanned.txt").write_text("\f")
            fixtures(baseline)
            fixtures(patched)
            self.assertEqual(compare_synthetic_parity(baseline, patched), {
                "four_rasters_pixel_identical": True,
                "two_text_outputs_identical": True,
            })
            (patched / "clipped.pgm").write_bytes(
                b"P5\n10 10\n255\n" + b"\x00" * 99 + b"\x11"
            )
            with self.assertRaises(ValueError):
                compare_synthetic_parity(baseline, patched)
            fixtures(patched)
            (patched / "native.txt").write_text("EXPEDIENTE OBRA 2026 altered\n")
            with self.assertRaises(ValueError):
                compare_synthetic_parity(baseline, patched)

    def test_a_fake_container_success_without_real_outputs_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            patches = base / "patches"
            fixes = base / "fixes"
            patches.mkdir()
            fixes.mkdir()
            dummy = {
                "baseline_sha256": {"poppler/Function.cc": hashlib.sha256(b"a").hexdigest()},
                "prototype_source_sha256": {"poppler/Function.cc": hashlib.sha256(b"b").hexdigest()},
                "base_source_version": "25.03.0-5+deb13u4",
                "research_patch_sha256": RESEARCH_PROTOTYPES,
            }
            fake_success = subprocess.CompletedProcess([], 0, stdout=(
                '{"build":"asan_ubsan_complete","native_pdf":"parsed",'
                '"scan_pdf":"parsed","clip_pdf":"rendered",'
                '"sampled_function_32bit":"rendered","pdfinfo_sanitized_link_verified":false,"malformed_exit":1,'
                '"release_authorized":false}\n'
            ), stderr="")
            with patch("poppler_isolated_sanitizer.inspect_semantic_prototypes",
                       return_value=dummy):
                with self.assertRaises(ValueError):
                    inspect_isolated_build(
                        {}, {}, {}, builder_id=ID,
                        prototype_directory=patches, fix_directory=fixes,
                        runner=lambda *a, **kw: fake_success,
                    )

    def test_cli_rejects_missing_inputs_without_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(sys, "argv", [
                "poppler_isolated_sanitizer.py",
                "--source-directory", tmp,
                "--fix-directory", tmp,
                "--builder-image-id", ID,
            ]), patch("builtins.print") as printer:
                self.assertEqual(main(), 3)
                self.assertEqual(json.loads(printer.call_args.args[0]), {
                    "reason": "isolated_poppler_sanitizer_evidence_incomplete",
                    "release_authorized": False,
                    "status": "error",
                })


if __name__ == "__main__":
    unittest.main()
