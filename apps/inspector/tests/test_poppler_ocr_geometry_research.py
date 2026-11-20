"""R1.33: source-image per-page PDF geometry evidence, never a runtime guard."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_ocr_geometry_research import (
    EXPECTED_CORPUS_SHA256, PROVISIONAL_MAX_PIXELS, PROVISIONAL_MAX_SIDE,
    build_pdfinfo_args, inspect_pdfinfo_geometry, synthetic_geometry_pdf,
)


def real_format_info() -> str:
    # Format measured with pdfinfo 25.03.0 -f 1 -l 4 -box on synthetic input.
    return """Pages:           4
Encrypted:       no
Page    1 size:  595 x 842 pts (A4)
Page    1 rot:   0
Page    2 size:  5.36871e+08 x 1 pts
Page    2 rot:   0
Page    3 size:  842 x 595 pts (A4)
Page    3 rot:   90
Page    4 size:  200 x 200 pts
Page    4 rot:   0
Page    1 MediaBox:      0.00     0.00   595.00   842.00
Page    2 MediaBox:      0.00     0.00 536870919.00     1.00
Page    3 MediaBox:      0.00     0.00   842.00   595.00
Page    4 MediaBox:      0.00     0.00   200.00   200.00
"""


class GeometryResearchTests(unittest.TestCase):
    def test_corpus_is_pinned_and_contains_mixed_page_geometry(self):
        blob = synthetic_geometry_pdf()
        self.assertLess(len(blob), 2048)
        self.assertTrue(blob.startswith(b"%PDF-1.6\n"))
        self.assertEqual(hashlib.sha256(blob).hexdigest(), EXPECTED_CORPUS_SHA256)
        self.assertIn(b"/MediaBox [0 0 536870919 1]", blob)
        self.assertIn(b"/Rotate 90", blob)
        self.assertIn(b"/UserUnit 5", blob)

    def test_all_pages_have_conservative_180_dpi_estimates(self):
        result = inspect_pdfinfo_geometry(real_format_info())
        pages = result["pages"]
        self.assertEqual([x["page"] for x in pages], [1, 2, 3, 4])
        self.assertEqual(
            (pages[0]["estimated_width_px_upper_bound"],
             pages[0]["estimated_height_px_upper_bound"]), (1488, 2106))
        self.assertGreater(pages[1]["estimated_width_px_upper_bound"], 1_000_000_000)
        self.assertTrue(pages[1]["provisional_budget_exceeded"])
        self.assertEqual(
            (pages[2]["estimated_width_px_upper_bound"],
             pages[2]["estimated_height_px_upper_bound"]), (1488, 2106))
        self.assertEqual(
            (pages[3]["estimated_width_px_upper_bound"],
             pages[3]["estimated_height_px_upper_bound"]), (501, 501))
        self.assertLess(pages[0]["estimated_pixels_upper_bound"], PROVISIONAL_MAX_PIXELS)
        self.assertLess(pages[0]["estimated_width_px_upper_bound"], PROVISIONAL_MAX_SIDE)
        self.assertFalse(result["runtime_guard_implemented"])
        self.assertFalse(result["user_unit_effect_verified"])
        self.assertFalse(result["release_authorized"])

    def test_missing_or_duplicate_page_records_fail_closed(self):
        raw = real_format_info()
        for altered in (
            raw.replace("Page    2 MediaBox:      0.00     0.00 536870919.00     1.00\n", ""),
            raw + "Page    1 rot: 0\n",
            raw + "Page    5 size: 200 x 200 pts\n",
            raw + "Page    1 MediaBox: 0 0 NaN 842\n",
            raw + "Page    1 size: invalid\n",
            raw.replace("Pages:           4", "Pages:           5"),
            raw.replace("Encrypted:       no", "Encrypted:       yes"),
        ):
            with self.subTest(candidate=altered[-70:]), self.assertRaises(ValueError):
                inspect_pdfinfo_geometry(altered)

    def test_malformed_and_inconsistent_geometry_fail_closed(self):
        raw = real_format_info()
        for altered in (
            raw.replace("536870919.00", "NaN"),
            raw.replace("842.00", "-842.00", 1),
            raw.replace("Page    3 rot:   90", "Page    3 rot:   45"),
            raw.replace("Page    1 size:  595 x 842", "Page    1 size:  300 x 842"),
            raw.replace("536870919.00", "536870919.00 extra", 1),
        ):
            with self.subTest(candidate=altered[-70:]), self.assertRaises(ValueError):
                inspect_pdfinfo_geometry(altered)

    def test_truncated_oversized_or_non_ascii_report_fails_closed(self):
        for raw in ("", "Pages: 4\n", "x" * 66000, real_format_info() + "\u202e"):
            with self.subTest(n=len(raw)), self.assertRaises(ValueError):
                inspect_pdfinfo_geometry(raw)

    def test_mutated_mounted_fixture_cannot_be_reported_as_real_evidence(self):
        from subprocess import CompletedProcess
        from poppler_ocr_geometry_research import (
            EXPECTED_EXPERIMENTAL_ELF_SHA256, inspect_local_image,
        )
        def fake_runner(argv, **kwargs):
            if "/usr/bin/sha256sum" in argv:
                digest = "".join(
                    f"{sha}  {name}\n"
                    for name, sha in EXPECTED_EXPERIMENTAL_ELF_SHA256.items()
                )
                return CompletedProcess(argv, 0, digest, "")
            mount = next(arg for arg in argv if arg.startswith("type=bind,source="))
            folder = mount.removeprefix("type=bind,source=").split(",target=", 1)[0]
            fixture = Path(folder) / "synthetic.pdf"
            fixture.write_bytes(fixture.read_bytes() + b"\n% synthetic tamper\n")
            return CompletedProcess(argv, 0, real_format_info(), "")

        with self.assertRaises(ValueError):
            inspect_local_image("sha256:" + "a" * 64, runner=fake_runner)

    def test_runtime_limits_not_declared_from_only_pdfinfo(self):
        result = inspect_pdfinfo_geometry(real_format_info())
        self.assertFalse(result["source_binary_equivalence_to_runtime_verified"])
        self.assertFalse(result["page_geometry_safe_for_untrusted_pdf_verified"])
        self.assertTrue(result["metadata_requires_independent_user_unit_review"])

    def test_png_header_controls_are_verified_before_acceptance(self):
        import struct
        import zlib
        from poppler_ocr_geometry_research import verify_png_geometry

        def chunk(name: bytes, payload: bytes) -> bytes:
            return (struct.pack(">I", len(payload)) + name + payload
                    + struct.pack(">I", zlib.crc32(name + payload) & 0xffffffff))

        png = (b"\x89PNG\r\n\x1a\n"
               + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
               + chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff" * 4))
               + chunk(b"IEND", b""))
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "control.png"
            file.write_bytes(png)
            self.assertEqual(verify_png_geometry(file), (2, 2))
            file.write_bytes(png[:20])
            with self.assertRaises(ValueError):
                verify_png_geometry(file)
            file.write_bytes(png + b"extra")
            with self.assertRaises(ValueError):
                verify_png_geometry(file)
            file.write_bytes(png[:29] + b"\x00\x00\x00\x00" + png[33:])
            with self.assertRaises(ValueError):
                verify_png_geometry(file)

    def test_experimental_elf_digest_identity_rejects_partial_or_altered_evidence(self):
        from poppler_ocr_geometry_research import (
            EXPECTED_EXPERIMENTAL_ELF_SHA256, parse_experimental_elf_digests,
        )
        sample = "".join(
            f"{sha}  {path}\n"
            for path, sha in EXPECTED_EXPERIMENTAL_ELF_SHA256.items()
        )
        self.assertEqual(parse_experimental_elf_digests(sample),
                         EXPECTED_EXPERIMENTAL_ELF_SHA256)
        for bad in (
            sample.replace("3ca61c1", "fca61c1", 1),
            sample.splitlines(keepends=True)[1] + sample.splitlines(keepends=True)[2],
            sample + "0" * 64 + "  /tmp/fake\n",
        ):
            with self.subTest(bad=bad[:30]), self.assertRaises(ValueError):
                parse_experimental_elf_digests(bad)

    def test_small_raster_arguments_skip_extreme_page(self):
        from poppler_ocr_geometry_research import build_small_raster_args
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_dir, result_dir = root / "in", root / "out"
            input_dir.mkdir()
            result_dir.mkdir()
            image = "sha256:" + "a" * 64
            for page in (1, 3, 4):
                args = build_small_raster_args(image, input_dir, result_dir, page)
                self.assertIn("-png", args)
                self.assertIn("180", args)
                self.assertEqual(args[args.index("-f") + 1], str(page))
                self.assertEqual(args[args.index("-l") + 1], str(page))
                self.assertIn("--network", args)
                self.assertIn("none", args)
            with self.assertRaises(ValueError):
                build_small_raster_args(image, input_dir, result_dir, 2)

    def test_build_args_require_content_addressed_image_and_rootless_mounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = "sha256:" + "a" * 64
            argv = build_pdfinfo_args(image, root)
            joined = " ".join(argv)
            for required in (
                "docker run --rm --pull never --network none", "--read-only",
                "--user 65534:65534", "--cap-drop ALL", "no-new-privileges",
                "--memory 256m", "/fixtures,readonly", "pdfinfo", "-box",
            ):
                self.assertIn(required, joined)
            with self.assertRaises(ValueError):
                build_pdfinfo_args("folio:latest", root)
            link = root / "linked"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                build_pdfinfo_args(image, link)


if __name__ == "__main__":
    unittest.main()
