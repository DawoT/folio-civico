"""R1.34: adversarial CropBox/MediaBox differential research; no runtime guard."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_ocr_box_semantics_research import (
    CORPUS_SHA256, IMAGE_ID, EXPECTED_PIXELS, build_matrix_pdf,
    build_docker_args, parse_matrix_pdfinfo, verify_pixel_measurements,
    semantic_report,
)


# Representative real pdfinfo -f 1 -l 9 -box lines, omitting other metadata.
# These values were observed on the source-built experimental Poppler ELF.
SIZES = (
    ("595", "842"), ("100", "60"), ("200", "200"), ("200", "200"),
    ("200", "200"), ("200", "400"), ("200", "200"),
    ("0.01", "0.02"), ("100", "1"),
)
MEDIA = (
    ("0", "0", "595", "842"),
    ("0", "0", "200", "200"),
    ("0", "0", "200", "200"),
    ("0", "0", "200", "200"),
    ("0", "0", "200", "200"),
    ("0", "0", "200", "400"),
    ("0", "0", "500", "300"),
    ("0", "0", "0.01", "0.02"),
    ("0", "0", "536870919", "1"),
)
CROP = (
    MEDIA[0], ("20", "30", "120", "90"), MEDIA[2], MEDIA[3],
    MEDIA[4], MEDIA[5], ("100", "10", "300", "210"), MEDIA[7],
    ("0", "0", "100", "1"),
)
ROT = ("0", "0", "0", "0", "0", "90", "0", "0", "0")


def sample_info() -> str:
    lines = ["Pages: 9", "Encrypted: no"]
    for i, (w, h) in enumerate(SIZES, 1):
        lines += [f"Page {i} size: {w} x {h} pts",
                  f"Page {i} rot: {ROT[i - 1]}"]
    for i in range(1, 10):
        lines += ["Page %d MediaBox: %s" % (i, " ".join(MEDIA[i - 1])),
                  "Page %d CropBox: %s" % (i, " ".join(CROP[i - 1]))]
    return "\n".join(lines) + "\n"


class CropBoxSemanticsTests(unittest.TestCase):
    def test_matrix_pdf_is_small_deterministic_and_sha_pinned(self):
        pdf = build_matrix_pdf()
        self.assertLess(len(pdf), 2048)
        self.assertEqual(hashlib.sha256(pdf).hexdigest(), CORPUS_SHA256)
        self.assertIn(b"/MediaBox [0 0 536870919 1] /CropBox [0 0 100 1]", pdf)
        self.assertIn(b"/CropBox [20 30 120 90]", pdf)
        self.assertIn(b"/UserUnit 10000", pdf)
        self.assertIn(b"/Rotate 90", pdf)

    def test_page_size_can_understate_default_raster_dimensions(self):
        report = parse_matrix_pdfinfo(sample_info())
        self.assertEqual(report["page_count"], 9)
        self.assertEqual(report["pages_where_page_size_understates_media"], [2, 7, 9])
        self.assertTrue(report["extreme_media_hidden_by_small_page_size"])
        self.assertGreater(report["pages"][8]["media_estimated_pixels_at_180_dpi"],
                           1_000_000_000)
        self.assertEqual(report["pages"][8]["page_size_points"], [100.0, 1.0])
        self.assertEqual(report["pages"][8]["media_box_points"][2], 536870919.0)
        self.assertFalse(report["runtime_guard_implemented"])
        self.assertFalse(report["release_authorized"])

    def test_r133_research_parser_overrejects_valid_cropped_page(self):
        # Previous parser equated Page size to MediaBox; Poppler chooses
        # clipped CropBox for Page size, unlike default pdftoppm output.
        from poppler_ocr_geometry_research import inspect_pdfinfo_geometry
        with self.assertRaisesRegex(ValueError, "Page size and MediaBox disagree"):
            inspect_pdfinfo_geometry(sample_info())

    def test_metadata_fail_closed_on_missing_duplicate_or_forged_boxes(self):
        valid = sample_info()
        attempts = (
            valid.replace("Page 9 MediaBox: 0 0 536870919 1\n", ""),
            valid.replace("Page 9 MediaBox: 0 0 536870919 1",
                          "Page 9 MediaBox: 0 0 100 1"),
            valid.replace("Page 2 CropBox: 20 30 120 90",
                          "Page 2 CropBox: 20 30 0 90"),
            valid.replace("Page 2 size: 100 x 60", "Page 2 size: NaN x 60"),
            valid + "Page 9 CropBox: fake\n",
            valid + "Page 1 rot: 0\n",
            valid.replace("Encrypted: no", "Encrypted: yes"),
            valid.replace("Pages: 9", "Pages: 8"),
            valid + "\u202e",
        )
        for candidate in attempts:
            with self.subTest(bad=candidate[-60:]), self.assertRaises(ValueError):
                parse_matrix_pdfinfo(candidate)

    def test_raster_matrix_proves_cropbox_changes_output_not_default(self):
        report = verify_pixel_measurements(dict(EXPECTED_PIXELS))
        self.assertEqual(report["page2_default_png"], [500, 500])
        self.assertEqual(report["page2_crop_png"], [250, 150])
        self.assertEqual(report["page7_default_png"], [1250, 750])
        self.assertEqual(report["page7_crop_png"], [500, 500])
        self.assertEqual(report["page8_default_png"], [1, 1])
        self.assertTrue(report["default_raster_exceeds_crop_raster_observed"])

    def test_bad_raster_measurements_or_extra_extreme_pages_rejected(self):
        for bad in (
            {**EXPECTED_PIXELS, "p2": (250, 150)},
            {k: v for k, v in EXPECTED_PIXELS.items() if k != "p7"},
            {**EXPECTED_PIXELS, "p9": (250, 3)},
        ):
            with self.assertRaises(ValueError):
                verify_pixel_measurements(bad)

    def test_docker_args_fail_closed_on_tags_and_extreme_page_raster(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "src"
            output = Path(tmp) / "out"
            source.mkdir()
            output.mkdir()
            for case in EXPECTED_PIXELS:
                argv = build_docker_args(IMAGE_ID, source, output, "raster", case)
                self.assertIn("--network", argv)
                self.assertIn("none", argv)
                self.assertIn("--read-only", argv)
                self.assertIn("65534:65534", argv)
                self.assertIn("-r", argv)
                self.assertIn("180", argv)
            for bad in ("p5", "p9", "p999", "../p2"):
                with self.assertRaises(ValueError):
                    build_docker_args(IMAGE_ID, source, output, "raster", bad)
            with self.assertRaises(ValueError):
                build_docker_args("folio-civico-inspector:poppler-experiment",
                                  source, output, "metadata")
            for mode in ("metadata", "sha"):
                argv = build_docker_args(IMAGE_ID, source, output, mode)
                self.assertIn("--pull", argv)
                self.assertIn("never", argv)
            link = Path(tmp) / "link"
            link.symlink_to(source, target_is_directory=True)
            with self.assertRaises(ValueError):
                build_docker_args(IMAGE_ID, link, output, "metadata")

    def test_full_runner_fake_records_only_allowlisted_pages_and_disclaims_real_execution(self):
        import struct
        import zlib
        from subprocess import CompletedProcess
        from poppler_ocr_box_semantics_research import inspect_local_matrix
        from poppler_ocr_geometry_research import EXPECTED_EXPERIMENTAL_ELF_SHA256

        executed = []
        def png(width: int, height: int) -> bytes:
            def chunk(kind: bytes, value: bytes) -> bytes:
                return (struct.pack(">I", len(value)) + kind + value
                        + struct.pack(">I", zlib.crc32(kind + value) & 0xffffffff))
            scanlines = (b"\x00" + b"\xff" * (3 * width)) * height
            return (b"\x89PNG\r\n\x1a\n"
                    + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
                    + chunk(b"IDAT", zlib.compress(scanlines, 9))
                    + chunk(b"IEND", b""))

        def fake_run(args, **kwargs):
            entry = args[args.index("--entrypoint") + 1]
            if entry == "/usr/bin/sha256sum":
                value = "".join(f"{sha}  {name}\n"
                                for name, sha in EXPECTED_EXPERIMENTAL_ELF_SHA256.items())
            elif entry.endswith("/pdfinfo"):
                value = sample_info()
            else:
                case = Path(args[-1]).name
                self.assertIn(case, EXPECTED_PIXELS)
                executed.append(case)
                mount = next(value for value in args if ",target=/results" in value)
                path = Path(mount.removeprefix("type=bind,source=").split(",target=")[0])
                (path / f"{case}.png").write_bytes(png(*EXPECTED_PIXELS[case]))
                value = ""
            return CompletedProcess(args, 0, value, "")

        result = inspect_local_matrix(runner=fake_run)
        self.assertEqual(executed, list(EXPECTED_PIXELS))
        self.assertFalse(result["real_differential_raster_executed"])
        self.assertFalse(result["experimental_elf_identity_verified"])
        self.assertFalse(result["release_authorized"])

    def test_unavailable_experimental_image_fails_closed(self):
        from subprocess import CompletedProcess
        from poppler_ocr_box_semantics_research import inspect_local_matrix
        def missing_image(args, **kwargs):
            return CompletedProcess(args, 125, "", "No such image")
        with self.assertRaises(ValueError):
            inspect_local_matrix(runner=missing_image)

    def test_report_never_claims_guaranteed_preflight_or_cve_fix(self):
        result = semantic_report(sample_info(), dict(EXPECTED_PIXELS))
        for field in ("runtime_guard_implemented", "source_binary_equivalence_to_runtime_verified",
                      "user_unit_safety_verified", "cve_remediation_claimed",
                      "release_authorized", "safe_for_untrusted_pdf_verified"):
            self.assertIs(result[field], False)
        self.assertTrue(result["source_pdf_corpus_pinned"])
        self.assertEqual(result["measured_raster_cases"], len(EXPECTED_PIXELS))


if __name__ == "__main__":
    unittest.main()
