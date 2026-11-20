"""R1.36 experimental real-Debian-Poppler OCR preflight smoke contracts."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from poppler_ocr_box_semantics_research import CORPUS_SHA256
from ocr_poppler_binary_smoke import (
    ALLOWED_RASTER_PAGES, build_lab_command, inspect_png_envelope,
    prepare_corpus, validate_page_raster_admission,
)

IMAGE = "sha256:" + "a" * 64


class BinarySmokeContracts(unittest.TestCase):
    def test_pinned_corpus_matches_r134_and_has_extreme_ninth_page(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_file = prepare_corpus(root)
            self.assertEqual(hashlib.sha256(input_file.read_bytes()).hexdigest(),
                             CORPUS_SHA256)
            self.assertIn(b"/MediaBox [0 0 536870919 1]", input_file.read_bytes())
            self.assertIn(b"/UserUnit 10000", input_file.read_bytes())

    def test_docker_commands_are_offline_readonly_and_use_exact_image_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source", root / "output"
            source.mkdir()
            output.mkdir()
            meta = build_lab_command(IMAGE, source, output, tool="pdfinfo", page=2)
            self.assertIn("--network", meta)
            self.assertEqual(meta[meta.index("--network") + 1], "none")
            self.assertIn("--read-only", meta)
            self.assertIn("--pull", meta)
            self.assertEqual(meta[meta.index("--pull") + 1], "never")
            self.assertIn("--cap-drop", meta)
            self.assertIn("ALL", meta)
            self.assertIn("--user", meta)
            self.assertIn("65534:65534", meta)
            self.assertIn("-box", meta)
            self.assertEqual(meta[meta.index("-l") + 1], "2")
            raster = build_lab_command(IMAGE, source, output, tool="pdftoppm", page=7)
            self.assertIn("-r", raster)
            self.assertEqual(raster[raster.index("-r") + 1], "180")
            self.assertIn("-png", raster)
            self.assertNotIn("-cropbox", raster)
            for disallowed in (5, 9, 0, 100, True):
                with self.subTest(page=disallowed), self.assertRaises(ValueError):
                    build_lab_command(IMAGE, source, output, tool="pdftoppm",
                                      page=disallowed)

    def test_image_id_and_unapproved_mount_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input", root / "output"
            source.mkdir()
            output.mkdir()
            for bad in ("debian:trixie-slim", "sha256:" + "G" * 64,
                        "sha256:" + "a" * 63, ""):
                with self.subTest(image=bad), self.assertRaises(ValueError):
                    build_lab_command(bad, source, output, tool="pdfinfo", page=1)
            link = root / "link"
            link.symlink_to(source, target_is_directory=True)
            with self.assertRaises(ValueError):
                build_lab_command(IMAGE, link, output, tool="pdfinfo", page=1)

    def test_extreme_media_is_rejected_before_any_raster(self):
        from test_ocr_mediabox_preflight import box_report
        with self.assertRaises(ValueError):
            validate_page_raster_admission(
                box_report(9, pages=9,
                           media="0 0 536870919 1",
                           crop="0 0 100 1",
                           size="100 x 1"),
                page=9, count=9,
            )
        self.assertNotIn(9, ALLOWED_RASTER_PAGES)
        self.assertNotIn(5, ALLOWED_RASTER_PAGES)

    def test_cropped_page_uses_media_geometry_not_page_size(self):
        from test_ocr_mediabox_preflight import box_report
        size = validate_page_raster_admission(
            box_report(2, pages=9, media="0 0 200 200",
                       crop="20 30 120 90", size="100 x 60"),
            page=2, count=9,
        )
        self.assertEqual(size, (501, 501))

    def test_png_header_reader_rejects_non_png_and_oversized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control.png"
            path.write_bytes(b"not a PNG")
            with self.assertRaises(ValueError):
                inspect_png_envelope(path, (500, 500))
            path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
            with self.assertRaises(ValueError):
                inspect_png_envelope(path, (500, 500))


if __name__ == "__main__":
    unittest.main()
