"""R1.39: deterministic synthetic fidelity contract (no live PDF in unit CI)."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ocr_real_fidelity_lab import (
    EXPECTED, EXPECTED_BINARY_SHA256, image_only_pdf, parse_gray_pgm,
    container_command, synthetic_native_source, run_experiment,
)

IMAGE = "sha256:" + "a" * 64


class SourceContracts(unittest.TestCase):
    def test_fidelity_cases_have_synthetic_content_and_bounded_pdf_sizes(self):
        self.assertEqual(set(EXPECTED), {"a4", "a1", "a1_detail"})
        for kind, (expected, dimensions) in EXPECTED.items():
            with self.subTest(kind=kind):
                pdf = synthetic_native_source(kind)
                self.assertTrue(pdf.startswith(b"%PDF-"))
                self.assertTrue(pdf.endswith(b"%%EOF\n"))
                self.assertIn(expected.encode(), pdf)
                self.assertLess(len(pdf), 10_000)
                self.assertTrue(all(n > 0 for n in dimensions))
        with self.assertRaises(ValueError):
            synthetic_native_source("institutional")

    def test_valid_bounded_image_only_pdf(self):
        pdf = image_only_pdf(2, 2, bytes((255, 200, 20, 0)), box=(612, 792))
        self.assertIn(b"/Subtype /Image", pdf)
        self.assertIn(b"/Filter /FlateDecode", pdf)
        self.assertIn(b"/MediaBox [0 0 612 792]", pdf)
        self.assertNotIn(b"BT\n", pdf)

    def test_image_only_pdf_rejects_invalid_dimensions(self):
        for w, h, pixels, box in (
            (0, 2, b"\0"*4, (612, 792)),
            (2, -1, b"\0"*4, (612, 792)),
            (2, 2, b"\0"*3, (612, 792)),
            (True, 2, b"\0"*4, (612, 792)),
            (100000, 1, b"\0", (612, 792)),
            (2, 2, b"\0"*4, (612, 0)),
            (2, 2, b"\0"*4, (0, 792)),
            (2, 2, b"\0"*4, ("612", 792)),
        ):
            with self.subTest(dimensions=(w,h),box=box), self.assertRaises(ValueError):
                image_only_pdf(w, h, pixels, box=box)


class RasterContracts(unittest.TestCase):
    def test_gray_pgm_requires_complete_exact_raster(self):
        raster = b"P5\n2 2\n255\n" + bytes((0,1,2,255))
        self.assertEqual(parse_gray_pgm(raster), (2, 2, bytes((0,1,2,255))))
        for bad in (
            b"", b"P3\n2 2\n255\n"+bytes((0,1,2,255)),
            b"P5\n2 2\n256\n"+bytes((0,1,2,255)),
            b"P5\n2 2\n255\n"+bytes((0,1,2)),
            b"P5\n2 2\n255\n"+bytes((0,1,2,3,4)),
            b"P5\n10000 10000\n255\n"+bytes((0,1,2,3)),
            b"P5\n0 2\n255\n"+bytes((0,1,2,3)),
            b"P5\nnan 2\n255\n"+bytes((0,1,2,3)),
            b"P5\n2 2\n255\n"+bytes((0,1,2,3))+b"TRAIL",
        ):
            with self.subTest(sample=bad[:24]), self.assertRaises(ValueError):
                parse_gray_pgm(bad)

    def test_only_content_addressed_image_and_approved_engines(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source,output = root/"fixtures", root/"output"
            source.mkdir()
            output.mkdir()
            cmd=container_command(IMAGE,source,output,"pdftoppm",(
                "-f","1","-l","1","-singlefile","-r","180",
                "-png","/fixtures/synthetic.pdf","/results/ocr",
            ))
            self.assertIn("--network",cmd)
            self.assertEqual(cmd[cmd.index("--network")+1],"none")
            self.assertEqual(cmd[cmd.index("--pull")+1],"never")
            self.assertIn("--read-only",cmd)
            self.assertIn("--cap-drop",cmd)
            self.assertEqual(cmd[cmd.index("--user")+1],"65534:65534")
            self.assertEqual(cmd[cmd.index("--memory")+1],"1g")
            self.assertIn("XDG_CACHE_HOME=/tmp",cmd)
            for bad in ("debian:trixie-slim","sha256:"+"A"*64,
                        "sha256:"+"b"*63,""):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    container_command(bad,source,output,"pdfinfo",("--version",))
            with self.assertRaises(ValueError):
                container_command(IMAGE,source,output,"shell",("--version",))
            link=root/"link"
            link.symlink_to(source, target_is_directory=True)
            with self.assertRaises(ValueError):
                container_command(IMAGE,link,output,"pdfinfo",("--version",))

    def test_absent_real_image_or_bad_binary_report_never_reports_success(self):
        class Process:
            returncode=0
            stdout="corrupted-nonbinary-inventory"
            stderr=""
        called=[]
        def runner(argv,**kwargs):
            called.append(argv)
            return Process()
        with self.assertRaises(ValueError):
            run_experiment(IMAGE,runner=runner)
        self.assertEqual(len(called),1)
        self.assertIn("/usr/bin/sha256sum",called[0])
        self.assertEqual(called[0][called[0].index("--entrypoint")+1],
                         "/usr/bin/sha256sum")

        class PlausibleWrongDigest:
            returncode=0
            stderr=""
            stdout="".join(
                f"{'0'*64}  {path}\n" for path in EXPECTED_BINARY_SHA256
            )
        called.clear()
        def forged_runner(argv, **kwargs):
            called.append(argv)
            return PlausibleWrongDigest()
        with self.assertRaises(ValueError):
            run_experiment(IMAGE, runner=forged_runner)
        self.assertEqual(len(called), 1)


if __name__ == "__main__":
    unittest.main()
