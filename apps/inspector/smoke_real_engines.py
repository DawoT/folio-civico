"""Real-engine synthetic PDF acceptance and AV smoke checks.

The manual command REQUIRES actual ClamAV, qpdf, Poppler and Tesseract plus
current official AV definitions. NEVER reports a simulated success. It creates
no persistent documents, logs no document contents and uses no cloud resources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from fixtures import native_pdf, scanned_pdf, malformed_pdf
from inspector import inspect_pdf, ReviewRequired
from preflight import inspect_host


def scanner_test_sample() -> bytes:
    """Generate the harmless EICAR standard antivirus test string in memory."""
    # Construct at runtime to avoid putting an antivirus-triggering file into
    # the repository. See https://www.eicar.org/download-anti-malware-testfile/
    return (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ).encode("ascii")


def parse_pgm(raw: bytes) -> tuple[int, int, bytes]:
    """Read a bounded P5 grayscale image created from a synthetic text PDF."""
    if len(raw) > 8 * 1024 * 1024 + 128:
        raise ValueError("Synthetic raster exceeds fixture cap")
    lines = raw.split(b"\n", 3)
    if (len(lines) != 4 or lines[0] != b"P5"
            or lines[2] != b"255"):
        raise ValueError("Unexpected grayscale format")
    dimensions = lines[1].split()
    if len(dimensions) != 2 or any(not number.isdigit() for number in dimensions):
        raise ValueError("Malformed grayscale dimensions")
    width, height = (int(number) for number in dimensions)
    if (width < 1 or height < 1 or width > 4000 or height > 4000
            or width * height > 8 * 1024 * 1024
            or len(lines[3]) != width * height):
        raise ValueError("Invalid grayscale payload size")
    return width, height, lines[3]


def build_scanned_fixture() -> bytes:
    """Rasterize original synthetic text, then strip ALL PDF text/font objects.

    This uses real Poppler only in the opt-in real-engine smoke. The resulting
    PDF is an image XObject with no searchable text layer. It is never stored.
    """
    with tempfile.TemporaryDirectory(prefix="folio-synthetic-raster-") as root:
        folder = Path(root)
        source = folder / "native.pdf"
        dest = folder / "scan"
        source.write_bytes(native_pdf())
        try:
            run = subprocess.run([
                "pdftoppm", "-f", "1", "-l", "1", "-singlefile",
                "-gray", "-r", "180", str(source), str(dest)
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("Synthetic raster engine unavailable") from error
        image = folder / "scan.pgm"
        if run.returncode != 0 or not image.is_file() or image.stat().st_size > 8 * 1024 * 1024 + 128:
            raise RuntimeError("Could not create bounded synthetic raster")
        return scanned_pdf(raster=parse_pgm(image.read_bytes()))


def assert_no_pdf_text(pdf: bytes) -> None:
    """Prove that the OCR fixture has no extractable PDF text layer."""
    with tempfile.TemporaryDirectory(prefix="folio-synthetic-text-check-") as root:
        sample = Path(root) / "scan.pdf"
        sample.write_bytes(pdf)
        try:
            result = subprocess.run([
                "pdftotext", "-f", "1", "-l", "1", "-enc", "UTF-8",
                str(sample), "-"
            ], capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("Could not verify synthetic image-only PDF") from error
        if result.returncode != 0 or result.stdout.strip():
            raise AssertionError("OCR fixture must contain no searchable PDF text")


def build_negative_fixtures() -> list[tuple[str, bytes]]:
    """Generate genuinely encrypted and attachment-bearing synthetic PDFs."""
    with tempfile.TemporaryDirectory(prefix="folio-synthetic-negative-") as root:
        folder = Path(root)
        source = folder / "native.pdf"
        attachment = folder / "synthetic.txt"
        source.write_bytes(native_pdf())
        attachment.write_text("Synthetic fixture only. No institutional data.",
                              encoding="utf-8")
        outputs = [
            ("encrypted", folder / "encrypted.pdf", [
                "qpdf", "--encrypt", "synthetic_user", "synthetic_owner",
                "256", "--", str(source), str(folder / "encrypted.pdf")
            ]),
            ("embedded_file", folder / "with_attachment.pdf", [
                "pdfattach", str(source), str(attachment),
                str(folder / "with_attachment.pdf")
            ])
        ]
        results: list[tuple[str, bytes]] = []
        for name, output, command in outputs:
            try:
                result = subprocess.run(
                    command, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=30, check=False
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise RuntimeError("Synthetic negative fixture tool unavailable") from error
            if (result.returncode != 0 or not output.is_file()
                    or output.stat().st_size < 12
                    or output.stat().st_size > 8 * 1024 * 1024):
                raise RuntimeError("Could not generate a bounded negative fixture")
            results.append((name, output.read_bytes()))
        return results


def exercise_real_engines(database: Path) -> dict[str, str]:
    expected = {"native": "passed", "ocr": "passed",
                "malformed": "rejected", "encrypted": "rejected",
                "embedded_file": "rejected", "antivirus_test": "detected"}

    native = native_pdf()
    manifest = inspect_pdf(native, "synthetic_native", hashlib.sha256(native).hexdigest(),
                           signatures=database)
    if len(manifest["pages"]) != 1:
        raise AssertionError("Native PDF page count differs")
    native_text = manifest["pages"][0]["text"].upper()
    if "EXPEDIENTE" not in native_text or "OBRA" not in native_text or "2026" not in native_text:
        raise AssertionError("Native PDF extraction did not preserve text")

    scanned = build_scanned_fixture()
    assert_no_pdf_text(scanned)
    manifest = inspect_pdf(scanned, "synthetic_ocr", hashlib.sha256(scanned).hexdigest(),
                           signatures=database)
    if len(manifest["pages"]) != 1:
        raise AssertionError("OCR PDF page count differs")
    ocr_text = manifest["pages"][0]["text"].upper()
    if "OBRA" not in ocr_text or "2026" not in ocr_text:
        raise AssertionError("Tesseract OCR did not recover expected synthetic text")

    malformed = malformed_pdf()
    try:
        inspect_pdf(malformed, "synthetic_bad", hashlib.sha256(malformed).hexdigest(),
                    signatures=database)
    except ReviewRequired:
        pass
    else:
        raise AssertionError("Malformed PDF unexpectedly passed inspection")

    for name, rejected_pdf in build_negative_fixtures():
        try:
            inspect_pdf(
                rejected_pdf, "synthetic_" + name,
                hashlib.sha256(rejected_pdf).hexdigest(), signatures=database
            )
        except ReviewRequired:
            pass
        else:
            raise AssertionError("Unsupported synthetic PDF unexpectedly passed inspection")

    with tempfile.TemporaryDirectory(prefix="folio-av-test-") as temporary:
        sample = Path(temporary) / "eicar-test-only.txt"
        payload = scanner_test_sample()
        if len(payload) != 68:
            raise AssertionError("Unexpected antivirus smoke signature size")
        sample.write_bytes(payload)
        # EICAR is harmless, not malware. Its detection verifies that official
        # signatures are actually loaded by clamscan, not merely present by name.
        scan = subprocess.run([
            "clamscan", "--no-summary", "--database", str(database), str(sample)
        ], capture_output=True, timeout=30, check=False)
        if scan.returncode != 1:
            raise AssertionError("ClamAV did not identify its harmless EICAR test pattern")

    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("/opt/clamdb"))
    args = parser.parse_args()
    preflight = inspect_host("smoke",Path(__file__).resolve().parents[2],args.database)
    if not preflight["ready"]:
        print(json.dumps({"ready": False, "problems": preflight["problems"]},
                         sort_keys=True))
        return 2
    try:
        result = exercise_real_engines(args.database)
    except Exception:
        # Do not log exception messages or PDFs: some tools include file paths,
        # scanner internals, or original document content in their diagnostics.
        print(json.dumps({"ready":False,"reason":"real_engine_validation_failed"}))
        return 1
    print(json.dumps({"ready": True, "checks": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
