"""R1.39: real Poppler -> image-only synthetic PDF -> Tesseract OCR lab.

NOT a ClamAV test, not the inspector candidate, not proof of OCR safety or
quality for institutional documents. Strict, offline Docker sandbox by image ID.
All PDFs are original synthetic fixtures and deleted when the process exits.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zlib

from fixtures import _pdf, _stream
from inspector import (
    parse_qpdf_page_inventory, parse_qpdf_user_unit,
    require_ocr_png_envelope, require_ocr_raster_geometry,
)
from ocr_quality_matrix import canonical, edit_distance, synthetic_text_pdf

IMAGE_REF = re.compile(r"sha256:[a-f0-9]{64}\Z")
MAX_PDF = 8 * 1024 * 1024
MAX_PIXELS = 32_000_000
MAX_PGM_BYTES = MAX_PIXELS + 128
EXPECTED = {
    "a4": ("EXPEDIENTE OBRA 2026", (612, 792)),
    "a1": ("PLANO OBRA 2026", (1684, 2384)),
    "a1_detail": ("DETALLE TECNICO 2026", (1684, 2384)),
}
# Laboratory-specific reference fingerprints. These do NOT assert that this
# Debian runtime or its shared libraries match the deployable inspector.
EXPECTED_BINARY_SHA256 = {
    "/usr/bin/pdfinfo": "a1a371340d7b76e7d501da9136cc9256dfdb9cbdf09300520d7a3b4465343e67",
    "/usr/bin/pdftoppm": "f22d753dfb4c31c9f0198d608982dac5b06a3c5d9a08d7d9bf0c6004f08a1a56",
    "/usr/bin/qpdf": "30b2389c3ed0ba73434244fff5b149d4d919279ea7a8c3b1cd9fc25f57ec1792",
    "/usr/bin/pdfdetach": "85df25b0d0533e09f2e1ab8f5f1f89377854b2b68e6cf911ca4dd18e63a2b479",
    "/usr/bin/tesseract": "74b76a5b994adcc18be362bf64ed5118082b2401d5d9a35242e92fc4c62e2b4b",
    "/usr/lib/x86_64-linux-gnu/libpoppler.so.147": "8f199d8f320d485c8a0051676b8a0d6c6019900e5643b685afd7e304250ef340",
    "/usr/lib/x86_64-linux-gnu/libtesseract.so.5": "66b27d857aa90bb7a31059c65bb624e918e96a7c276699bd5ac5dca4cf1ba322",
    "/usr/share/tesseract-ocr/5/tessdata/spa.traineddata": "6f2e04d02774a18f01bed44b1111f2cd7f3ba7ac9dc4373cd3f898a40ea6b464",
    "/usr/share/tesseract-ocr/5/tessdata/eng.traineddata": "7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2",
}
IMAGE_SOURCE_SHA256_PATHS = tuple(EXPECTED_BINARY_SHA256)


def synthetic_native_source(kind: str) -> bytes:
    if kind == "a4":
        return synthetic_text_pdf(EXPECTED[kind][0])
    if kind not in ("a1", "a1_detail"):
        raise ValueError("Unapproved synthetic layout")
    if kind == "a1":
        content = (
            b"BT\n/F1 56 Tf\n160 2160 Td\n(PLANO OBRA 2026) Tj\nET\n"
        )
    else:
        # 14pt detail text at 180 DPI plus vector drawing lines. No OCR
        # shortcuts or PDF text layer in the *scanned* derivative.
        content = (
            b"0.6 w\n100 1860 m\n1120 1860 l\nS\n"
            b"100 1790 m\n1120 1790 l\nS\n"
            b"BT\n/F1 14 Tf\n160 2160 Td\n(DETALLE TECNICO 2026) Tj\nET\n"
        )
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1684 2384] "
         b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        _stream(content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ])


def parse_gray_pgm(payload: bytes) -> tuple[int, int, bytes]:
    if not isinstance(payload, bytes) or not 12 <= len(payload) <= MAX_PGM_BYTES:
        raise ValueError("Oversized or absent real PGM")
    rows = payload.split(b"\n", 3)
    if len(rows) != 4 or rows[0] != b"P5" or rows[2] != b"255":
        raise ValueError("Unsupported real PGM format")
    sizes = rows[1].split()
    if len(sizes) != 2 or any(not n.isdigit() or len(n) > 6 for n in sizes):
        raise ValueError("Invalid real PGM dimensions")
    width, height = map(int, sizes)
    if (not 1 <= width <= 8192 or not 1 <= height <= 8192
            or width * height > MAX_PIXELS
            or len(rows[3]) != width * height):
        raise ValueError("PGM raster dimensional mismatch")
    return width, height, rows[3]


def image_only_pdf(width: int, height: int, gray: bytes, *, box: tuple[int, int]) -> bytes:
    if (type(width) is not int or type(height) is not int
            or type(box) is not tuple or len(box) != 2
            or any(type(n) is not int or n <= 0 for n in box)
            or not 1 <= width <= 8192 or not 1 <= height <= 8192
            or width * height > MAX_PIXELS
            or len(gray) != width * height):
        raise ValueError("Invalid synthetic scan raster")
    compressed = zlib.compress(gray, level=6)
    pdf = _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (f"<< /Type /Page /Parent 2 0 R "
         f"/MediaBox [0 0 {box[0]} {box[1]}] "
         "/Contents 4 0 R /Resources << /XObject << /Im0 5 0 R >> >> >>"
         ).encode("ascii"),
        _stream((f"q\n{box[0]} 0 0 {box[1]} 0 0 cm\n/Im0 Do\nQ\n").encode()),
        _stream(
            compressed,
            (f"/Type /XObject /Subtype /Image /Width {width} "
             f"/Height {height} /ColorSpace /DeviceGray "
             "/BitsPerComponent 8 /Filter /FlateDecode").encode(),
        ),
    ])
    if len(pdf) > MAX_PDF:
        raise ValueError("Synthetic scanned PDF exceeds product upload budget")
    return pdf


def container_command(
    image_id: str, fixtures: Path, output: Path, tool: str,
    args: tuple[str, ...],
) -> list[str]:
    """Only approved engine binaries in unprivileged, offline, read-only OCI."""
    if not isinstance(image_id, str) or not IMAGE_REF.fullmatch(image_id):
        raise ValueError("Experimental image must be specified by immutable ID")
    if tool not in ("pdfinfo", "pdftoppm", "pdftotext", "pdfdetach", "qpdf", "tesseract", "sha256sum"):
        raise ValueError("Unapproved real engine")
    for folder in (fixtures, output):
        if (not folder.is_dir() or folder.is_symlink()
                or "," in str(folder) or "\n" in str(folder)):
            raise ValueError("Unsafe experimental mount path")
    if (not isinstance(args, tuple)
            or not all(isinstance(x, str) and x and "\x00" not in x
                       and len(x) <= 200 for x in args)):
        raise ValueError("Unapproved real engine arguments")
    return [
        "docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--cpus", "2", "--memory", "1g", "--memory-swap", "1g",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        "--env", "XDG_CACHE_HOME=/tmp",
        "--mount", f"type=bind,source={fixtures.resolve(strict=True)},target=/fixtures,readonly",
        "--mount", f"type=bind,source={output.resolve(strict=True)},target=/results",
        "--entrypoint", f"/usr/bin/{tool}", image_id, *args,
    ]


def run_experiment(image_id: str, *, runner=subprocess.run) -> dict:
    with tempfile.TemporaryDirectory(prefix="folio-ocr-fidelity-r139-") as name:
        root = Path(name)
        root.chmod(0o755)
        inputs, outputs = root / "inputs", root / "outputs"
        inputs.mkdir(mode=0o755)
        outputs.mkdir(mode=0o777)
        # tempfile umask may remove world write; container runs as uid 65534.
        outputs.chmod(0o777)

        def call(
            tool: str, *argv: str, expected_rc: int = 0,
            seconds: int = 90,
        ) -> str:
            command = container_command(image_id, inputs, outputs, tool, argv)
            try:
                result = runner(command, capture_output=True, text=True,
                                timeout=seconds, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError("Real lab process timeout or unavailable") from error
            if (result.returncode != expected_rc
                    or not isinstance(result.stdout, str)
                    or len(result.stdout.encode("utf-8")) > 65536
                    or len(result.stderr.encode("utf-8")) > 65536):
                raise ValueError("Real lab process rejected, truncated or oversized")
            return result.stdout

        identities = {}
        digest_rows = call("sha256sum", *IMAGE_SOURCE_SHA256_PATHS).splitlines()
        if len(digest_rows) != len(IMAGE_SOURCE_SHA256_PATHS):
            raise ValueError("Missing real engine fingerprint")
        for expected_path, row in zip(IMAGE_SOURCE_SHA256_PATHS, digest_rows):
            match = re.fullmatch(r"([a-f0-9]{64})  (/.+)", row)
            if (not match or match.group(2) != expected_path
                    or match.group(1) != EXPECTED_BINARY_SHA256[expected_path]):
                raise ValueError("Research engine fingerprint differs from pinned laboratory baseline")
            identities[expected_path] = match.group(1)

        results = []
        for kind, (expected, box) in EXPECTED.items():
            native = synthetic_native_source(kind)
            native_path = inputs / f"{kind}-native.pdf"
            native_path.write_bytes(native)
            native_path.chmod(0o644)
            call("qpdf", "--is-encrypted", f"/fixtures/{kind}-native.pdf",
                 expected_rc=2)
            call("qpdf", "--check", f"/fixtures/{kind}-native.pdf")
            call("pdftoppm", "-f", "1", "-l", "1", "-singlefile", "-gray",
                 "-r", "180", f"/fixtures/{kind}-native.pdf",
                 f"/results/{kind}-source", seconds=90)
            pgm = outputs / f"{kind}-source.pgm"
            if not pgm.is_file() or pgm.stat().st_size > MAX_PGM_BYTES:
                raise ValueError("Real PGM exceeds bounded source raster budget")
            pixels = pgm.read_bytes()
            width, height, raster = parse_gray_pgm(pixels)
            scan = image_only_pdf(width, height, raster, box=box)
            scan_name = f"{kind}-scan.pdf"
            scanned = inputs / scan_name
            scanned.write_bytes(scan)
            scanned.chmod(0o644)
            call("qpdf", "--is-encrypted", f"/fixtures/{scan_name}",
                 expected_rc=2)
            call("qpdf", "--check", f"/fixtures/{scan_name}")
            attachments = call("pdfdetach", "-list", f"/fixtures/{scan_name}")
            if not re.search(r"^0 embedded files?\s*$", attachments, re.M | re.I):
                raise ValueError("Synthetic image-only PDF contains an attachment")
            page_inventory = parse_qpdf_page_inventory(
                call("qpdf", "--json", "--json-key=pages",
                     f"/fixtures/{scan_name}"), count=1,
            )
            objnum, generation = page_inventory[0]
            user_unit = parse_qpdf_user_unit(
                call("qpdf", "--json", "--json-key=qpdf",
                     f"--json-object={objnum},{generation}",
                     f"/fixtures/{scan_name}"),
                object_number=objnum, generation=generation,
            )
            if user_unit != Decimal(1):
                raise ValueError("Unexpected unit in synthetic PDF without UserUnit")
            if call("pdftotext", "-f", "1", "-l", "1", "-enc", "UTF-8",
                    f"/fixtures/{scan_name}", "-").strip():
                raise ValueError("Synthetic scanned PDF contains extractable text")
            meta = call("pdfinfo", "-f", "1", "-l", "1", "-box",
                        f"/fixtures/{scan_name}")
            budget = require_ocr_raster_geometry(
                meta, page=1, count=1, user_unit=user_unit,
            )
            png_prefix = f"/results/{kind}-ocr"
            call("pdftoppm", "-f", "1", "-l", "1", "-singlefile",
                 "-r", "180", "-png", f"/fixtures/{scan_name}",
                 png_prefix, seconds=90)
            png_path = outputs / f"{kind}-ocr.png"
            actual_dims = require_ocr_png_envelope(png_path, budget)
            extracted = call("tesseract", f"/results/{kind}-ocr.png",
                             "stdout", "-l", "spa+eng", seconds=90)
            expected_normalized = canonical(expected)
            actual_normalized = canonical(extracted)
            error_count = edit_distance(expected_normalized, actual_normalized)
            # Quality contract for controlled synthetic text, not a
            # procurement/municipal validity or general OCR accuracy claim.
            if not actual_normalized or error_count != 0:
                raise ValueError("Laboratory OCR fidelity below exact synthetic threshold")
            results.append({
                "case": kind,
                "source_sha256": hashlib.sha256(native).hexdigest(),
                "scan_sha256": hashlib.sha256(scan).hexdigest(),
                "scan_bytes": len(scan),
                "source_raster_dimensions": [width, height],
                "qpdf_user_unit": str(user_unit),
                "preflight_dimensions": list(budget),
                "real_png_dimensions": list(actual_dims),
                "png_sha256": hashlib.sha256(png_path.read_bytes()).hexdigest(),
                "expected_text_sha256": hashlib.sha256(expected_normalized.encode()).hexdigest(),
                "actual_text_sha256": hashlib.sha256(actual_normalized.encode()).hexdigest(),
                "reference_characters": len(expected_normalized),
                "character_errors": error_count,
            })
        return {
            "status": "real_poppler_tesseract_synthetic_fidelity_lab",
            "image_id": image_id,
            "measured_binary_sha256": identities,
            "real_docker_processes_executed": runner is subprocess.run,
            "cases": results,
            "antivirus_real_verified": False,
            "clamav_1_5_5_verified": False,
            "inspector_full_pipeline_verified": False,
            "runtime_candidate_equivalence_verified": False,
            "safe_for_untrusted_pdf_verified": False,
            "release_authorized": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--offline-lab-only", action="store_true")
    args = parser.parse_args()
    if not args.offline_lab_only:
        parser.error("An explicit offline lab flag is required")
    try:
        report = run_experiment(args.image_id)
    except (ValueError, OSError, TypeError, UnicodeError):
        print(json.dumps({
            "status": "inconclusive",
            "full_pipeline_verified": False,
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
