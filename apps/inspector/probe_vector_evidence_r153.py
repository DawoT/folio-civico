"""R1.53 · Research-only proof of vector evidence missing from PDF text manifests.

This is NOT a scanner fix and MUST NOT be used as a release gate approval.
The fixture is 100% original: text plus a distinct four-digit number drawn
using PDF path-fill rectangles. qpdf/Poppler/AV are real in opt-in probes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from fixtures import GLYPHS, _pdf, _stream, native_pdf
from inspector import ReviewRequired, command, has_pdf_page_raster, inspect_pdf
from qpdf_paint_triage_r154 import qpdf_page_has_uncovered_paint

DIGITAL_TEXT = "EXPEDIENTE OBRA 2026"
VECTOR_VALUE = "6002"
GRAPHIC_X = 80
GRAPHIC_Y = 540
SCALE = 8
WIDTH = 612
HEIGHT = 792
MAX_PGM_BYTES = WIDTH * HEIGHT + 80


def vector_evidence_pdf() -> tuple[bytes, int]:
    """Make a valid one-page PDF with a visible vector value, no image XObjects."""
    commands = [
        ("BT\n/F1 24 Tf\n70 720 Td\n(" + DIGITAL_TEXT + ") Tj\nET\n").encode("ascii")
    ]
    for index, glyph in enumerate(VECTOR_VALUE):
        for row, pixels in enumerate(GLYPHS[glyph]):
            for col, bit in enumerate(pixels):
                if bit == "1":
                    x = GRAPHIC_X + index * 6 * SCALE + col * SCALE
                    y = GRAPHIC_Y + (6 - row) * SCALE
                    commands.append(f"{x} {y} {SCALE} {SCALE} re f\n".encode("ascii"))
    pdf = _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        _stream(b"".join(commands)),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ])
    return pdf, len(commands) - 1


def count_vector_ink(pgm: bytes) -> int:
    """Verify ink exists inside the synthetic vector-only region, not the text."""
    if len(pgm) > MAX_PGM_BYTES:
        raise ValueError("Unbounded grayscale raster in research probe")
    header = pgm.split(b"\n", 3)
    if (len(header) != 4 or header[:3] != [b"P5", b"612 792", b"255"]
            or len(header[3]) != WIDTH * HEIGHT):
        raise ValueError("Unexpected Poppler grayscale output")
    data = header[3]
    return sum(
        data[row * WIDTH + col] < 100
        for row in range(180, 275)
        for col in range(70, 295)
    )


def classify_result(*, digital_text: str, image_present: bool, ink: int,
                    drawn_rectangles: int, scanned_text: str | None,
                    reviewed: bool, inspected_commands: list[str]) -> dict:
    """Never certify a PDF; emit only a bounded observation or an error."""
    if (digital_text != DIGITAL_TEXT or VECTOR_VALUE in digital_text
            or image_present or ink < 1000 or not 50 <= drawn_rectangles <= 100
            or not {"clamscan", "qpdf", "pdftotext", "pdfimages"}.issubset(
                inspected_commands
            )):
        raise ValueError("Vector sample or scanner admission was not proven")

    if reviewed and scanned_text is None:
        status = "vector_evidence_review_required_release_blocked"
        omitted = None
    elif not reviewed and scanned_text == DIGITAL_TEXT:
        status = "vector_evidence_gap_reproduced_release_blocked"
        omitted = True
    else:
        raise ValueError("Unsupported scanner outcome in research probe")
    return {
        "status": status,
        "release_authorized": False,
        "g4_gate": "blocked",
        "synthetic_sample": "one-page-digital-text-plus-vector-number",
        "vector_value_selectable": False,
        "raster_xobject_detected": False,
        "drawn_rectangles": drawn_rectangles,
        "visible_vector_dark_pixels": ink,
        "visual_value_omitted_from_manifest": omitted,
    }


def probe() -> dict:
    """Opt-in real-engine execution, offline inside the pinned research image."""
    sample, rectangles = vector_evidence_pdf()
    # Positive control: normal text-only PDFs must still pass extraction.
    clean = native_pdf()
    trace: list[str] = []
    with tempfile.TemporaryDirectory(prefix="folio-synthetic-vector-") as folder:
        directory = Path(folder)
        path = directory / "vector.pdf"
        path.write_bytes(sample)
        digital = command([
            "pdftotext", "-f", "1", "-l", "1", "-layout", "-nopgbrk",
            "-enc", "UTF-8", str(path), "-",
        ], directory).strip()
        images = has_pdf_page_raster(command([
            "pdfimages", "-f", "1", "-l", "1", "-list", str(path),
        ], directory), page=1, count=1)
        try:
            converted = subprocess.run([
                "pdftoppm", "-f", "1", "-l", "1", "-singlefile",
                "-gray", "-r", "72", str(path),
            ], capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Poppler vector raster verification unavailable") from error
        if converted.returncode != 0:
            raise ValueError("Poppler vector raster verification unsuccessful")
        ink = count_vector_ink(converted.stdout)

        # Ask QPDF to resolve and decode the *content stream* syntax, not
        # grep raw PDF bytes: paint operators can be inside Flate streams,
        # and PDF string literals/comments can contain inert words like "f".
        qpdf_args = [
            "qpdf", "--json", "--json-key=pages", "--json-key=qpdf",
            "--json-stream-data=inline", "--decode-level=all",
        ]
        vector_json = command([*qpdf_args, str(path)], directory)
        if not qpdf_page_has_uncovered_paint(vector_json, page=1, count=1):
            raise ValueError("Semantic vector evidence not found in decoded stream")
        control_path = directory / "native.pdf"
        control_path.write_bytes(clean)
        control_json = command([*qpdf_args, str(control_path)], directory)
        if qpdf_page_has_uncovered_paint(control_json, page=1, count=1):
            raise ValueError("Native PDF falsely classified as vector evidence")

        def traced(argv: list[str], cwd: Path) -> str:
            trace.append(argv[0])
            return command(argv, cwd)

        normal = inspect_pdf(
            clean, "synthetic_control_native", hashlib.sha256(clean).hexdigest(),
            signatures=Path("/opt/clamdb"), run=traced,
        )
        if (normal["scanVerdict"] != "clean"
                or len(normal["pages"]) != 1
                or normal["pages"][0]["text"] != DIGITAL_TEXT):
            raise ValueError("Native-text positive control failed")
        trace.clear()
        try:
            result = inspect_pdf(
                sample, "synthetic_vector_evidence",
                hashlib.sha256(sample).hexdigest(),
                signatures=Path("/opt/clamdb"), run=traced,
            )
        except ReviewRequired:
            reviewed, scanned_text = True, None
        else:
            if (result.get("scanVerdict") != "clean"
                    or len(result.get("pages", [])) != 1):
                raise ValueError("Unexpected vector document scanner result")
            reviewed, scanned_text = False, result["pages"][0].get("text")
        observation = classify_result(
            digital_text=digital, image_present=images, ink=ink,
            drawn_rectangles=rectangles, scanned_text=scanned_text,
            reviewed=reviewed, inspected_commands=trace,
        )
        return dict(
            observation, qpdf_decoded_paint_detected=True,
            qpdf_native_text_control_drawing_detected=False,
        )


def main() -> int:
    try:
        result = probe()
    except (ValueError, OSError, KeyError, TypeError, IndexError):
        print(json.dumps({
            "status": "vector_evidence_probe_incomplete",
            "release_authorized": False, "g4_gate": "blocked",
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2  # Both credible outcomes KEEP G4 blocked, never approve.


if __name__ == "__main__":
    raise SystemExit(main())
