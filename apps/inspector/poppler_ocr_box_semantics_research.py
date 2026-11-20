"""R1.34: offline, bounded CropBox/MediaBox/rotation differential research.

This module is NEVER imported by inspector.py. The observations apply only to
the exact synthetic corpus and local experimental Poppler image pinned below.
A successful result is NOT a validated pre-rasterization security guard.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

from fixtures import _pdf, _stream
from poppler_ocr_geometry_research import (
    DPI, EXPECTED_EXPERIMENTAL_ELF_SHA256, MAX_REPORT_BYTES, NUMBER,
    _decimal, _records, parse_experimental_elf_digests, verify_png_geometry,
)

IMAGE_ID = "sha256:abf8192c743f176c6da02bcc288a4eb0ba2d9cb4377a7b8f1725ae9471798254"
CORPUS_SHA256 = "0641c796fea6cb2078376765e77dcf99bcb5995f3df0c79cbe3dfdacc5f47153"
PAGE_COUNT = 9
# Untrusted original PDF source is never an input to this module.
CASE_PARAMS = (
    b"/MediaBox [0 0 595 842]",
    b"/MediaBox [0 0 200 200] /CropBox [20 30 120 90]",
    b"/MediaBox [0 0 200 200] /CropBox [0 0 400 400]",
    b"/MediaBox [0 0 200 200] /UserUnit 5",
    b"/MediaBox [0 0 200 200] /UserUnit 10000",  # NEVER rasterized.
    b"/MediaBox [0 0 200 400] /Rotate 90",
    b"/CropBox [100 10 300 210]",  # Inherited /MediaBox from parent.
    b"/MediaBox [0 0 0.01 0.02]",
    b"/MediaBox [0 0 536870919 1] /CropBox [0 0 100 1]",  # NEVER rasterized.
)
EXPECTED_MEDIA = (
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
EXPECTED_CROP = (
    EXPECTED_MEDIA[0], ("20", "30", "120", "90"), EXPECTED_MEDIA[2],
    EXPECTED_MEDIA[3], EXPECTED_MEDIA[4], EXPECTED_MEDIA[5],
    ("100", "10", "300", "210"), EXPECTED_MEDIA[7], ("0", "0", "100", "1"),
)
EXPECTED_SIZE = (
    ("595", "842"), ("100", "60"), ("200", "200"), ("200", "200"),
    ("200", "200"), ("200", "400"), ("200", "200"),
    ("0.01", "0.02"), ("100", "1"),
)
EXPECTED_ROTATION = (0, 0, 0, 0, 0, 90, 0, 0, 0)

# Only bounded synthetic pages are rasterized, using the exact OCR flags.
# Page 5 has extreme UserUnit; page 9 has an enormous MediaBox.
EXPECTED_PIXELS = {
    "p1": (1488, 2105),
    "p2": (500, 500),
    "p2crop": (250, 150),
    "p3": (500, 500),
    "p4": (500, 500),
    "p6": (1000, 500),
    "p7": (1250, 750),
    "p7crop": (500, 500),
    "p8": (1, 1),
}
RE_SIZE = re.compile(
    rf"^Page[ ]+(\d+)[ ]+size:[ ]+({NUMBER})[ ]+x[ ]+({NUMBER})[ ]+pts"
    r"(?:[ ]+\([^()\r\n]{1,80}\))?[ ]*$", re.M,
)
RE_ROT = re.compile(r"^Page[ ]+(\d+)[ ]+rot:[ ]+(\d+)[ ]*$", re.M)
RE_BOX = {
    name: re.compile(
        rf"^Page[ ]+(\d+)[ ]+{name}:[ ]+({NUMBER})[ ]+({NUMBER})[ ]+"
        rf"({NUMBER})[ ]+({NUMBER})[ ]*$", re.M,
    )
    for name in ("MediaBox", "CropBox")
}


def build_matrix_pdf() -> bytes:
    """Nine original PDF 1.6 pages with source-pinned, harmless blank streams."""
    leaves = b" ".join(f"{i} 0 R".encode() for i in range(3, PAGE_COUNT + 3))
    parent = (
        b"<< /Type /Pages /Kids [" + leaves
        + b"] /Count 9 /MediaBox [0 0 500 300] >>"
    )
    content_id = str(PAGE_COUNT + 3).encode()
    pages = [
        b"<< /Type /Page /Parent 2 0 R /Contents " + content_id
        + b" 0 R " + params + b" >>" for params in CASE_PARAMS
    ]
    pdf = _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>", parent, *pages,
        _stream(b"q\nQ\n"),
    ]).replace(b"%PDF-1.4", b"%PDF-1.6", 1)
    if (len(pdf) >= 2048 or
            hashlib.sha256(pdf).hexdigest() != CORPUS_SHA256):
        raise ValueError("Synthetic PDF corpus not pinned")
    return pdf


def parse_matrix_pdfinfo(raw: str) -> dict:
    """Fail closed on an unexpected change to the EXACT nine-page experiment."""
    if (not isinstance(raw, str) or not raw or not raw.isascii()
            or "\r" in raw or "\x00" in raw or len(raw) > MAX_REPORT_BYTES):
        raise ValueError("Untrusted PDF metadata")
    pages = re.findall(r"^Pages:[ ]+(\d+)[ ]*$", raw, re.M)
    encrypted = re.findall(r"^Encrypted:[ ]+(yes|no)[ ]*$", raw, re.M)
    if pages != ["9"] or encrypted != ["no"]:
        raise ValueError("Unexpected PDF metadata overview")
    for label in ("size", "rot", "MediaBox", "CropBox"):
        # Detect a duplicate or malformed extra record otherwise ignored by
        # the numeric-only patterns below.
        if len(re.findall(rf"^Page[ ]+\d+[ ]+{label}:", raw, re.M)) != PAGE_COUNT:
            raise ValueError("Incomplete or duplicated PDF page inventory")
    sizes = _records(raw, RE_SIZE, PAGE_COUNT)
    rotations = _records(raw, RE_ROT, PAGE_COUNT)
    media = _records(raw, RE_BOX["MediaBox"], PAGE_COUNT)
    crop = _records(raw, RE_BOX["CropBox"], PAGE_COUNT)

    entries: list[dict] = []
    below = []
    for i in range(1, PAGE_COUNT + 1):
        size = tuple(_decimal(x) for x in sizes[i])
        m = tuple(_decimal(x) for x in media[i])
        c = tuple(_decimal(x) for x in crop[i])
        if (size != tuple(Decimal(x) for x in EXPECTED_SIZE[i-1])
                or m != tuple(Decimal(x) for x in EXPECTED_MEDIA[i-1])
                or c != tuple(Decimal(x) for x in EXPECTED_CROP[i-1])):
            raise ValueError("PDF box differs from pinned synthetic reference")
        if int(rotations[i][0]) != EXPECTED_ROTATION[i-1]:
            raise ValueError("Unexpected page rotation")
        mw, mh = m[2] - m[0], m[3] - m[1]
        if min(mw, mh, *size) <= 0:
            raise ValueError("Invalid page geometry")
        if any(a < b for a,b in zip(size, (mw, mh))):
            below.append(i)
        if EXPECTED_ROTATION[i-1] in (90, 270):
            mw, mh = mh, mw
        w_px = int(((mw + Decimal("0.02")) * DPI / 72).to_integral_value(
            rounding=ROUND_CEILING))
        h_px = int(((mh + Decimal("0.02")) * DPI / 72).to_integral_value(
            rounding=ROUND_CEILING))
        entries.append({
            "page": i, "page_size_points": [float(v) for v in size],
            "media_box_points": [float(v) for v in m],
            "crop_box_points": [float(v) for v in c],
            "rotation": EXPECTED_ROTATION[i-1],
            "media_estimated_pixels_at_180_dpi": w_px * h_px,
        })
    if below != [2, 7, 9]:
        raise ValueError("CropBox vs MediaBox research control missing")
    return {
        "page_count": PAGE_COUNT,
        "pages": entries,
        "pages_where_page_size_understates_media": below,
        "extreme_media_hidden_by_small_page_size": True,
        "runtime_guard_implemented": False,
        "release_authorized": False,
    }


def verify_pixel_measurements(measurements: dict) -> dict:
    if (type(measurements) is not dict or measurements.keys() != EXPECTED_PIXELS.keys()
            or any(type(value) is not tuple or value != EXPECTED_PIXELS[name]
                   for name, value in measurements.items())):
        raise ValueError("Missing or unexpected raster differential control")
    if (measurements["p2"][0] * measurements["p2"][1]
            <= measurements["p2crop"][0] * measurements["p2crop"][1]
            or measurements["p7"][0] * measurements["p7"][1]
            <= measurements["p7crop"][0] * measurements["p7crop"][1]):
        raise ValueError("Expected CropBox differential not observed")
    return {
        "page2_default_png": list(measurements["p2"]),
        "page2_crop_png": list(measurements["p2crop"]),
        "page7_default_png": list(measurements["p7"]),
        "page7_crop_png": list(measurements["p7crop"]),
        "page8_default_png": list(measurements["p8"]),
        "default_raster_exceeds_crop_raster_observed": True,
    }


def semantic_report(raw: str, measurements: dict) -> dict:
    parsed = parse_matrix_pdfinfo(raw)
    differential = verify_pixel_measurements(measurements)
    return {
        **parsed, **differential,
        "status": "research_media_crop_raster_differential_only",
        "source_pdf_corpus_pinned": True,
        "corpus_sha256": CORPUS_SHA256,
        "measured_raster_cases": len(EXPECTED_PIXELS),
        "extreme_media_page_rasterized": False,
        "extreme_userunit_page_rasterized": False,
        "runtime_guard_implemented": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "user_unit_safety_verified": False,
        "cve_remediation_claimed": False,
        "release_authorized": False,
        "safe_for_untrusted_pdf_verified": False,
    }


def build_docker_args(
    image_id: str, fixtures: Path, results: Path,
    operation: str, case: str | None = None,
) -> list[str]:
    if image_id != IMAGE_ID:
        raise ValueError("Experimental image must match the exact local digest")
    for directory in (fixtures, results):
        if (not directory.is_dir() or directory.is_symlink()
                or any(char in str(directory) for char in (",", "\n", "\r"))):
            raise ValueError("Unsafe experimental fixture/output mount")
    root = [
        "docker", "run", "--rm", "--pull", "never",
        "--network", "none", "--read-only", "--user", "65534:65534",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "64", "--cpus", "1", "--memory", "256m",
        "--memory-swap", "256m",
        "--mount", f"type=bind,source={fixtures.resolve(strict=True)},target=/fixtures,readonly",
    ]
    if operation == "sha" and case is None:
        return [
            *root, "--entrypoint", "/usr/bin/sha256sum", image_id,
            *EXPECTED_EXPERIMENTAL_ELF_SHA256.keys(),
        ]
    if operation == "metadata" and case is None:
        return [
            *root, "--entrypoint", "/opt/folio-poppler/bin/pdfinfo",
            image_id, "-f", "1", "-l", "9", "-box", "/fixtures/matrix.pdf",
        ]
    if operation == "raster" and case in EXPECTED_PIXELS:
        page = int(case[1])
        return [
            *root,
            "--mount", f"type=bind,source={results.resolve(strict=True)},target=/results",
            "--entrypoint", "/opt/folio-poppler/bin/pdftoppm", image_id,
            "-f", str(page), "-l", str(page), "-singlefile",
            "-r", str(DPI), "-png",
            *(['-cropbox'] if case.endswith("crop") else []),
            "/fixtures/matrix.pdf", f"/results/{case}",
        ]
    raise ValueError("Unapproved experimental command or extreme raster page")


def inspect_local_matrix(
    *, runner: Callable = subprocess.run,
) -> dict:
    """Read-only, offline Docker experiment; never render pages 5 or 9."""
    corpus = build_matrix_pdf()
    with tempfile.TemporaryDirectory(prefix="folio-r134-box-") as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        results = root / "results"
        results.mkdir(mode=0o777)
        results.chmod(0o777)
        fixture = root / "matrix.pdf"
        fixture.write_bytes(corpus)
        fixture.chmod(0o644)

        def execute(operation: str, case: str | None = None) -> str:
            args = build_docker_args(IMAGE_ID, root, results, operation, case)
            try:
                completed = runner(
                    args, capture_output=True, text=True, timeout=30,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError("Experimental Poppler invocation unavailable") from error
            if (completed.returncode != 0 or not isinstance(completed.stdout, str)
                    or completed.stderr != "" or len(completed.stdout) > MAX_REPORT_BYTES):
                raise ValueError("Experimental Poppler control failed")
            if operation == "raster" and completed.stdout != "":
                raise ValueError("Unexpected raster stdout")
            return completed.stdout

        digests = parse_experimental_elf_digests(execute("sha"))
        raw_info = execute("metadata")
        parse_matrix_pdfinfo(raw_info)
        measures = {}
        for case in EXPECTED_PIXELS:
            execute("raster", case)
            measures[case] = verify_png_geometry(results / (case + ".png"))
        report = semantic_report(raw_info, measures)
        if (fixture.is_symlink() or hashlib.sha256(fixture.read_bytes()).hexdigest()
                != CORPUS_SHA256):
            raise ValueError("Synthetic PDF was modified during experiment")
    return {
        **report,
        "image_id": IMAGE_ID,
        "experimental_elf_sha256": digests,
        "experimental_elf_identity_verified": runner is subprocess.run,
        "real_differential_raster_executed": runner is subprocess.run,
        "pdfinfo_stdout_sha256": hashlib.sha256(raw_info.encode("ascii")).hexdigest(),
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-local-experiment", action="store_true")
    args = parser.parse_args()
    if not args.offline_local_experiment:
        parser.error("Explicit --offline-local-experiment required")
    try:
        print(json.dumps(inspect_local_matrix(), sort_keys=True))
    except (ValueError, OSError, UnicodeError):
        print(json.dumps({
            "status": "research_inconclusive",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
