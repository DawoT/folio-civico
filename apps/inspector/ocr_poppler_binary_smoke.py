"""R1.36: bounded, offline real-Poppler preflight/raster research.

Runs only on R1.34 SHA-pinned nine-page *synthetic* corpus. The Poppler
image is a disposable Debian lab build, NOT the inspector candidate runtime.
NEVER rasterizes the huge MediaBox page or the extreme UserUnit page.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from typing import Callable
import zlib

from inspector import (
    OCR_DPI, ReviewRequired, require_ocr_raster_geometry,
    parse_qpdf_page_inventory, parse_qpdf_user_unit,
)
from poppler_ocr_box_semantics_research import build_matrix_pdf, CORPUS_SHA256

IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
PDF_NAME = "matrix.pdf"
PAGE_COUNT = 9
ALLOWED_RASTER_PAGES = frozenset((1, 2, 4, 6, 7, 8))
CROP_CONTROLS = frozenset((2, 7))
PNG_EXPECTED = {
    1: (1488, 2105),
    2: (500, 500),
    4: (500, 500),
    6: (1000, 500),
    7: (1250, 750),
    8: (1, 1),
}
CROP_PNG_EXPECTED = {2: (250, 150), 7: (500, 500)}
HASH_PATHS = (
    "/usr/bin/pdfinfo", "/usr/bin/pdftoppm", "/usr/bin/qpdf",
    "/usr/lib/x86_64-linux-gnu/libpoppler.so.147",
)
PACKAGE_NAMES = ("poppler-utils", "libpoppler147", "qpdf")
MAX_TEXT_BYTES = 65_536


def prepare_corpus(folder: Path) -> Path:
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("Untrusted synthetic source directory")
    corpus = build_matrix_pdf()
    if hashlib.sha256(corpus).hexdigest() != CORPUS_SHA256:
        raise ValueError("Research corpus digest mismatch")
    target = folder / PDF_NAME
    if target.exists() or target.is_symlink():
        raise ValueError("Research corpus path not pristine")
    target.write_bytes(corpus)
    target.chmod(0o644)
    return target


def build_lab_command(
    image_id: str, source: Path, output: Path,
    *, tool: str, page: int | None = None, crop: bool = False,
    object_ref: tuple[int, int] | None = None,
) -> list[str]:
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise ValueError("Docker research image must be pinned by full ID")
    for folder in (source, output):
        if (not folder.is_dir() or folder.is_symlink()
                or any(c in str(folder) for c in (",", "\n", "\r"))):
            raise ValueError("Untrusted research mount")
    base = [
        "docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--cpus", "1", "--memory", "512m", "--memory-swap", "512m",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        "--mount", f"type=bind,source={source.resolve(strict=True)},target=/fixtures,readonly",
    ]
    if tool == "sha" and page is None and not crop:
        return [*base, "--entrypoint", "/usr/bin/sha256sum", image_id, *HASH_PATHS]
    if tool == "packages" and page is None and not crop:
        return [
            *base, "--entrypoint", "/usr/bin/dpkg-query", image_id,
            "-W", "-f", "$" + "{Package}=" + "$" + "{Version}\n",
            *PACKAGE_NAMES,
        ]
    if tool == "qpdf-pages" and page is None and not crop:
        return [*base, "--entrypoint", "/usr/bin/qpdf", image_id,
                "--json", "--json-key=pages", f"/fixtures/{PDF_NAME}"]
    if (tool == "qpdf-unit" and type(page) is int
            and 1 <= page <= PAGE_COUNT and not crop
            and isinstance(object_ref, tuple) and len(object_ref) == 2
            and all(type(n) is int for n in object_ref)
            and 1 <= object_ref[0] <= 1_000_000
            and 0 <= object_ref[1] <= 65535):
        object_number, generation = object_ref
        return [*base, "--entrypoint", "/usr/bin/qpdf", image_id,
                "--json", "--json-key=qpdf",
                f"--json-object={object_number},{generation}",
                f"/fixtures/{PDF_NAME}"]
    if tool == "qpdf-check" and page is None and not crop:
        return [*base, "--entrypoint", "/usr/bin/qpdf", image_id,
                "--check", f"/fixtures/{PDF_NAME}"]
    if tool == "qpdf-encrypted" and page is None and not crop:
        return [*base, "--entrypoint", "/usr/bin/qpdf", image_id,
                "--is-encrypted", f"/fixtures/{PDF_NAME}"]
    if (type(page) is int and 1 <= page <= PAGE_COUNT
            and tool == "pdfinfo" and not crop):
        return [*base, "--entrypoint", "/usr/bin/pdfinfo", image_id,
                "-f", str(page), "-l", str(page), "-box", f"/fixtures/{PDF_NAME}"]
    if (type(page) is int and tool == "pdftoppm"
            and page in ALLOWED_RASTER_PAGES
            and (not crop or page in CROP_CONTROLS)):
        suffix = f"p{page}" + ("crop" if crop else "")
        return [
            *base, "--mount",
            f"type=bind,source={output.resolve(strict=True)},target=/results",
            "--entrypoint", "/usr/bin/pdftoppm", image_id,
            "-f", str(page), "-l", str(page), "-singlefile",
            "-r", str(OCR_DPI), "-png", *(["-cropbox"] if crop else []),
            f"/fixtures/{PDF_NAME}", f"/results/{suffix}",
        ]
    raise ValueError("Unapproved synthetic experiment or extreme page")


def validate_page_raster_admission(
    raw: str, *, page: int, count: int,
    user_unit: Decimal = Decimal(1),
) -> tuple[int, int]:
    try:
        return require_ocr_raster_geometry(
            raw, page=page, count=count, user_unit=user_unit,
        )
    except ReviewRequired as error:
        raise ValueError("OCR MediaBox preflight rejected page") from error


def inspect_png_envelope(path: Path, upper: tuple[int, int]) -> tuple[int, int]:
    """Check IHDR, CRC, IEND, size, and dimensions. No full image decode."""
    if (not path.is_file() or path.is_symlink()
            or not 45 <= path.stat().st_size <= 32 * 1024 * 1024):
        raise ValueError("PNG raster missing or larger than the runtime file budget")
    with path.open("rb") as stream:
        header = stream.read(33)
        stream.seek(-12, 2)
        trailer = stream.read(12)
    if (header[:16] != b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"
            or trailer != b"\x00\x00\x00\x00IEND\xaeB\x60\x82"
            or header[24] != 8 or header[25] not in (2, 6)
            or header[26:29] != b"\x00\x00\x00"):
        raise ValueError("Unexpected PNG raster envelope")
    checksum = struct.unpack(">I", header[29:33])[0]
    if checksum != (zlib.crc32(header[12:29]) & 0xFFFFFFFF):
        raise ValueError("PNG IHDR CRC mismatch")
    dimensions = struct.unpack(">II", header[16:24])
    if (not all(0 < n <= bound for n, bound in zip(dimensions, upper))
            or dimensions[0] * dimensions[1] > upper[0] * upper[1]):
        raise ValueError("PNG exceeded geometry preflight")
    return dimensions


def _parse_hash_report(stdout: str) -> dict[str, str]:
    lines = stdout.splitlines()
    if len(lines) != len(HASH_PATHS):
        raise ValueError("Incomplete binary identity")
    result = {}
    for expected, line in zip(HASH_PATHS, lines):
        match = re.fullmatch(r"([a-f0-9]{64})  (/.+)", line)
        if not match or match.group(2) != expected:
            raise ValueError("Binary identity not tied to requested ELF")
        result[expected] = match.group(1)
    return result


def _parse_package_report(stdout: str) -> dict[str, str]:
    parsed = {}
    for line in stdout.splitlines():
        if not re.fullmatch(r"[a-z0-9.+:-]+=[A-Za-z0-9.+:~\-]+", line):
            raise ValueError("Noncanonical Debian package version")
        package, version = line.split("=", 1)
        package = package.removesuffix(":amd64")
        if package not in PACKAGE_NAMES or package in parsed:
            raise ValueError("Unexpected Debian package version")
        parsed[package] = version
    if set(parsed) != set(PACKAGE_NAMES):
        raise ValueError("Incomplete Debian package inventory")
    return parsed


def inspect_real_image(
    image_id: str, *, runner: Callable = subprocess.run,
) -> dict:
    """Execute offline, content-addressed Docker containers for synthetic PDF."""
    with tempfile.TemporaryDirectory(prefix="folio-r136-poppler-") as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        results = root / "results"
        results.mkdir()
        results.chmod(0o777)
        fixture = prepare_corpus(root)

        def execute(
            tool: str, page: int | None = None, *, crop: bool = False,
            object_ref: tuple[int, int] | None = None,
        ) -> str:
            argv = build_lab_command(
                image_id, root, results, tool=tool, page=page,
                crop=crop, object_ref=object_ref,
            )
            try:
                completed = runner(argv, capture_output=True, text=True,
                                   timeout=35, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ValueError("Real Poppler lab process unavailable") from error
            if (not isinstance(completed.stdout, str)
                    or not isinstance(completed.stderr, str)
                    or len(completed.stdout.encode("utf-8")) > MAX_TEXT_BYTES
                    or len(completed.stderr.encode("utf-8")) > MAX_TEXT_BYTES):
                raise ValueError("Poppler research output oversized")
            expected_rc = 2 if tool == "qpdf-encrypted" else 0
            if completed.returncode != expected_rc:
                raise ValueError("Experimental Docker engine failed closed")
            if tool not in ("qpdf-check", "qpdf-encrypted") and completed.stderr:
                raise ValueError("Unexpected Poppler experimental stderr")
            if tool == "pdftoppm" and completed.stdout:
                raise ValueError("Unexpected PNG raster stdout")
            return completed.stdout

        digests = _parse_hash_report(execute("sha"))
        packages = _parse_package_report(execute("packages"))
        execute("qpdf-encrypted")
        execute("qpdf-check")
        page_objects = parse_qpdf_page_inventory(
            execute("qpdf-pages"), count=PAGE_COUNT,
        )
        dimensions = {}
        measured_units = {}
        upper_bounds = {}
        for page in sorted(ALLOWED_RASTER_PAGES):
            ref = page_objects[page - 1]
            unit = parse_qpdf_user_unit(
                execute("qpdf-unit", page, object_ref=ref),
                object_number=ref[0], generation=ref[1],
            )
            measured_units[str(page)] = str(unit)
            meta = execute("pdfinfo", page)
            bound = validate_page_raster_admission(
                meta, page=page, count=PAGE_COUNT, user_unit=unit,
            )
            upper_bounds[str(page)] = list(bound)
            execute("pdftoppm", page)
            measured = inspect_png_envelope(results / f"p{page}.png", bound)
            if measured != PNG_EXPECTED[page]:
                raise ValueError("Real Poppler raster changed from expected corpus")
            dimensions[str(page)] = list(measured)
        crops = {}
        for page in sorted(CROP_CONTROLS):
            execute("pdftoppm", page, crop=True)
            measured = inspect_png_envelope(results / f"p{page}crop.png",
                                            tuple(upper_bounds[str(page)]))
            if measured != CROP_PNG_EXPECTED[page]:
                raise ValueError("Poppler CropBox differential missing")
            crops[str(page)] = list(measured)
        # Huge MediaBox page is metadata-only: MUST fail before a raster call,
        # even though its advertised CropBox/Page size is tiny.
        extreme_ref = page_objects[8]
        extreme_unit = parse_qpdf_user_unit(
            execute("qpdf-unit", 9, object_ref=extreme_ref),
            object_number=extreme_ref[0], generation=extreme_ref[1],
        )
        extreme_report = execute("pdfinfo", 9)
        try:
            validate_page_raster_admission(
                extreme_report, page=9, count=PAGE_COUNT, user_unit=extreme_unit,
            )
        except ValueError:
            extreme_blocked = True
        else:
            raise ValueError("Extreme MediaBox erroneously admitted to OCR")
        # Extreme UserUnit is NEVER rasterized, but QPDF-based preflight must
        # reject it despite innocuous 200x200 point MediaBox metadata.
        userunit_ref = page_objects[4]
        userunit = parse_qpdf_user_unit(
            execute("qpdf-unit", 5, object_ref=userunit_ref),
            object_number=userunit_ref[0], generation=userunit_ref[1],
        )
        userunit_meta = execute("pdfinfo", 5)
        try:
            validate_page_raster_admission(
                userunit_meta, page=5, count=PAGE_COUNT, user_unit=userunit,
            )
        except ValueError:
            userunit_rejected = True
        else:
            raise ValueError("Extreme UserUnit erroneously admitted to OCR")

        if (fixture.is_symlink() or hashlib.sha256(fixture.read_bytes()).hexdigest()
                != CORPUS_SHA256):
            raise ValueError("Synthetic PDF corpus altered during smoke")
        if (not dimensions["2"][0] > crops["2"][0]
                or not dimensions["7"][0] > crops["7"][0]):
            raise ValueError("Raster must expose the MediaBox/CropBox difference")
    return {
        "status": "experimental_debian_poppler_real_preflight_raster_smoke",
        "image_id": image_id,
        "corpus_sha256": CORPUS_SHA256,
        "debian_package_versions": packages,
        "measured_executable_sha256": digests,
        "real_docker_processes_executed": runner is subprocess.run,
        "default_raster_dimensions": dimensions,
        "cropbox_control_dimensions": crops,
        "preflight_max_pixel_dimensions": upper_bounds,
        "qpdf_page_userunits": measured_units,
        "extreme_userunit_observed": str(userunit),
        "extreme_media_page_preflight_rejected": extreme_blocked,
        "extreme_media_page_rasterized": False,
        "extreme_userunit_page_rasterized": False,
        "extreme_userunit_page_preflight_rejected": userunit_rejected,
        "runtime_candidate_equivalence_verified": False,
        "source_to_elf_reproducibility_verified": False,
        "safe_for_untrusted_pdfs_verified": False,
        "cve_remediation_claimed": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--offline-lab-smoke", action="store_true")
    args = parser.parse_args()
    if not args.offline_lab_smoke:
        parser.error("Explicit --offline-lab-smoke is required")
    try:
        report = inspect_real_image(args.image_id)
    except (ValueError, OSError, TypeError, UnicodeError):
        print(json.dumps({
            "status": "experimental_poppler_smoke_inconclusive",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
