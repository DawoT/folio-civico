"""R1.33: read-only per-page geometry research for the Folio OCR raster path.

Never used by inspector.py. The estimates come from human-readable pdfinfo
metadata, which is rounded and does NOT expose all PDF rendering semantics.
No result from this module constitutes a verified runtime raster safety gate,
CVE remediation, a source-to-ELF build attestation or release authorization.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zlib
from typing import Callable

from fixtures import _pdf, _stream

DPI = 180  # inspector.py: pdftoppm -r 180 -png
PROVISIONAL_MAX_SIDE = 8192
PROVISIONAL_MAX_PIXELS = 16_000_000  # Research threshold, NOT production policy.
MAX_PAGES = 100
MAX_REPORT_BYTES = 65_536
EXPECTED_CORPUS_SHA256 = "f0ed77b9fad56aa7741ea02b9ebceb427bdf705913fbb643ee12a0b13acc5b2f"
# Observed directly in the immutable experimental image. ELF identity alone is
# not proof of source-to-binary reproducibility or applicability to runtime.
EXPECTED_EXPERIMENTAL_ELF_SHA256 = {
    "/opt/folio-poppler/lib/libpoppler.so.147":
        "3ca61c1d42c8a040e47f01524d0bc3d45d73bc3e7981fe79a46b9cf9cb8dfe3b",
    "/opt/folio-poppler/bin/pdftoppm":
        "04dd62778926081c15bd437eaf58dab27e205e59f5b00a5d33585df7ce3617a0",
    "/opt/folio-poppler/bin/pdfinfo":
        "888221ae778e7bc97261c743cf779d4a982c94afa70e91b2ef49eeef7897ebed",
}
IMAGE_ID_PATTERN = re.compile(r"sha256:[a-f0-9]{64}\Z")
NUMBER = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[Ee][+-]?\d{1,2})?"
RE_SIZE = re.compile(
    rf"^Page\s+(\d+)\s+size:\s+({NUMBER})\s+x\s+({NUMBER})\s+pts"
    r"(?:\s+\([^()\r\n]{1,80}\))?\s*$", re.M,
)
RE_ROT = re.compile(r"^Page\s+(\d+)\s+rot:\s+(\d+)\s*$", re.M)
RE_MEDIA = re.compile(
    rf"^Page\s+(\d+)\s+MediaBox:\s+({NUMBER})\s+({NUMBER})\s+({NUMBER})\s+({NUMBER})\s*$",
    re.M,
)


def synthetic_geometry_pdf() -> bytes:
    """Four original pages: A4, extreme MediaBox, rotated A4, UserUnit probe."""
    pages = [
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 7 0 R >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 536870919 1] /Contents 7 0 R >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] /Rotate 90 /Contents 7 0 R >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /UserUnit 5 /Contents 7 0 R >>",
    ]
    blob = _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R 6 0 R] /Count 4 >>",
        *pages,
        _stream(b"q\nQ\n"),
    ]).replace(b"%PDF-1.4", b"%PDF-1.6", 1)
    if (len(blob) >= 2048 or hashlib.sha256(blob).hexdigest()
            != EXPECTED_CORPUS_SHA256):
        raise ValueError("Unpinned research PDF corpus")
    return blob


def _decimal(token: str) -> Decimal:
    if len(token) > 32:
        raise ValueError("Unbounded geometry token")
    try:
        value = Decimal(token)
    except InvalidOperation as exc:
        raise ValueError("Malformed PDF page coordinate") from exc
    if not value.is_finite() or abs(value) > Decimal("1e12"):
        raise ValueError("Non-finite or unbounded PDF page coordinate")
    return value


def _records(raw: str, pattern: re.Pattern[str], count: int) -> dict[int, tuple[str, ...]]:
    entries: dict[int, tuple[str, ...]] = {}
    found = list(pattern.finditer(raw))
    if len(found) != count:
        raise ValueError("PDF page geometry inventory incomplete")
    for match in found:
        page = int(match.group(1))
        if page < 1 or page > count or page in entries:
            raise ValueError("Duplicate or unexpected PDF page geometry")
        entries[page] = match.groups()[1:]
    if set(entries) != set(range(1, count + 1)):
        raise ValueError("Non-contiguous PDF page geometry inventory")
    return entries


def inspect_pdfinfo_geometry(raw: str) -> dict:
    """Bounded analysis of -f 1 -l N -box; intentionally NOT an accept/reject gate."""
    if (not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > MAX_REPORT_BYTES
            or not raw.isascii() or "\r" in raw or "\x00" in raw):
        raise ValueError("Untrusted PDF metadata report")
    counts = re.findall(r"^Pages:\s*(\d+)\s*$", raw, re.M)
    encryptions = re.findall(r"^Encrypted:\s*(no|yes)\b.*$", raw, re.M)
    if (len(counts) != 1 or len(encryptions) != 1 or encryptions[0] != "no"
            or not 1 <= int(counts[0]) <= MAX_PAGES):
        raise ValueError("Untrusted or unsupported page inventory")
    count = int(counts[0])
    # A second malformed line must not be silently ignored just because a
    # correctly formatted line for that page is already present.
    for marker in ("size", "rot", "MediaBox"):
        if len(re.findall(rf"^Page\s+\d+\s+{marker}:", raw, re.M)) != count:
            raise ValueError("Unexpected additional page metadata")
    sizes = _records(raw, RE_SIZE, count)
    rotations = _records(raw, RE_ROT, count)
    media = _records(raw, RE_MEDIA, count)

    pages = []
    for page in range(1, count + 1):
        size_w, size_h = (_decimal(t) for t in sizes[page])
        x0, y0, x1, y1 = (_decimal(t) for t in media[page])
        width, height = x1 - x0, y1 - y0
        if min(width, height, size_w, size_h) <= 0:
            raise ValueError("Invalid PDF page dimensions")
        # pdfinfo prints Page size in scientific notation for extreme pages.
        # Its two-decimal-place MediaBox may also round subpoint coordinates.
        if any(
            abs(declared - measured) > max(Decimal("0.025"), measured * Decimal("0.00001"))
            for declared, measured in ((size_w, width), (size_h, height))
        ):
            raise ValueError("Page size and MediaBox disagree")
        rotation = int(rotations[page][0])
        if rotation not in (0, 90, 180, 270):
            raise ValueError("Unknown raster rotation")
        if rotation in (90, 270):
            width, height = height, width
        # A conservative estimate for a rounded 2-decimal MediaBox, not a
        # guarantee about GfxState, CropBox, UserUnit or pdftoppm internals.
        width_px = int(((width + Decimal("0.02")) * DPI / 72).to_integral_value(
            rounding=ROUND_CEILING))
        height_px = int(((height + Decimal("0.02")) * DPI / 72).to_integral_value(
            rounding=ROUND_CEILING))
        pixels = width_px * height_px
        pages.append({
            "page": page, "rotation": rotation,
            "estimated_width_px_upper_bound": width_px,
            "estimated_height_px_upper_bound": height_px,
            "estimated_pixels_upper_bound": pixels,
            "provisional_budget_exceeded": (
                max(width_px, height_px) > PROVISIONAL_MAX_SIDE
                or pixels > PROVISIONAL_MAX_PIXELS
            ),
        })
    return {
        "status": "research_pdfinfo_page_geometry_only",
        "dpi": DPI, "page_count": count, "pages": pages,
        "provisional_max_side": PROVISIONAL_MAX_SIDE,
        "provisional_max_pixels": PROVISIONAL_MAX_PIXELS,
        "metadata_requires_independent_user_unit_review": True,
        "user_unit_effect_verified": False,
        "page_geometry_safe_for_untrusted_pdf_verified": False,
        "runtime_guard_implemented": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "cve_remediation_claimed": False,
        "release_authorized": False,
    }


def build_pdfinfo_args(image_id: str, fixtures: Path, *, docker: str = "docker") -> list[str]:
    if not IMAGE_ID_PATTERN.fullmatch(image_id):
        raise ValueError("Research image must be content-addressed")
    if (not fixtures.is_dir() or fixtures.is_symlink()
            or any(c in str(fixtures) for c in (",", "\n", "\r"))):
        raise ValueError("Untrusted synthetic input mount")
    return [
        docker, "run", "--rm", "--pull", "never", "--network", "none",
        "--read-only", "--user", "65534:65534",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "64", "--cpus", "1", "--memory", "256m",
        "--memory-swap", "256m",
        "--mount", f"type=bind,source={fixtures.resolve(strict=True)},target=/fixtures,readonly",
        "--entrypoint", "/opt/folio-poppler/bin/pdfinfo", image_id,
        "-f", "1", "-l", "4", "-box", "/fixtures/synthetic.pdf",
    ]


def parse_experimental_elf_digests(stdout: str) -> dict[str, str]:
    """Require all three exact SHA lines from the experimental image."""
    expected = [
        f"{digest}  {path}"
        for path, digest in EXPECTED_EXPERIMENTAL_ELF_SHA256.items()
    ]
    if not isinstance(stdout, str) or stdout.splitlines() != expected:
        raise ValueError("Experimental Poppler ELF identity incomplete")
    return dict(EXPECTED_EXPERIMENTAL_ELF_SHA256)


def build_small_raster_args(
    image_id: str, fixtures: Path, results: Path, page: int,
    *, docker: str = "docker",
) -> list[str]:
    """Use the actual OCR flags only on bounded synthetic pages (never page 2)."""
    if type(page) is not int or page not in (1, 3, 4):
        raise ValueError("Unapproved synthetic PDF raster page")
    if (not results.is_dir() or results.is_symlink()
            or any(c in str(results) for c in (",", "\n", "\r"))):
        raise ValueError("Untrusted output mount")
    metadata_args = build_pdfinfo_args(image_id, fixtures, docker=docker)
    base = metadata_args[:metadata_args.index("--entrypoint")]
    return [
        *base,
        "--mount", f"type=bind,source={results.resolve(strict=True)},target=/results",
        "--entrypoint", "/opt/folio-poppler/bin/pdftoppm", image_id,
        "-f", str(page), "-l", str(page), "-singlefile",
        "-r", str(DPI), "-png", "/fixtures/synthetic.pdf", f"/results/page{page}",
    ]


def verify_png_geometry(path: Path) -> tuple[int, int]:
    """Validate a bounded PNG envelope and its IHDR/IEND before reading dimensions.

    No PNG decompression is done. Engine exit status is checked independently.
    """
    if not path.is_file() or path.is_symlink():
        raise ValueError("Raster control missing or symlinked")
    if not 45 <= path.stat().st_size <= 8 * 1024 * 1024:
        raise ValueError("Raster control absent or oversized")
    with path.open("rb") as stream:
        header = stream.read(33)
        stream.seek(-12, 2)
        trailer = stream.read(12)
    if (header[:8] != b"\x89PNG\r\n\x1a\n"
            or header[8:16] != b"\x00\x00\x00\x0dIHDR"
            or trailer != b"\x00\x00\x00\x00IEND\xaeB\x60\x82"):
        raise ValueError("Invalid raster PNG framing")
    if zlib.crc32(header[12:29]) & 0xFFFFFFFF != struct.unpack(">I", header[29:33])[0]:
        raise ValueError("Invalid raster PNG IHDR digest")
    width, height = struct.unpack(">II", header[16:24])
    if (not 0 < width <= PROVISIONAL_MAX_SIDE
            or not 0 < height <= PROVISIONAL_MAX_SIDE
            or width * height > PROVISIONAL_MAX_PIXELS
            or header[24] != 8 or header[25] not in (2, 6)):
        raise ValueError("Untrusted or oversized raster PNG dimensions")
    return width, height


def inspect_local_image(
    image_id: str, *, runner: Callable = subprocess.run,
    with_small_raster_controls: bool = False,
) -> dict:
    """Offline metadata plus opt-in real OCR raster controls on tiny pages only."""
    blob = synthetic_geometry_pdf()
    with tempfile.TemporaryDirectory(prefix="folio-r133-geometry-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        (root / "synthetic.pdf").write_bytes(blob)
        (root / "synthetic.pdf").chmod(0o644)
        command = build_pdfinfo_args(image_id, root)
        executable_digest_args = [
            *command[:command.index("--entrypoint")],
            "--entrypoint", "/usr/bin/sha256sum", image_id,
            *EXPECTED_EXPERIMENTAL_ELF_SHA256,
        ]
        try:
            digest_result = runner(
                executable_digest_args, capture_output=True, text=True,
                timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Experimental ELF digest measurement unavailable") from exc
        if digest_result.returncode != 0 or digest_result.stderr != "":
            raise ValueError("Experimental ELF digest measurement incomplete")
        measured_elf_sha256 = parse_experimental_elf_digests(digest_result.stdout)
        try:
            result = runner(command, capture_output=True, text=True,
                            timeout=25, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Local PDF geometry research did not complete") from exc
        if (result.returncode != 0 or not isinstance(result.stdout, str)
                or not isinstance(result.stderr, str) or result.stderr
                or len(result.stdout.encode("utf-8")) > MAX_REPORT_BYTES):
            raise ValueError("Local PDF metadata process incomplete")
        report = inspect_pdfinfo_geometry(result.stdout)
        controls: dict[str, dict[str, int]] = {}
        if with_small_raster_controls:
            results = root / "results"
            results.mkdir(mode=0o777)
            results.chmod(0o777)
            for page in (1, 3, 4):
                args = build_small_raster_args(image_id, root, results, page)
                try:
                    completed = runner(args, capture_output=True, text=True,
                                       timeout=35, check=False)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise ValueError("Bounded raster control unavailable") from exc
                if (completed.returncode != 0 or completed.stdout != ""
                        or completed.stderr != ""):
                    raise ValueError("Bounded raster process incomplete")
                width, height = verify_png_geometry(results / f"page{page}.png")
                upper = report["pages"][page - 1]
                if (not 0 <= upper["estimated_width_px_upper_bound"] - width <= 2
                        or not 0 <= upper["estimated_height_px_upper_bound"] - height <= 2):
                    raise ValueError("PDF metadata does not bound measured raster dimensions")
                controls[str(page)] = {"raster_width_px": width, "raster_height_px": height}
        # A mounted file can change between initial hashing and a child process.
        # Detect persistent mutation after the entire experiment (not a TOCTOU
        # proof against an actor able to modify and restore the file).
        fixture = root / "synthetic.pdf"
        if (fixture.is_symlink()
                or hashlib.sha256(fixture.read_bytes()).hexdigest()
                != EXPECTED_CORPUS_SHA256):
            raise ValueError("Mounted synthetic PDF was altered")
    if report["page_count"] != 4 or not report["pages"][1]["provisional_budget_exceeded"]:
        raise ValueError("Research corpus did not exercise extreme geometry")
    return {
        **report, "image_id": image_id,
        "bounded_real_ocr_raster_controls": controls,
        "small_page_raster_controls_verified": (
            with_small_raster_controls and runner is subprocess.run
        ),
        "synthetic_pdf_sha256": EXPECTED_CORPUS_SHA256,
        "experimental_elf_sha256": measured_elf_sha256,
        "experimental_elf_identity_verified": runner is subprocess.run,
        "pdfinfo_stdout_sha256": hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
        "real_pdfinfo_executed": runner is subprocess.run,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--with-small-raster-controls", action="store_true")
    args = parser.parse_args()
    try:
        report = inspect_local_image(
            args.image_id, with_small_raster_controls=args.with_small_raster_controls,
        )
    except (ValueError, OSError, TypeError, UnicodeError):
        print(json.dumps({"status": "error",
                          "reason": "per_page_geometry_research_incomplete",
                          "release_authorized": False}, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
