#!/usr/bin/env python3
"""Folio Cívico isolated PDF inspector.

Execute ONLY inside a container/process sandbox with no outbound networking,
non-root user, seccomp, resource limits, fresh offline ClamAV signatures and
read-only filesystem except a bounded private tmpfs. This service is not bound
to Cloudflare until operator approval.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable
import zlib

MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_PAGES = 100
MAX_PAGE_TEXT = 8000
# Defense-in-depth for blank pages rasterized at 180 DPI. A1 passes; A0 needs
# manual handling rather than an unbounded raster. These are initial admission
# limits, not a proof of safety for every Poppler PDF feature or a CVE fix.
OCR_DPI = 180
OCR_MAX_SIDE_PX = 8192
OCR_MAX_PIXELS = 32_000_000
OCR_MAX_RASTER_BYTES = 32 * 1024 * 1024
OCR_MAX_COORDINATE_PT = Decimal("1000000")
OCR_GEOMETRY_ROUNDING_MARGIN_PT = Decimal("0.02")
OCR_MAX_METADATA_BYTES = 65_536
MAX_SIGNATURE_AGE = 72 * 60 * 60
MAX_PROCESS_SECONDS = 30
MAX_TOTAL_SECONDS = 8 * 60
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]")
ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HASH = re.compile(r"^[a-f0-9]{64}$")


class ReviewRequired(Exception):
    """Suspicious, malformed, encrypted or unsupported input: no clean verdict."""


class ScannerUnavailable(Exception):
    """A mandatory verification engine or signature database is unavailable."""


CORE_CLAMAV_DATABASES = frozenset(("daily", "main", "bytecode"))


def require_fresh_signatures(directory: Path, now: float | None = None) -> None:
    """Require all official core DBs; one freshly touched file is insufficient.

    The scanner image is read-only at runtime. mtime is an operational age
    gate, not proof that signature contents are authentic; freshclam validates
    the downloaded databases during image construction.
    """
    if not directory.is_dir() or directory.is_symlink():
        raise ScannerUnavailable("ClamAV signatures not mounted")
    current = time.time() if now is None else now
    databases: dict[str, Path] = {}
    try:
        for file in directory.iterdir():
            if file.suffix not in (".cvd", ".cld"):
                continue
            # A duplicate core name could cause the engine to select an
            # unintended database. Additional databases need review.
            if (file.stem not in CORE_CLAMAV_DATABASES
                    or file.stem in databases
                    or file.is_symlink() or not file.is_file()):
                raise ScannerUnavailable("Unapproved or ambiguous ClamAV database")
            databases[file.stem] = file
        if databases.keys() != CORE_CLAMAV_DATABASES:
            raise ScannerUnavailable("ClamAV core signature databases incomplete")
        for file in databases.values():
            stats = file.stat()
            if (stats.st_size == 0
                    or stats.st_mtime < current - MAX_SIGNATURE_AGE
                    or stats.st_mtime > current + 300):
                raise ScannerUnavailable("ClamAV signatures are missing or stale")
    except OSError as error:
        raise ScannerUnavailable("Unable to validate ClamAV signature inventory") from error


MAX_ENGINE_OUTPUT_BYTES = 2 * 1024 * 1024
MIN_CLAMAV_RELEASE = (1, 5, 5)
QPDF_UNENCRYPTED = "not_encrypted"

# Never let an untrusted PDF/AV parser inherit the service token, HMAC key,
# loader hooks, or caller-defined Fontconfig XML. Fontconfig must keep using
# the image-owned system configuration: removing it lost visible PDF text.
# This is a defense-in-depth control, NOT a fix for Expat or Poppler CVEs.
_ENGINE_ENV = {
    "PATH": "/opt/folio-poppler/bin:/opt/folio-ocr/bin:/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TESSDATA_PREFIX": "/usr/share/tesseract-ocr/5/tessdata",
    "FONTCONFIG_FILE": "/etc/fonts/fonts.conf",
    "FONTCONFIG_PATH": "/etc/fonts",
    "HOME": "/nonexistent",
    "XDG_CONFIG_HOME": "/nonexistent",
    "XDG_CACHE_HOME": "/nonexistent",
}


def engine_environment() -> dict[str, str]:
    """Fresh, deterministic subprocess environment without caller secrets."""
    return dict(_ENGINE_ENV)


def verify_clamav_version(raw: str) -> None:
    """Refuse the ClamAV releases affected by November 2026 CVEs.

    The scanner must use the tested 1.5 feature series. A newer feature line
    needs a separate compatibility review rather than automatic admission.
    """
    match = re.match(r"^ClamAV (\d+)\.(\d+)\.(\d+)(?=/|\s|$)", raw.strip())
    if not match:
        raise ScannerUnavailable("Invalid ClamAV version metadata")
    installed = tuple(int(group) for group in match.groups())
    if installed[:2] != (1, 5) or installed < MIN_CLAMAV_RELEASE:
        raise ScannerUnavailable("Patched ClamAV 1.5.5+ is required")


def command(argv: list[str], cwd: Path, seconds: int = MAX_PROCESS_SECONDS) -> str:
    # Never invoke a shell or interpolate a document-controlled command.
    # Redirect untrusted parser output to the bounded private tmpfs rather
    # than accumulating arbitrary decompressed output in Worker memory.
    with tempfile.TemporaryFile(mode="w+b", dir=cwd) as output:
        try:
            result = subprocess.run(
                argv, cwd=cwd, check=False, stdout=output,
                stderr=subprocess.DEVNULL, timeout=seconds,
                env=engine_environment()
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
            raise ScannerUnavailable("Required inspector engine unavailable") from error
        # qpdf --is-encrypted has intentionally nonstandard exit codes:
        # 0 = encrypted, 2 = NOT encrypted; 1/3/signals = indeterminate.
        # This check is mandatory BEFORE any Poppler parser touches the PDF.
        if argv[:2] == ["qpdf", "--is-encrypted"] and len(argv) == 3:
            if result.returncode == 2:
                return QPDF_UNENCRYPTED
            if result.returncode == 0:
                raise ReviewRequired("Encrypted PDFs are not supported")
            raise ScannerUnavailable("PDF encryption preflight unavailable")
        if result.returncode != 0:
            # ClamAV uses 1 for a detection, 2 for engine/database failures.
            # A broken antivirus must be retried, never classified as a document finding.
            if argv[0] == "clamscan" and result.returncode != 1:
                raise ScannerUnavailable("ClamAV could not complete inspection")
            raise ReviewRequired("PDF scan, validation, or extraction rejected")
        if os.fstat(output.fileno()).st_size > MAX_ENGINE_OUTPUT_BYTES:
            raise ReviewRequired("Inspector output exceeds limit")
        output.seek(0)
        try:
            return output.read(MAX_ENGINE_OUTPUT_BYTES + 1).decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ReviewRequired("Non-UTF-8 inspector output") from error


# pdfinfo -f PAGE -l PAGE -box exposes effective per-page MediaBox after
# inheritance. "Page size" is normally based on CropBox and MUST NEVER be
# used to budget pdftoppm without -cropbox.
_OCR_NUM = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d{1,2})?"
_OCR_SIZE = re.compile(
    rf"^Page[ \t]+(\d+)[ \t]+size:[ \t]+({_OCR_NUM})[ \t]+x[ \t]+({_OCR_NUM})"
    r"[ \t]+pts(?:[ \t]+\([^()\r\n]{1,80}\))?[ \t]*$", re.M,
)
_OCR_ROT = re.compile(r"^Page[ \t]+(\d+)[ \t]+rot:[ \t]+(\d+)[ \t]*$", re.M)
_OCR_BOX = {
    kind: re.compile(
        rf"^Page[ \t]+(\d+)[ \t]+{kind}:[ \t]+"
        rf"({_OCR_NUM})[ \t]+({_OCR_NUM})[ \t]+({_OCR_NUM})[ \t]+({_OCR_NUM})[ \t]*$",
        re.M,
    )
    for kind in ("MediaBox", "CropBox")
}


def _ocr_decimal(token: str) -> Decimal:
    if len(token) > 32:
        raise ReviewRequired("Invalid OCR geometry coordinate")
    try:
        value = Decimal(token)
    except InvalidOperation as error:
        raise ReviewRequired("Invalid OCR geometry coordinate") from error
    if not value.is_finite() or abs(value) > OCR_MAX_COORDINATE_PT:
        raise ReviewRequired("Unsupported OCR geometry coordinate")
    return value


OCR_QPDF_JSON_MAX_BYTES = 1024 * 1024
OCR_MAX_USER_UNIT = Decimal("75000")
_OCR_PAGE_REF = re.compile(r"([1-9][0-9]{0,8}) ([0-9]{1,5}) R\Z")


def _parse_qpdf_json(raw: str) -> dict:
    """Read bounded QPDF v2 JSON with duplicate-key rejection."""
    if (not isinstance(raw, str) or not raw
            or len(raw.encode("utf-8")) > OCR_QPDF_JSON_MAX_BYTES
            or CONTROL.search(raw)):
        raise ReviewRequired("QPDF page structure report unavailable")

    def unique_keys(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ReviewRequired("Ambiguous QPDF JSON object keys")
            result[key] = value
        return result

    def reject_non_finite(_value: str) -> None:
        raise ReviewRequired("Invalid QPDF JSON numeric constant")

    try:
        document = json.loads(
            raw, parse_int=Decimal, parse_float=Decimal,
            object_pairs_hook=unique_keys,
            parse_constant=reject_non_finite,
        )
    except (ValueError, TypeError, OverflowError) as error:
        raise ReviewRequired("Malformed QPDF JSON document") from error
    if (not isinstance(document, dict)
            or document.get("version") != Decimal(2)):
        raise ReviewRequired("Unknown QPDF JSON contract")
    return document


def parse_qpdf_page_inventory(raw: str, *, count: int) -> tuple[tuple[int, int], ...]:
    """Resolve QPDF's ordered page object IDs, not PDF-byte string searches."""
    if type(count) is not int or not 1 <= count <= MAX_PAGES:
        raise ReviewRequired("Unsupported page inventory length")
    document = _parse_qpdf_json(raw)
    pages = document.get("pages")
    if not isinstance(pages, list) or len(pages) != count:
        raise ReviewRequired("Incomplete QPDF ordered page inventory")
    objects = []
    for i, record in enumerate(pages, 1):
        if (not isinstance(record, dict)
                or type(record.get("pageposfrom1")) is not Decimal
                or record["pageposfrom1"] != Decimal(i)
                or not isinstance(record.get("object"), str)):
            raise ReviewRequired("Ambiguous QPDF page reference")
        match = _OCR_PAGE_REF.fullmatch(record["object"])
        if not match:
            raise ReviewRequired("Unsupported QPDF page reference")
        object_number, generation = map(int, match.groups())
        if object_number > 1_000_000 or generation > 65535:
            raise ReviewRequired("Out-of-range QPDF page reference")
        objects.append((object_number, generation))
    if len(set(objects)) != count:
        raise ReviewRequired("Duplicate QPDF page references")
    return tuple(objects)


def parse_qpdf_user_unit(
    raw: str, *, object_number: int, generation: int,
) -> Decimal:
    """Fail closed if page /UserUnit is nonnumeric, indirect, or out of range.

    QPDF's JSON decoding resolves object streams and names, but an indirect
    numeric /UserUnit reference must be handled in a future reviewed parser.
    Rejecting it avoids silently assuming the default unit.
    """
    if (type(object_number) is not int or not 1 <= object_number <= 1_000_000
            or type(generation) is not int or not 0 <= generation <= 65535):
        raise ReviewRequired("Invalid QPDF page object identity")
    doc = _parse_qpdf_json(raw)
    objects = doc.get("qpdf")
    key = f"obj:{object_number} {generation} R"
    if (not isinstance(objects, list) or len(objects) != 2
            or not isinstance(objects[0], dict)
            or objects[0].get("jsonversion") != Decimal(2)
            or not isinstance(objects[1], dict)
            or set(objects[1]) != {key}):
        raise ReviewRequired("Unexpected QPDF page dictionary identity")
    entry = objects[1][key]
    if (not isinstance(entry, dict) or not isinstance(entry.get("value"), dict)
            or entry["value"].get("/Type") != "/Page"):
        raise ReviewRequired("Unexpected QPDF page dictionary shape")
    value = entry["value"].get("/UserUnit", Decimal(1))
    if (type(value) is not Decimal or not value.is_finite()
            or not Decimal(1) <= value <= OCR_MAX_USER_UNIT):
        raise ReviewRequired("Unsupported PDF UserUnit for OCR")
    return value


def require_ocr_raster_geometry(
    raw: str, *, page: int, count: int,
    user_unit: Decimal,
) -> tuple[int, int]:
    """Fail closed on per-page MediaBox before pdftoppm -r 180 -png.

    Conservative OCR budget from pdfinfo's rounded MediaBox, not its CropBox
    page-size line. When QPDF identifies a nondefault UserUnit, scale the
    estimated pixel budget pessimistically even if pdftoppm ignores UserUnit.
    This does not verify internal Poppler memory or source/ELF identity.
    """
    if (type(page) is not int or type(count) is not int
            or type(user_unit) is not Decimal or not user_unit.is_finite()
            or not Decimal(1) <= user_unit <= OCR_MAX_USER_UNIT
            or not 1 <= page <= count <= MAX_PAGES or not isinstance(raw, str)
            or not raw or CONTROL.search(raw)
            or len(raw.encode("utf-8")) > OCR_MAX_METADATA_BYTES):
        raise ReviewRequired("Invalid OCR page geometry report")
    pages = re.findall(r"^Pages:[ \t]*(\d+)[ \t]*$", raw, re.M)
    encryptions = re.findall(r"^Encrypted:[ \t]*(yes|no)\b[^\r\n]*$", raw, re.M)
    if pages != [str(count)] or encryptions != ["no"]:
        raise ReviewRequired("OCR page inventory unavailable")

    matches: dict[str, tuple[str, ...]] = {}
    for kind, pattern in (
        ("size", _OCR_SIZE), ("rot", _OCR_ROT),
        ("MediaBox", _OCR_BOX["MediaBox"]), ("CropBox", _OCR_BOX["CropBox"]),
    ):
        # Checking both the marker and the full record detects malformed or
        # duplicate entries and metadata for an unintended page.
        markers = re.findall(
            rf"^Page[ \t]+(\d+)[ \t]+{kind}:", raw, re.M,
        )
        found = list(pattern.finditer(raw))
        if (len(markers) != 1 or markers != [str(page)]
                or len(found) != 1 or found[0].group(1) != str(page)):
            raise ReviewRequired("OCR page geometry metadata incomplete")
        matches[kind] = found[0].groups()[1:]

    try:
        size = tuple(_ocr_decimal(t) for t in matches["size"])
        media = tuple(_ocr_decimal(t) for t in matches["MediaBox"])
        crop = tuple(_ocr_decimal(t) for t in matches["CropBox"])
        rot = int(matches["rot"][0])
    except (ValueError, OverflowError) as error:
        raise ReviewRequired("Invalid OCR page geometry") from error
    if rot not in (0, 90, 180, 270) or min(size) <= 0:
        raise ReviewRequired("Unsupported OCR page rotation or size")
    for rect in (media, crop):
        if rect[2] <= rect[0] or rect[3] <= rect[1]:
            raise ReviewRequired("Invalid OCR page rectangle")

    width_pt, height_pt = media[2] - media[0], media[3] - media[1]
    if rot in (90, 270):
        width_pt, height_pt = height_pt, width_pt
    # pdfinfo reports box coordinates rounded to two decimal places. Add a
    # two-coordinate rounding margin rather than assuming the printed box is
    # exact. Decimal avoids binary float and signed-overflow arithmetic here.
    width_px = int(((width_pt + OCR_GEOMETRY_ROUNDING_MARGIN_PT)
                    * user_unit * OCR_DPI / 72).to_integral_value(
                        rounding=ROUND_CEILING))
    height_px = int(((height_pt + OCR_GEOMETRY_ROUNDING_MARGIN_PT)
                     * user_unit * OCR_DPI / 72).to_integral_value(
                         rounding=ROUND_CEILING))
    if (width_px < 1 or height_px < 1
            or max(width_px, height_px) > OCR_MAX_SIDE_PX
            or width_px * height_px > OCR_MAX_PIXELS):
        raise ReviewRequired("OCR raster page exceeds geometry budget")
    return width_px, height_px


MAX_PDFIMAGE_LIST_BYTES = 256 * 1024
_PDFIMAGE_COLUMNS = (
    "page", "num", "type", "width", "height", "color", "comp", "bpc",
    "enc", "interp", "object", "ID", "x-ppi", "y-ppi", "size", "ratio",
)


def has_pdf_page_raster(raw: str, *, page: int, count: int) -> bool:
    """Admit only a complete Poppler pdfimages -list page-specific report.

    A raster XObject beside digital text may contain evidence pdftotext never
    extracted. Route to human review; this is not proof that image-free pages
    contain no other visual-only content (e.g. vector graphics or patterns).
    """
    if (type(page) is not int or type(count) is not int
            or not 1 <= page <= count <= MAX_PAGES or not isinstance(raw, str)
            or len(raw.encode("utf-8")) > MAX_PDFIMAGE_LIST_BYTES
            or CONTROL.search(raw)):
        raise ReviewRequired("PDF page raster inventory unavailable")
    lines = raw.splitlines()
    if (len(lines) < 2 or tuple(lines[0].split()) != _PDFIMAGE_COLUMNS
            or re.fullmatch(r"-{60,}", lines[1].strip()) is None):
        raise ReviewRequired("PDF page raster inventory malformed")
    seen: set[int] = set()
    for line in lines[2:]:
        fields = line.split()
        if len(fields) != len(_PDFIMAGE_COLUMNS):
            raise ReviewRequired("PDF page raster inventory row malformed")
        # Metadata is data, not a command or a path. Never interpret an
        # unfamiliar row as evidence of a page without raster content.
        if (any(not field.isascii() for field in fields)
                or any(not fields[i].isdigit()
                       for i in (0, 1, 3, 4, 6, 7, 10, 11, 12, 13))
                or not re.fullmatch(r"[a-zA-Z0-9._+-]{1,16}", fields[2])
                or fields[9] not in ("yes", "no")
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[BKMG]?", fields[14])
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?%", fields[15])):
            raise ReviewRequired("PDF page raster inventory row unsupported")
        image_page, image_index = int(fields[0]), int(fields[1])
        if (image_page != page or image_index in seen
                or int(fields[3]) < 1 or int(fields[4]) < 1):
            raise ReviewRequired("Unexpected PDF page image identity")
        seen.add(image_index)
    return bool(seen)


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_END = b"\x00\x00\x00\x00IEND\xaeB\x60\x82"


def require_ocr_png_envelope(
    image: Path, upper: tuple[int, int],
) -> tuple[int, int]:
    """Verify bounded PNG dimensions before opening the raster in Tesseract.

    An untrusted renderer may produce a very compressed but extremely wide
    image. The filesystem byte limit alone does not bound decoder allocation.
    Inspect PNG signature, IHDR, CRC, IEND and pixel budget using a file
    descriptor opened without symlink traversal, reading only 45 bytes.
    This is not a PNG sanitizer or a full IDAT decoder.
    """
    if (not isinstance(image, Path) or type(upper) is not tuple
            or len(upper) != 2 or any(type(n) is not int for n in upper)
            or any(n < 1 or n > OCR_MAX_SIDE_PX for n in upper)
            or upper[0] * upper[1] > OCR_MAX_PIXELS):
        raise ReviewRequired("Invalid OCR raster geometry budget")
    try:
        fd = os.open(
            image,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        )
    except OSError as error:
        raise ReviewRequired("OCR raster unavailable or unsafe") from error
    try:
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
                or not 57 <= meta.st_size <= OCR_MAX_RASTER_BYTES):
            raise ReviewRequired("OCR raster unavailable or oversized")
        header = os.pread(fd, 33, 0)
        trailer = os.pread(fd, 12, meta.st_size - 12)
        if (len(header) != 33 or header[:8] != _PNG_SIGNATURE
                or header[8:16] != b"\x00\x00\x00\x0dIHDR"
                or header[24] != 8 or header[25] not in (2, 6)
                or header[26:29] != b"\x00\x00\x00"
                or trailer != _PNG_END):
            raise ReviewRequired("Unsupported OCR raster PNG envelope")
        expected_crc = struct.unpack(">I", header[29:33])[0]
        if expected_crc != (zlib.crc32(header[12:29]) & 0xffffffff):
            raise ReviewRequired("OCR raster PNG header checksum mismatch")
        width, height = struct.unpack(">II", header[16:24])
        if (not 1 <= width <= upper[0] or not 1 <= height <= upper[1]
                or width * height > OCR_MAX_PIXELS):
            raise ReviewRequired("OCR raster dimensions exceed preflight budget")
        return width, height
    except OSError as error:
        raise ReviewRequired("OCR raster unreadable") from error
    finally:
        os.close(fd)


def inspect_pdf(
    pdf: bytes, version_id: str, expected_sha256: str, *,
    signatures: Path, run: Callable[[list[str], Path], str] = command
) -> dict:
    if not ID.fullmatch(version_id) or not HASH.fullmatch(expected_sha256):
        raise ReviewRequired("Malformed version identity")
    if len(pdf) < 12 or len(pdf) > MAX_PDF_BYTES or not pdf.startswith(b"%PDF-"):
        raise ReviewRequired("Unsupported PDF envelope")
    if hashlib.sha256(pdf).hexdigest() != expected_sha256:
        raise ReviewRequired("Original content checksum mismatch")
    require_fresh_signatures(signatures)
    try:
        verify_clamav_version(run(["clamscan", "--version"], Path(tempfile.gettempdir())))
    except ReviewRequired as error:
        raise ScannerUnavailable("Cannot verify ClamAV security patch version") from error
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="folio-inspector-") as name:
        directory = Path(name)
        source = directory / "original.pdf"
        source.write_bytes(pdf)
        try:
            # ClamAV return code 1 is NOT CLEAN and must never be admitted.
            # A nonzero exit or unavailable database fails closed.
            run(["clamscan", "--no-summary", "--database", str(signatures), str(source)], directory)
            # Rejection by qpdf precedes Poppler's pdfdetach/pdfinfo/parser
            # paths, including Decrypt::revision6Hash for encrypted AESV3/R6.
            if run(["qpdf", "--is-encrypted", str(source)], directory) != QPDF_UNENCRYPTED:
                raise ScannerUnavailable("PDF encryption status could not be verified")
            run(["qpdf", "--check", str(source)], directory)
            attachments = run(["pdfdetach", "-list", str(source)], directory)
            if not re.search(r"^0 embedded files?\s*$", attachments, re.MULTILINE | re.IGNORECASE):
                raise ReviewRequired("Embedded files are not allowed")
            info = run(["pdfinfo", str(source)], directory)
            pages_line = re.search(r"^Pages:\s*(\d+)\s*$", info, re.MULTILINE)
            if not pages_line or re.search(r"^Encrypted:\s*yes", info, re.MULTILINE | re.IGNORECASE):
                raise ReviewRequired("Encrypted PDF or missing page inventory")
            count = int(pages_line.group(1))
            if count < 1 or count > MAX_PAGES:
                raise ReviewRequired("Unsupported number of pages")
            pages: list[dict] = []
            qpdf_page_objects: tuple[tuple[int, int], ...] | None = None
            for page in range(1, count + 1):
                if time.monotonic() - started > MAX_TOTAL_SECONDS:
                    raise ScannerUnavailable("PDF processing exceeded total time budget")
                raw = run([
                    "pdftotext", "-f", str(page), "-l", str(page),
                    "-layout", "-nopgbrk", "-enc", "UTF-8", str(source), "-"
                ], directory)
                text = raw.strip()
                if text and (len(text) > MAX_PAGE_TEXT or CONTROL.search(text)):
                    raise ReviewRequired("Unsafe or oversized digital page text")
                if text:
                    # Presence of a raster XObject on a text-bearing page
                    # makes text-only extraction evidentially incomplete.
                    # Review rather than minting a signed 'clean' manifest.
                    image_report = run([
                        "pdfimages", "-f", str(page), "-l", str(page),
                        "-list", str(source),
                    ], directory)
                    if has_pdf_page_raster(image_report, page=page, count=count):
                        raise ReviewRequired(
                            "Mixed digital text and raster evidence requires review"
                        )
                if not text:
                    # QPDF resolves page dictionaries including object streams.
                    # pdfinfo -box does NOT expose UserUnit. Obtain page IDs
                    # once, then read only this exact page's dictionary JSON.
                    if qpdf_page_objects is None:
                        qpdf_page_objects = parse_qpdf_page_inventory(
                            run(["qpdf", "--json", "--json-key=pages",
                                 str(source)], directory),
                            count=count,
                        )
                    object_number, generation = qpdf_page_objects[page - 1]
                    user_unit = parse_qpdf_user_unit(
                        run([
                            "qpdf", "--json", "--json-key=qpdf",
                            f"--json-object={object_number},{generation}",
                            str(source),
                        ], directory),
                        object_number=object_number, generation=generation,
                    )
                    # Check the effective MediaBox of *this* OCR page before
                    # Poppler allocates the 180 DPI raster. Page size/CropBox
                    # would understate the area for pdftoppm without -cropbox.
                    box_info = run([
                        "pdfinfo", "-f", str(page), "-l", str(page),
                        "-box", str(source),
                    ], directory)
                    raster_budget = require_ocr_raster_geometry(
                        box_info, page=page, count=count, user_unit=user_unit,
                    )
                    # Rasterize ONLY in the isolated sandbox; never serve these
                    # derived images until a separate sanitization gate exists.
                    output_prefix = directory / "ocr-page"
                    run(["pdftoppm", "-f", str(page), "-l", str(page),
                         "-singlefile", "-r", str(OCR_DPI), "-png",
                         str(source), str(output_prefix)], directory)
                    image = directory / "ocr-page.png"
                    require_ocr_png_envelope(image, raster_budget)
                    text = run(["tesseract", str(image), "stdout",
                                "-l", "spa+eng"], directory).strip()
                    image.unlink(missing_ok=True)
                if time.monotonic() - started > MAX_TOTAL_SECONDS:
                    raise ScannerUnavailable("PDF processing exceeded total time budget")
                if not text or len(text) > MAX_PAGE_TEXT or CONTROL.search(text):
                    raise ReviewRequired("Empty, unsafe or oversized page text")
                pages.append({"page": page, "text": text})
        finally:
            # TemporaryDirectory removes the source and all raster files.
            pass

    return {
        "documentVersionId": version_id,
        "sourceSha256": expected_sha256,
        "scanVerdict": "clean",
        "scanner": "folio-isolated-clamav-poppler-v1",
        "scannerReportId": "scan_" + os.urandom(16).hex(),
        "scannedAt": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "pages": pages
    }


def signed_result(manifest: dict, key: bytes) -> bytes:
    if len(key) < 32:
        raise ScannerUnavailable("Signing key is missing or too short")
    # Stable order matches serializeInspectionManifest() in TypeScript.
    serial = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(key, serial, hashlib.sha256).hexdigest()
    return json.dumps(
        {"manifest": manifest, "signature": signature},
        ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def secret_file(path_variable: str) -> bytes:
    # Local Docker deployments use mounted secret files. Cloudflare Containers
    # receives Worker secrets via ctx.container.start({env:...}).
    filename = os.environ.get(path_variable, "")
    if filename:
        if not Path(filename).is_file():
            raise ScannerUnavailable("Required private secret mount is missing")
        result = Path(filename).read_bytes().strip()
    else:
        fallback = {
            "FOLIO_INSPECTOR_TOKEN_FILE": "FOLIO_INSPECTOR_SERVICE_TOKEN",
            "FOLIO_INSPECTOR_HMAC_FILE": "FOLIO_INSPECTOR_HMAC_KEY"
        }.get(path_variable)
        result = os.environ.get(fallback, "").encode() if fallback else b""
    if len(result) < 32:
        raise ScannerUnavailable("Private secret is missing or too short")
    return result


def inspection_output_mode() -> str:
    mode = os.environ.get("FOLIO_INSPECTOR_OUTPUT_MODE", "signed")
    if mode not in ("signed", "unsigned"):
        raise ScannerUnavailable("Unsupported inspection output mode")
    return mode


def inspection_ready() -> None:
    secret_file("FOLIO_INSPECTOR_TOKEN_FILE")
    if inspection_output_mode() == "signed":
        secret_file("FOLIO_INSPECTOR_HMAC_FILE")
    require_fresh_signatures(Path(os.environ.get("CLAMAV_DB_DIR", "/opt/clamdb")))
    engines = ("clamscan", "qpdf", "pdfinfo", "pdfdetach",
               "pdftotext", "pdfimages", "pdftoppm", "tesseract")
    if any(shutil.which(engine) is None for engine in engines):
        raise ScannerUnavailable("One or more mandatory scanner engines are unavailable")
    verify_clamav_version(command(["clamscan", "--version"], Path(tempfile.gettempdir())))


class InspectorHandler(BaseHTTPRequestHandler):
    server_version = "FolioInspector"
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        # Never log request headers, PDF filenames, raw text or document IDs.
        pass

    def do_GET(self) -> None:
        if self.path != "/health":
            self.reply(404)
            return
        try:
            inspection_ready()
            self.reply(200)
        except (ScannerUnavailable, OSError):
            self.reply(503)

    def do_POST(self) -> None:
        if self.path != "/inspect":
            self.reply(404)
            return
        try:
            token = secret_file("FOLIO_INSPECTOR_TOKEN_FILE")
            mode = inspection_output_mode()
            signed_key = (secret_file("FOLIO_INSPECTOR_HMAC_FILE")
                          if mode == "signed" else None)
            candidate = self.headers.get("X-Folio-Inspector-Token", "").encode()
            if not hmac.compare_digest(token, candidate):
                self.reply(403)
                return
            length_string = self.headers.get("Content-Length", "")
            if (not length_string.isdigit()
                    or int(length_string) < 12
                    or int(length_string) > MAX_PDF_BYTES
                    or self.headers.get("Content-Type") != "application/pdf"):
                self.reply(413)
                return
            contents = self.rfile.read(int(length_string))
            if len(contents) != int(length_string):
                self.reply(400)
                return
            manifest = inspect_pdf(
                contents,
                self.headers.get("X-Folio-Document-Version", ""),
                self.headers.get("X-Folio-Source-Sha256", ""),
                signatures=Path(os.environ.get("CLAMAV_DB_DIR", "/opt/clamdb"))
            )
            # In Cloudflare Containers the gateway Worker, not this lower-trust
            # parser process, owns the signing key. The unsigned result never
            # reaches the application without verification and gateway signing.
            result = (signed_result(manifest, signed_key)
                      if signed_key is not None else
                      json.dumps({"manifest": manifest}, ensure_ascii=False,
                                 separators=(",", ":")).encode("utf-8"))
            if len(result) > 2 * 1024 * 1024:
                self.reply(422)
                return
            self.reply(200, result)
        except ReviewRequired:
            self.reply(422)
        except (ScannerUnavailable, OSError):
            self.reply(503)
        except Exception:
            # Fail closed on any unexpected parser/engine error.
            self.reply(503)

    def reply(self, status: int, data: bytes = b"") -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if data:
            self.wfile.write(data)


if __name__ == "__main__":
    # Defaults to loopback; a container gateway may bind an internal interface
    # only after network policies, mTLS/service binding and Access are verified.
    host = os.environ.get("FOLIO_INSPECTOR_BIND", "127.0.0.1")
    if host not in ("127.0.0.1", "0.0.0.0"):
        raise SystemExit("Unsafe inspector bind address")
    inspection_ready()
    HTTPServer((host, 8789), InspectorHandler).serve_forever()
