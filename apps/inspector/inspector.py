#!/usr/bin/env python3
"""Folio Cívico isolated PDF inspector.

Execute ONLY inside a container/process sandbox with no outbound networking,
non-root user, seccomp, resource limits, fresh offline ClamAV signatures and
read-only filesystem except a bounded private tmpfs. This service is not bound
to Cloudflare until operator approval.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable

MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_PAGES = 100
MAX_PAGE_TEXT = 8000
MAX_SIGNATURE_AGE = 72 * 60 * 60
MAX_PROCESS_SECONDS = 30
MAX_TOTAL_SECONDS = 8 * 60
# Preliminary per-page MediaBox raster budget at the existing OCR resolution.
# Metadata is rounded; this is defense-in-depth, not proof of Poppler safety
# against UserUnit or other unverified page-state semantics (issue #68).
OCR_DPI = 180
MAX_OCR_SIDE_PIXELS = 8192
MAX_OCR_AREA_PIXELS = 16_000_000
MAX_OCR_METADATA_BYTES = 65_536
OCR_NUMBER = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[Ee][+-]?\d{1,2})?"
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


def verify_ocr_raster_geometry(raw: str, page: int) -> None:
    """Reject oversized default MediaBox raster before pdftoppm touches a page.

    The actual pdftoppm invocation does NOT use -cropbox: Page size from
    pdfinfo may therefore understate the rasterized MediaBox. This check is
    intentionally conservative and cannot certify UserUnit or parser CVEs.
    """
    if (not isinstance(raw, str) or not 1 <= page <= MAX_PAGES
            or not raw.isascii() or "\r" in raw or "\x00" in raw
            or len(raw) > MAX_OCR_METADATA_BYTES):
        raise ReviewRequired("Untrusted OCR page geometry")
    count = re.findall(r"^Pages:[ \t]+(\d+)[ \t]*$", raw, re.MULTILINE)
    encrypted = re.findall(
        r"^Encrypted:[ \t]+(yes|no)[ \t]*$", raw, re.MULTILINE
    )
    if (len(count) != 1 or not 1 <= int(count[0]) <= MAX_PAGES
            or page > int(count[0]) or encrypted != ["no"]):
        raise ReviewRequired("Incomplete OCR page inventory")
    patterns = {
        "size": rf"^Page[ \t]+(\d+)[ \t]+size:[ \t]+({OCR_NUMBER})[ \t]+x[ \t]+({OCR_NUMBER})[ \t]+pts(?:[ \t]+\([^()\r\n]{{1,80}}\))?[ \t]*$",
        "rot": r"^Page[ \t]+(\d+)[ \t]+rot:[ \t]+(\d+)[ \t]*$",
        "MediaBox": rf"^Page[ \t]+(\d+)[ \t]+MediaBox:[ \t]+({OCR_NUMBER})[ \t]+({OCR_NUMBER})[ \t]+({OCR_NUMBER})[ \t]+({OCR_NUMBER})[ \t]*$",
    }
    records = {}
    for marker, pattern in patterns.items():
        # Require exactly one declaration, including malformed duplicates
        # that a regex matching only numeric records would otherwise skip.
        headers = re.findall(
            rf"^Page[ \t]+\d+[ \t]+{marker}:", raw, re.MULTILINE
        )
        matches = list(re.finditer(pattern, raw, re.MULTILINE))
        if (len(headers) != 1 or len(matches) != 1
                or int(matches[0].group(1)) != page):
            raise ReviewRequired("Incomplete or ambiguous OCR page geometry")
        records[marker] = matches[0].groups()[1:]
    try:
        coords = [Decimal(token) for token in records["MediaBox"]]
        size = [Decimal(token) for token in records["size"]]
        if (any(len(token) > 32 for token in (*records["MediaBox"], *records["size"]))
                or any(not x.is_finite() or abs(x) > 1_000_000 for x in coords)
                or any(not x.is_finite() or x <= 0 for x in size)):
            raise ReviewRequired("Invalid OCR page geometry")
        width, height = coords[2] - coords[0], coords[3] - coords[1]
        if width <= 0 or height <= 0:
            raise ReviewRequired("Invalid OCR MediaBox dimensions")
        rotation = int(records["rot"][0])
        if rotation not in (0, 90, 180, 270):
            raise ReviewRequired("Unsupported OCR page rotation")
        if rotation in (90, 270):
            width, height = height, width
        # pdfinfo rounds MediaBox to hundredths of a point. Add conservative
        # tolerance before converting to pixel dimensions at 180 DPI.
        px_width = int(((width + Decimal("0.02")) * OCR_DPI / 72)
                       .to_integral_value(rounding=ROUND_CEILING))
        px_height = int(((height + Decimal("0.02")) * OCR_DPI / 72)
                        .to_integral_value(rounding=ROUND_CEILING))
        if (px_width > MAX_OCR_SIDE_PIXELS or px_height > MAX_OCR_SIDE_PIXELS
                or px_width * px_height > MAX_OCR_AREA_PIXELS):
            raise ReviewRequired("OCR page raster exceeds geometry budget")
    except (InvalidOperation, ValueError, OverflowError) as error:
        raise ReviewRequired("Invalid OCR page geometry") from error


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
            for page in range(1, count + 1):
                if time.monotonic() - started > MAX_TOTAL_SECONDS:
                    raise ScannerUnavailable("PDF processing exceeded total time budget")
                raw = run([
                    "pdftotext", "-f", str(page), "-l", str(page),
                    "-layout", "-nopgbrk", "-enc", "UTF-8", str(source), "-"
                ], directory)
                text = raw.strip()
                if not text:
                    # Default pdftoppm rasterizes MediaBox, NOT the visible
                    # CropBox reported as Page size by pdfinfo. Check the
                    # actual page MediaBox BEFORE any raster allocation.
                    geometry = run(["pdfinfo", "-f", str(page), "-l", str(page),
                                    "-box", str(source)], directory)
                    verify_ocr_raster_geometry(geometry, page)
                    # Rasterize ONLY in the isolated sandbox; never serve these
                    # derived images until a separate sanitization gate exists.
                    output_prefix = directory / "ocr-page"
                    run(["pdftoppm", "-f", str(page), "-l", str(page),
                         "-singlefile", "-r", str(OCR_DPI), "-png",
                         str(source), str(output_prefix)], directory)
                    image = directory / "ocr-page.png"
                    if not image.is_file() or image.stat().st_size > 32 * 1024 * 1024:
                        raise ReviewRequired("OCR raster unavailable or oversized")
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
               "pdftotext", "pdftoppm", "tesseract")
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
