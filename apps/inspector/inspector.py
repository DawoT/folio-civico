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
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]")
ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HASH = re.compile(r"^[a-f0-9]{64}$")


class ReviewRequired(Exception):
    """Suspicious, malformed, encrypted or unsupported input: no clean verdict."""


class ScannerUnavailable(Exception):
    """A mandatory verification engine or signature database is unavailable."""


def require_fresh_signatures(directory: Path, now: float | None = None) -> None:
    if not directory.is_dir():
        raise ScannerUnavailable("ClamAV signatures not mounted")
    databases = [
        file for file in directory.iterdir()
        if file.is_file() and file.suffix in (".cvd", ".cld")
    ]
    current = time.time() if now is None else now
    if not databases or any(
        current - file.stat().st_mtime > MAX_SIGNATURE_AGE
        or file.stat().st_mtime > current + 300
        for file in databases
    ):
        raise ScannerUnavailable("ClamAV signatures are missing or stale")


MAX_ENGINE_OUTPUT_BYTES = 2 * 1024 * 1024


def command(argv: list[str], cwd: Path, seconds: int = MAX_PROCESS_SECONDS) -> str:
    # Never invoke a shell or interpolate a document-controlled command.
    # Redirect untrusted parser output to the bounded private tmpfs rather
    # than accumulating arbitrary decompressed output in Worker memory.
    with tempfile.TemporaryFile(mode="w+b", dir=cwd) as output:
        try:
            result = subprocess.run(
                argv, cwd=cwd, check=False, stdout=output,
                stderr=subprocess.DEVNULL, timeout=seconds
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as error:
            raise ScannerUnavailable("Required inspector engine unavailable") from error
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
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="folio-inspector-") as name:
        directory = Path(name)
        source = directory / "original.pdf"
        source.write_bytes(pdf)
        try:
            # ClamAV return code 1 is NOT CLEAN and must never be admitted.
            # A nonzero exit or unavailable database fails closed.
            run(["clamscan", "--no-summary", "--database", str(signatures), str(source)], directory)
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
                    # Rasterize ONLY in the isolated sandbox; never serve these
                    # derived images until a separate sanitization gate exists.
                    output_prefix = directory / "ocr-page"
                    run(["pdftoppm", "-f", str(page), "-l", str(page),
                         "-singlefile", "-r", "180", "-png",
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
