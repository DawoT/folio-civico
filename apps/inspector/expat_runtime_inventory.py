"""Read-only Expat ELF attestation *inside* a pinned, offline Docker image.

Never opens user documents. Measures installed package, actual ELF, provenance,
five Poppler dynamic links, and absence of xmlwf. Does not assess CVEs.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

VERSION = "2.10.0-1+folio1"
SOURCE_SHA = "b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f"
PATCH_SHA = "0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3"
TOOLS = ("pdfinfo", "pdftotext", "pdftoppm", "pdfdetach", "pdfattach")
LINK = re.compile(
    r"^\s*libexpat\.so\.1 => (/(?:usr/)?lib/x86_64-linux-gnu/libexpat\.so\.1) "
    r"\(0x[0-9a-f]+\)$", re.MULTILINE
)


def _checked(argv: list[str], timeout: int = 12) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Offline native evidence probe failed") from error
    if result.returncode != 0:
        raise ValueError("Native evidence probe returned a nonzero status")
    return result


def gather(root: Path = Path("/")) -> dict:
    provenance = root / "opt/folio-expat-package/source-provenance.json"
    try:
        raw = provenance.read_bytes()
        if len(raw) > 8192:
            raise ValueError("Oversized source provenance")
        metadata = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError("Expat source provenance unavailable") from error
    if metadata != {
        "name": "expat", "upstream_version": "2.10.0",
        "local_package_version": VERSION, "source_sha256": SOURCE_SHA,
        "patch_sha256": PATCH_SHA, "release_authorized": False,
    }:
        raise ValueError("Expat build provenance differs from approved experiment")

    actual_version = _checked(
        ["dpkg-query", "-W", "-f=${Version}", "libexpat1"], timeout=8
    ).stdout
    if actual_version != VERSION:
        raise ValueError("Installed Expat package version differs")

    allowed = (
        root / "usr/lib/x86_64-linux-gnu",
        root / "lib/x86_64-linux-gnu",
    )
    candidates = [directory / "libexpat.so.1" for directory in allowed]
    library = next((path for path in candidates if path.is_file()), None)
    if library is None:
        raise ValueError("Expat runtime shared library missing")
    # Symlinks are legitimate for Debian SONAME, but must remain inside one
    # trusted system directory. External symlinks and writable ELF are rejected.
    resolved = library.resolve()
    if not any(resolved.is_relative_to(directory.resolve()) for directory in allowed):
        raise ValueError("Expat shared library points outside trusted system paths")
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise ValueError("Expat shared library is mutable or nonregular")
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        if handle.read(4) != b"\x7fELF":
            raise ValueError("Expat shared library is not ELF")
        handle.seek(0)
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    try:
        handle = ctypes.CDLL(str(library))
        handle.XML_ExpatVersion.restype = ctypes.c_char_p
        actual_engine_version = handle.XML_ExpatVersion()
    except (OSError, AttributeError, TypeError) as error:
        raise ValueError("Expat library version probe failed") from error
    if actual_engine_version != b"expat_2.10.0":
        raise ValueError("Expat engine version mismatches Debian package")

    for name in TOOLS:
        binary = root / "opt/folio-poppler/bin" / name
        output = _checked(["ldd", str(binary)]).stdout
        links = LINK.findall(output)
        if len(links) != 1 or "not found" in output:
            raise ValueError("PDF utility does not link the measured Expat library")
        # ldd is run within the real image, so the runtime paths must resolve
        # to the exact system library whose ELF hash was measured above.
        if not (root / links[0].lstrip("/")).resolve() == resolved:
            raise ValueError("PDF parser resolved a different Expat binary")

    # xmlwf was not shipped: a shell PATH check complements the file checks.
    if any((root / path).exists() for path in (
        "usr/bin/xmlwf", "bin/xmlwf", "usr/local/bin/xmlwf",
    )):
        raise ValueError("Untrusted XML parser CLI is present")
    try:
        xmlwf = subprocess.run(
            ["/bin/sh", "-c", "command -v xmlwf"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("xmlwf absence could not be checked") from error
    if xmlwf.returncode not in (1, 127) or xmlwf.stdout.strip() or xmlwf.stderr.strip():
        raise ValueError("xmlwf CLI is present or probe ambiguous")

    return {
        "source": "folio-expat-local-provenance-v1",
        "package": "libexpat1", "package_version": VERSION,
        "library_sha256": digest.hexdigest(),
        "provenance_sha256": hashlib.sha256(raw).hexdigest(),
        "source_sha256": SOURCE_SHA, "patch_sha256": PATCH_SHA,
        "runtime_version": "expat_2.10.0",
        "linked_poppler_tools": list(TOOLS),
        "xmlwf_present": False, "native_cve_coverage": "unassessed",
    }


def main() -> int:
    try:
        result = gather()
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "error", "reason": "expat_runtime_inventory_incomplete"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
