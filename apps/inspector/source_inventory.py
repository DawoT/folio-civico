"""Offline runtime provenance inventory for locally compiled OCR/PDF engines.

Executed inside the IMMUTABLE local image ID, without network or host mounts.
The output provides measured ELF hashes and checks declared source versions.
It DOES NOT assess advisories; the security gate must remain blocked until
there is an explicit, independently approved source-code vulnerability review.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

SOURCE = "folio-local-elf-provenance-v1"
POPPLER_TOOLS = ("pdfinfo", "pdftotext", "pdftoppm", "pdfdetach", "pdfattach")
TESSERACT_SOURCE_SHA256 = "a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4"
TESSERACT_METADATA = {
    "name": "tesseract", "version": "5.5.4",
    "source_sha256": TESSERACT_SOURCE_SHA256, "archive": False, "curl": False,
}
POPPLER_METADATA = {
    "name": "poppler", "debian_source_version": "25.03.0-5+deb13u4",
    "curl": False, "gpgme": False, "nss3": False,
}
MODES = ("validation", "candidate", "experiment")


def sha256_elf(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file() or not path.resolve().is_relative_to((root / "opt").resolve()):
        raise ValueError("Native component missing or outside isolated build prefix")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError("Provenance target is not an ELF binary")
        stream.seek(0)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_dynamic_links(binary: Path, forbidden: tuple[str, ...]) -> None:
    try:
        result = subprocess.run(
            ["ldd", str(binary)], capture_output=True, text=True,
            timeout=12, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Native linkage could not be enumerated") from error
    output = result.stdout + result.stderr
    if (result.returncode != 0 or not output.strip() or "not found" in output
            or any(name in output for name in forbidden)):
        raise ValueError("Unexpected or unresolved native library linkage")


def inspect_component(root: Path, name: str) -> dict:
    if name == "tesseract":
        base = "opt/folio-ocr"
        declared = TESSERACT_METADATA
        exe = "bin/tesseract"
        lib = "lib/libtesseract.so.5.5.4"
        version_cmd = ["--version"]
        version_prefix = "tesseract 5.5.4"
        version = "5.5.4"
        forbidden = ("libarchive", "libcurl", "libxml2")
    elif name == "poppler":
        base = "opt/folio-poppler"
        declared = POPPLER_METADATA
        exe = "bin/pdfinfo"
        lib = "lib/libpoppler.so.147"
        version_cmd = ["-v"]
        version_prefix = "pdfinfo version 25.03.0"
        version = "25.03.0-5+deb13u4"
        forbidden = (
            "libcurl", "libgssapi", "libkrb5", "libk5crypto",
            "libgpgme", "libnss3",
        )
    else:
        raise ValueError("Unknown native source component")
    provenance = root / base / "source-provenance.json"
    try:
        metadata = json.loads(provenance.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError("Source provenance missing or malformed") from error
    if type(metadata) is not dict or metadata != declared:
        raise ValueError("Native source provenance version or flags differ")
    binary = root / base / exe
    try:
        version_output = subprocess.run(
            [str(binary), *version_cmd], capture_output=True,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Native executable version cannot be verified") from error
    if (version_output.returncode != 0 or not
            (version_output.stdout + version_output.stderr).startswith(version_prefix)):
        raise ValueError("Native executable version differs from provenance")
    verify_dynamic_links(binary, forbidden)
    verify_dynamic_links(root / base / lib, forbidden)
    # Fingerprint ALL Poppler executables actually exercised by the scanner
    # and synthetic fixture harness, not just the version-probe executable.
    tool_sha256 = {}
    if name == "poppler":
        for tool in POPPLER_TOOLS:
            relative = f"{base}/bin/{tool}"
            tool_sha256[tool] = sha256_elf(root, relative)
            verify_dynamic_links(root / relative, forbidden)
    return {
        "name": name, "version": version,
        "tool_sha256": tool_sha256,
        "executable_sha256": sha256_elf(root, f"{base}/{exe}"),
        "library_sha256": sha256_elf(root, f"{base}/{lib}"),
        "provenance_sha256": hashlib.sha256(
            provenance.read_bytes()
        ).hexdigest(),
        "cve_assessment": "required",
        "automated_cve_coverage": "not_verified",
    }


def inventory(mode: str, root: Path = Path("/")) -> dict:
    if mode not in MODES:
        raise ValueError("Unsupported native source image class")
    components: list[dict] = []
    for name, relative in (
        ("tesseract", "opt/folio-ocr"),
        ("poppler", "opt/folio-poppler"),
    ):
        prefix = root / relative
        present = any((prefix / item).exists() for item in (
            "source-provenance.json", "bin/tesseract", "bin/pdfinfo",
            "lib/libtesseract.so.5.5.4", "lib/libpoppler.so.147",
        ))
        if mode == "candidate" and name == "poppler" and present:
            raise ValueError("Unexpected custom Poppler in nonexperimental image")
        required = name == "tesseract" and mode != "validation"
        required = required or (name == "poppler" and mode == "experiment")
        if required or present:
            components.append(inspect_component(root, name))
        if required and not present:
            raise ValueError("Mandatory source-built engine missing")
    return {
        "source": SOURCE,
        "mode": mode,
        "components": components,
        "source_cve_coverage": (
            "unassessed" if components else "not_applicable"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    args = parser.parse_args()
    try:
        report = inventory(args.mode)
    except (ValueError, OSError, TypeError):
        print(json.dumps({"status": "error", "reason": "native_provenance_incomplete"}))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
