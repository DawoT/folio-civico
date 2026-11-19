"""Real-engine synthetic PDF acceptance and AV smoke checks.

The manual command REQUIRES actual ClamAV, qpdf, Poppler and Tesseract plus
current official AV definitions. NEVER reports a simulated success. It creates
no persistent documents, logs no document contents and uses no cloud resources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from fixtures import native_pdf, scanned_pdf, malformed_pdf
from inspector import inspect_pdf, ReviewRequired
from preflight import inspect_host


def scanner_test_sample() -> bytes:
    """Generate the harmless EICAR standard antivirus test string in memory."""
    # Construct at runtime to avoid putting an antivirus-triggering file into
    # the repository. See https://www.eicar.org/download-anti-malware-testfile/
    return (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ).encode("ascii")


def exercise_real_engines(database: Path) -> dict[str, str]:
    expected = {"native": "passed", "ocr": "passed",
                "malformed": "rejected", "antivirus_test": "detected"}

    native = native_pdf()
    manifest = inspect_pdf(native, "synthetic_native", hashlib.sha256(native).hexdigest(),
                           signatures=database)
    if len(manifest["pages"]) != 1:
        raise AssertionError("Native PDF page count differs")
    native_text = manifest["pages"][0]["text"].upper()
    if "EXPEDIENTE" not in native_text or "OBRA" not in native_text or "2026" not in native_text:
        raise AssertionError("Native PDF extraction did not preserve text")

    scanned = scanned_pdf()
    manifest = inspect_pdf(scanned, "synthetic_ocr", hashlib.sha256(scanned).hexdigest(),
                           signatures=database)
    if len(manifest["pages"]) != 1:
        raise AssertionError("OCR PDF page count differs")
    ocr_text = manifest["pages"][0]["text"].upper()
    if "OBRA" not in ocr_text or "2026" not in ocr_text:
        raise AssertionError("Tesseract OCR did not recover expected synthetic text")

    malformed = malformed_pdf()
    try:
        inspect_pdf(malformed, "synthetic_bad", hashlib.sha256(malformed).hexdigest(),
                    signatures=database)
    except ReviewRequired:
        pass
    else:
        raise AssertionError("Malformed PDF unexpectedly passed inspection")

    with tempfile.TemporaryDirectory(prefix="folio-av-test-") as temporary:
        sample = Path(temporary) / "eicar-test-only.txt"
        payload = scanner_test_sample()
        if len(payload) != 68:
            raise AssertionError("Unexpected antivirus smoke signature size")
        sample.write_bytes(payload)
        # EICAR is harmless, not malware. Its detection verifies that official
        # signatures are actually loaded by clamscan, not merely present by name.
        scan = subprocess.run([
            "clamscan", "--no-summary", "--database", str(database), str(sample)
        ], capture_output=True, timeout=30, check=False)
        if scan.returncode != 1:
            raise AssertionError("ClamAV did not identify its harmless EICAR test pattern")

    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("/opt/clamdb"))
    args = parser.parse_args()
    preflight = inspect_host("smoke",Path(__file__).resolve().parents[2],args.database)
    if not preflight["ready"]:
        print(json.dumps({"ready": False, "problems": preflight["problems"]},
                         sort_keys=True))
        return 2
    try:
        result = exercise_real_engines(args.database)
    except Exception:
        # Do not log exception messages or PDFs: some tools include file paths,
        # scanner internals, or original document content in their diagnostics.
        print(json.dumps({"ready":False,"reason":"real_engine_validation_failed"}))
        return 1
    print(json.dumps({"ready": True, "checks": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
