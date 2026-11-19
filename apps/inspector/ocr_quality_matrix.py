"""Deterministic, synthetic OCR regression matrix. No institutional PDFs.

Run ONLY in a sandboxed inspector image using python3 -c with this file's source.
No network, external fixtures, OCR mocks, or secrets. Results contain hashes and
error counts, not extracted text. Host comparison mode requires two JSON reports.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unicodedata

from fixtures import _pdf, _stream, scanned_pdf
from smoke_real_engines import parse_pgm, assert_no_pdf_text
from inspector import inspect_pdf

CORPUS = (
    ("spanish-procurement", "EXPEDIENTE OBRA 2026"),
    ("spanish-identifier", "RESOLUCION NUMERO 0042"),
    ("english-contract", "CONTRACT REVIEW 2026"),
    ("spanish-diacritics", "REVISIÓN PÚBLICA 2026"),
)
SOURCE = "folio-synthetic-ocr-matrix-v1"


def canonical(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).upper().split())


def edit_distance(expected: str, observed: str) -> int:
    previous = list(range(len(observed) + 1))
    for index, left in enumerate(expected, 1):
        current = [index]
        for col, right in enumerate(observed, 1):
            current.append(min(
                current[-1] + 1,
                previous[col] + 1,
                previous[col - 1] + (left != right),
            ))
        previous = current
    return previous[-1]


def synthetic_text_pdf(value: str) -> bytes:
    """Native Helvetica/WinAnsi page; Poppler rasterizes it to a genuine scan."""
    if not value or len(value) > 70 or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid synthetic text")
    text = value.encode("cp1252")
    escaped = text.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    stream = b"BT\n/F1 24 Tf\n60 690 Td\n(" + escaped + b") Tj\nET\n"
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        _stream(stream),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    ])


def synthetic_scan(value: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="folio-quality-") as folder:
        root = Path(folder)
        source, dest = root / "source.pdf", root / "scan"
        source.write_bytes(synthetic_text_pdf(value))
        result = subprocess.run([
            "pdftoppm", "-f", "1", "-l", "1", "-singlefile",
            "-gray", "-r", "180", str(source), str(dest)
        ], timeout=30, check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        image = root / "scan.pgm"
        if result.returncode != 0 or not image.is_file():
            raise RuntimeError("Synthetic raster generation failed")
        scanned = scanned_pdf(raster=parse_pgm(image.read_bytes()))
        assert_no_pdf_text(scanned)
        return scanned


def matrix_report() -> dict:
    results = []
    for case_id, expected in CORPUS:
        pdf = synthetic_scan(expected)
        manifest = inspect_pdf(
            pdf, case_id.replace("-", "_"), hashlib.sha256(pdf).hexdigest(),
            signatures=Path("/opt/clamdb")
        )
        if len(manifest["pages"]) != 1:
            raise AssertionError("Unexpected synthetic OCR page count")
        actual = canonical(manifest["pages"][0]["text"])
        target = canonical(expected)
        results.append({
            "case": case_id,
            "fixture_sha256": hashlib.sha256(pdf).hexdigest(),
            "text_sha256": hashlib.sha256(actual.encode("utf-8")).hexdigest(),
            "expected_sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
            "errors": edit_distance(target, actual),
            "reference_characters": len(target),
        })
    return {"source": SOURCE, "cases": results}


def compare_reports(reference: dict, candidate: dict) -> dict:
    if (not isinstance(reference, dict) or not isinstance(candidate, dict)
            or reference.get("source") != SOURCE or candidate.get("source") != SOURCE):
        raise ValueError("Unrecognized OCR matrix report")
    a, b = reference.get("cases"), candidate.get("cases")
    if not isinstance(a, list) or not isinstance(b, list) or len(a) != len(CORPUS) or len(b) != len(CORPUS):
        raise ValueError("Incomplete OCR quality matrix")
    mismatches = []
    equal = 0
    total_a = total_b = 0
    for index, ((name, _), left, right) in enumerate(zip(CORPUS, a, b)):
        if not all(isinstance(x, dict) for x in (left, right)):
            raise ValueError("Malformed case")
        if (left.get("case") != name or right.get("case") != name
                or left.get("fixture_sha256") != right.get("fixture_sha256")
                or left.get("expected_sha256") != right.get("expected_sha256")
                or not isinstance(left.get("errors"), int) or not isinstance(right.get("errors"), int)
                or left["errors"] < 0 or right["errors"] < 0
                or not isinstance(left.get("reference_characters"), int)
                or left["reference_characters"] < 1
                or left["reference_characters"] != right.get("reference_characters")
                or not all(isinstance(row.get(field), str) and len(row[field]) == 64
                           for row in (left, right)
                           for field in ("fixture_sha256", "text_sha256", "expected_sha256"))):
            raise ValueError(f"Invalid OCR comparison row {index}")
        total_a += left["errors"]
        total_b += right["errors"]
        if left["text_sha256"] == right["text_sha256"]:
            equal += 1
        if right["errors"] > left["errors"]:
            mismatches.append(name)
    return {
        "status": "no_regression" if not mismatches else "regression",
        "cases": len(CORPUS),
        "equal_text_hashes": equal,
        "reference_char_errors": total_a,
        "candidate_char_errors": total_b,
        "regressed_cases": mismatches,
        "synthetic_only": True,
    }


def main() -> int:
    try:
        if len(sys.argv) == 1:
            print(json.dumps(matrix_report(), sort_keys=True))
            return 0
        if len(sys.argv) == 4 and sys.argv[1] == "--compare":
            reference = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
            candidate = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
            result = compare_reports(reference, candidate)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["status"] == "no_regression" else 2
    except (OSError, ValueError, KeyError, RuntimeError, AssertionError,
            subprocess.TimeoutExpired):
        print(json.dumps({"status": "error", "reason": "ocr_quality_matrix_failed"}))
        return 3
    print(json.dumps({"status": "error", "reason": "invalid_quality_matrix_invocation"}))
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
