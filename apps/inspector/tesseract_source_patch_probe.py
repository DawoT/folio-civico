"""Offline Tesseract 5.5.4 source-archive patch marker verification.

A SHA-256-pinned original source tarball and selected C++ patch markers are
checked together. This is evidence that source fixes are PRESENT in the
downloaded release; not binary reproducibility, not CVE clearance and never
a release authorization. The caller supplies the tarball; no network calls.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

from source_inventory import TESSERACT_SOURCE_SHA256

MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024
PATCH_MARKERS: dict[str, tuple[str, ...]] = {
    "src/api/pagerenderer.cpp": (
        "static void AppendLinePolygon(Pta *pts_ltr, Pta **pts_rtl, Pta *ptss,",
        "ptaDestroy(pts_rtl);",
        "AppendLinePolygon(line_top_ltr_pts, &line_top_rtl_pts,",
    ),
    "src/lstm/weightmatrix.cpp": (
        "bool WeightMatrix::DeSerializeOld",
        'tprintf("Error: old format weight matrix not supported, ',
        "return false;\n#else",
    ),
    "src/ccstruct/matrix.h": (
        "bool DeSerializeSize(TFile *fp) {",
        "uint32_t size1, size2;",
        "if (required > fp->RemainingBytes()) {",
    ),
    "src/classify/adaptive.cpp": (
        "ADAPT_CLASS_STRUCT *ReadAdaptedClass(TFile *fp)",
        "Class->TempProtos = NIL_LIST;",
        "Class->Config[i].Temp = nullptr;",
    ),
}
SOURCE_CVE_BY_PATH = {
    "src/api/pagerenderer.cpp": "CVE-2026-119338",
    "src/lstm/weightmatrix.cpp": "CVE-2026-119339",
    "src/ccstruct/matrix.h": "CVE-2026-119340",
    "src/classify/adaptive.cpp": "CVE-2026-119341",
}


def probe_archive(source: bytes, *, expected_sha256: str = TESSERACT_SOURCE_SHA256) -> dict:
    if not isinstance(source, bytes) or not 0 < len(source) <= MAX_ARCHIVE_BYTES:
        raise ValueError("Source archive missing or oversized")
    sha256 = hashlib.sha256(source).hexdigest()
    if sha256 != expected_sha256:
        raise ValueError("Source archive digest mismatch")
    try:
        with tarfile.open(fileobj=io.BytesIO(source), mode="r:gz") as archive:
            members = archive.getmembers()
            result: dict[str, str] = {}
            for path, markers in PATCH_MARKERS.items():
                matching = [member for member in members
                            if member.name.endswith("/" + path)]
                if (len(matching) != 1 or not matching[0].isfile()
                        or not 0 < matching[0].size <= MAX_SOURCE_BYTES):
                    raise ValueError("Selected source patch target absent or ambiguous")
                stream = archive.extractfile(matching[0])
                if stream is None:
                    raise ValueError("Source archive patch target cannot be read")
                code = stream.read(MAX_SOURCE_BYTES + 1).decode("utf-8",errors="strict")
                if not all(marker in code for marker in markers):
                    raise ValueError("Selected source patch markers missing")
                result[SOURCE_CVE_BY_PATH[path]] = "source_marker_present"
    except (tarfile.TarError, UnicodeError, OSError, EOFError) as error:
        raise ValueError("Source archive cannot be examined") from error
    return {
        "status": "source_markers_verified",
        "release_version": "5.5.4",
        "source_sha256": sha256,
        "selected_checks": len(result),
        "checks": dict(sorted(result.items())),
        "binary_patch_verified": False,
        "complete_source_advisory_coverage": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.archive.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("Source archive oversized")
        report = probe_archive(args.archive.read_bytes())
    except (OSError, ValueError, TypeError):
        print(json.dumps({"status": "error", "reason": "source_fix_evidence_incomplete"}))
        return 3
    print(json.dumps(report,sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
