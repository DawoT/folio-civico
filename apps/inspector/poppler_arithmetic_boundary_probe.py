"""R1.16: reproducible UBSan numeric-boundary analogues, NOT parser/CVE proof.

Requires a source tree whose *relevant bytes* exactly match official Debian
Poppler 25.03.0-5+deb13u4, and a C++ compiler with UBSan available locally.
No Docker runtime, PDFs, external services or deployed code are changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

EXPECTED_SOURCE_SHA256 = {
    "fofi/FoFiTrueType.cc": "9e58abd2c38276b18a7f073b6d3154cae6ee1236fc076c7967f1a80aef139119",
    "poppler/Function.cc": "de8be371640a95e0eda20b8517262f9c4f4965c22c852c3ccb5fe5744c298a46",
    "poppler/JBIG2Stream.cc": "3dce697c3bb86440bab753e210cbab8b95264c44e951065695555ecc007575fe",
    "splash/SplashClip.cc": "9449ee782a2d13e424d4b94eaca5e87f0ec59b310bf2e6c05366cc154eebf599",
    "goo/GooCheckedOps.h": "41d9a2f187d7e17397c76633b23954da3a594efc6cffd44deda5c8c3e937d2ae",
}
SOURCE_MARKERS = {
    "fofi/FoFiTrueType.cc": (
        "length += locaTable[j].len;",
        "length += 4 - (length & 3);",
    ),
    "poppler/Function.cc": ("bitMask = (1 << sampleBits) - 1;",),
    "poppler/JBIG2Stream.cc": ("huffTab[i].val = lowVal - 1;",),
    "splash/SplashClip.cc": (
        "yMinAA = yMinI * splashAASize;",
        "yMaxAA = (yMaxI + 1) * splashAASize - 1;",
    ),
}
FIXED_OPERATIONS = (
    "sampled32", "jbig2_intmin", "splash_ymin", "truetype_glyph_length",
)
RESIDUAL_OPERATIONS = (
    "splash_ymax_residual", "truetype_alignment_residual",
)


def verify_source_snapshot(tree: Path) -> dict[str, str]:
    """Verify only selected exact source bytes, not the complete Debian signature."""
    observed = {}
    for name, expected in EXPECTED_SOURCE_SHA256.items():
        path = tree / name
        if (not path.is_file() or path.is_symlink()
                or not 0 < path.stat().st_size <= 512 * 1024):
            raise ValueError("Selected pinned Poppler source missing")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise ValueError("Selected Poppler source digest mismatch")
        if any(marker not in data.decode("utf-8", errors="strict")
               for marker in SOURCE_MARKERS.get(name, ())):
            raise ValueError("Selected original vulnerable arithmetic absent")
        observed[name] = digest
    return observed


def evaluate_boundary_analogues(
    tree: Path, *, compiler: str = "g++", runner=subprocess.run,
) -> dict:
    hashes = verify_source_snapshot(tree)
    source = Path(__file__).resolve().parent / "research_patches" / (
        "differential_arithmetic_boundaries.cc"
    )
    if (not source.is_file() or source.is_symlink()
            or not 0 < source.stat().st_size <= 16 * 1024):
        raise ValueError("Missing research arithmetic analogue")
    results = {}
    with tempfile.TemporaryDirectory(prefix="folio-r116-ubsan-analogues-") as temp:
        exe = Path(temp) / "arithmetic"
        command = [
            compiler, "-std=c++20", "-O1", "-g", "-fsanitize=undefined",
            "-fno-sanitize-recover=all", "-I", str(tree),
            str(source), "-o", str(exe),
        ]
        try:
            built = runner(
                command, capture_output=True, text=True, timeout=45,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Research C++ boundary compiler failed") from error
        if built.returncode != 0 or not exe.is_file():
            raise ValueError("UBSan arithmetic research compiler unavailable")
        for name in (*FIXED_OPERATIONS, *RESIDUAL_OPERATIONS):
            pair = {}
            for variant in ("original", "patched"):
                try:
                    proc = runner(
                        [str(exe), variant, name],
                        capture_output=True, text=True, timeout=8,
                        check=False, env={
                            **os.environ, "UBSAN_OPTIONS": "halt_on_error=1",
                        },
                    )
                except (OSError, subprocess.TimeoutExpired) as error:
                    raise ValueError("Arithmetic analogue hung or crashed") from error
                detected = "runtime error:" in proc.stderr
                if name in FIXED_OPERATIONS:
                    expected_signal = variant == "original"
                else:
                    expected_signal = True
                if detected != expected_signal or (proc.returncode == 0) == expected_signal:
                    raise ValueError("Unexpected UBSan arithmetic analogue result")
                pair[variant] = {
                    "exit_code": proc.returncode,
                    "ubsan_observed": detected,
                }
            results[name] = pair
    return {
        "status": "source_arithmetic_analogues_only",
        "source_files_sha256": hashes,
        "harness_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "operations": results,
        "original_overflow_analogues": len(FIXED_OPERATIONS),
        "prototype_guard_analogues": len(FIXED_OPERATIONS),
        "still_unchecked_analogues": len(RESIDUAL_OPERATIONS),
        "actual_pdf_parser_path_verified": False,
        "cve_remediation_claimed": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pinned-source-tree", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = evaluate_boundary_analogues(args.pinned_source_tree)
    except (ValueError, OSError, UnicodeError, TypeError):
        print(json.dumps({
            "status": "error",
            "reason": "arithmetic_analogue_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
