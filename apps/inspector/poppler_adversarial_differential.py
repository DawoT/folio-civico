"""R1.16: offline synthetic differential Poppler source experiment.

Two separately compiled ASan/UBSan source trees: unchanged SHA-pinned Debian
and the same Debian source with five research patches. No runtime replacement,
real PDFs, network traffic, CVE adjudication or release authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

from poppler_adversarial_corpus import corpus_sha256, synthetic_differential_pdfs
from poppler_isolated_sanitizer import (
    _sha_manifest, build_container_args, create_fixture_files, read_artifacts,
)
from poppler_semantic_research import inspect_semantic_prototypes

CASES = frozenset(synthetic_differential_pdfs())
VARIANTS = frozenset(("original", "patched"))
SANITIZER_CLASSIFICATIONS = frozenset((
    "none", "ubsan_shift_exponent_32", "ubsan_signed_integer_overflow",
    "ubsan_null_pointer_arithmetic", "sanitizer_other", "process_signal",
    "timeout",
))
SCRIPT = "/prototypes/run_adversarial_differential.sh"


def validate_differential_observation(value: dict) -> dict:
    if not isinstance(value, dict) or value.get("status") != "source_differential_research_only":
        raise ValueError("Untrusted differential report")
    if (value.get("release_authorized") is not False
            or value.get("cve_remediation_claimed") is not False
            or value.get("all_selected_cve_fixes_verified") is not False
            or value.get("source_binary_equivalence_to_runtime_verified") is not False):
        raise ValueError("Invalid differential security claims")
    cases = value.get("cases")
    if not isinstance(cases, dict) or set(cases) != CASES:
        raise ValueError("Incomplete adversarial differential corpus")
    for case, pair in cases.items():
        if not isinstance(pair, dict) or set(pair) != VARIANTS:
            raise ValueError("Incomplete differential pair")
        for variant, result in pair.items():
            if not isinstance(result, dict) or set(result) != {
                "exit_code", "sanitizer", "raster_sha256", "diagnostic_prefix",
            }:
                raise ValueError("Untrusted differential outcome")
            if (type(result["exit_code"]) is not int
                    or not -128 <= result["exit_code"] <= 128
                    or result["sanitizer"] not in SANITIZER_CLASSIFICATIONS
                    or not isinstance(result["diagnostic_prefix"], str)
                    or len(result["diagnostic_prefix"]) > 400
                    or (result["raster_sha256"] is not None
                        and (not isinstance(result["raster_sha256"], str)
                             or not re.fullmatch(r"[a-f0-9]{64}", result["raster_sha256"])))):
                raise ValueError("Malformed differential result")
    return value



def _read_bounded_text(path: Path, limit: int) -> str:
    if (not path.is_file() or path.is_symlink()
            or path.stat().st_size > limit):
        raise ValueError("Missing, linked or oversized differential output")
    return path.read_text("utf-8", errors="replace")


def read_instrumented_results(output: Path) -> dict:
    """Read and classify actual bounded process evidence from rootless Docker."""
    cases = {}
    for case in sorted(CASES):
        pair = {}
        for variant in sorted(VARIANTS):
            stem = output / (variant + "-" + case)
            exit_text = _read_bounded_text(Path(str(stem) + ".exit"), 8).strip()
            if not re.fullmatch(r"[0-9]{1,3}", exit_text):
                raise ValueError("Untrusted subprocess exit status")
            code = int(exit_text)
            if code > 255:
                raise ValueError("Unbounded subprocess exit status")
            stderr = _read_bounded_text(Path(str(stem) + ".stderr"), 128 * 1024)
            _read_bounded_text(Path(str(stem) + ".stdout"), 128 * 1024)
            signal = "none"
            if code == 124:
                signal = "timeout"
            elif "runtime error:" in stderr or "AddressSanitizer" in stderr:
                if "shift exponent 32" in stderr:
                    signal = "ubsan_shift_exponent_32"
                elif "signed integer overflow" in stderr:
                    signal = "ubsan_signed_integer_overflow"
                elif "applying non-zero offset to null pointer" in stderr:
                    signal = "ubsan_null_pointer_arithmetic"
                else:
                    signal = "sanitizer_other"
            elif code > 128:
                signal = "process_signal"
            raster_file = Path(str(stem) + ".pgm")
            digest = None
            if raster_file.exists():
                if (not raster_file.is_file() or raster_file.is_symlink()
                        or raster_file.stat().st_size > 1024 * 1024):
                    raise ValueError("Unsafe synthetic differential raster")
                digest = hashlib.sha256(raster_file.read_bytes()).hexdigest()
            pair[variant] = {
                "exit_code": code,
                "sanitizer": signal,
                "raster_sha256": digest,
                "diagnostic_prefix": stderr[:400],
            }
        cases[case] = pair
    return validate_differential_observation({
        "status": "source_differential_research_only",
        "cases": cases,
        "all_selected_cve_fixes_verified": False,
        "cve_remediation_claimed": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "release_authorized": False,
    })



PARSER_EXPECTED_DIFF = {
    "sampled32": "ubsan_shift_exponent_32",
    "jbig2_intmin": "ubsan_signed_integer_overflow",
}
PARSER_CONTROLS = frozenset(CASES - set(PARSER_EXPECTED_DIFF))


def verify_expected_parser_differentials(observed: dict) -> dict:
    """Two exact sanitizer observations, four unchanged control rasters.

    This is *not* proof of complete CVE remediation or exploit nonreachability.
    The JBIG2 INT_MIN PDF still generates a syntax warning after the patch.
    """
    value = validate_differential_observation(observed)
    for case, expected_marker in PARSER_EXPECTED_DIFF.items():
        original = value["cases"][case]["original"]
        patched = value["cases"][case]["patched"]
        if (original["sanitizer"] != expected_marker
                or original["exit_code"] == 0
                or patched["sanitizer"] != "none"
                or patched["exit_code"] != 0
                or patched["raster_sha256"] is None):
            raise ValueError("Required real-parser numeric differential absent")
    for case in PARSER_CONTROLS:
        original = value["cases"][case]["original"]
        patched = value["cases"][case]["patched"]
        if (original["sanitizer"] != "none" or patched["sanitizer"] != "none"
                or original["exit_code"] != 0 or patched["exit_code"] != 0
                or original["raster_sha256"] is None
                or original["raster_sha256"] != patched["raster_sha256"]):
            raise ValueError("Synthetic parser control diverged")
    return {
        "two_numeric_ub_differentials_observed": True,
        "four_control_rasters_identical": True,
        "targeted_pdf_cases_without_exploit_reproduction": [
            "splash_far", "jbig2_large_page",
        ],
        "jbig2_intmin_syntax_warning_remains": (
            "Syntax Error" in value["cases"]["jbig2_intmin"]["patched"]["diagnostic_prefix"]
        ),
        "selected_cve_fixes_verified": False,
    }


def inspect_source_differential(
    sources: dict[str, bytes], fixes: dict[str, bytes], prototypes: dict[str, bytes],
    *, builder_id: str, fix_directory: Path, prototype_directory: Path,
    runner: Callable = subprocess.run,
    docker: str = "docker",
) -> dict:
    attestation = inspect_semantic_prototypes(sources, fixes, prototypes)
    with tempfile.TemporaryDirectory(prefix="folio-r116-differential-") as scratch:
        tmp = Path(scratch)
        fixtures = tmp / "fixtures"
        output = tmp / "results"
        create_fixture_files(fixtures, attestation)
        expected = synthetic_differential_pdfs()
        for name, blob in expected.items():
            path = fixtures / (name + ".pdf")
            if path.exists() and path.read_bytes() != blob:
                raise ValueError("Synthetic corpus filename collision")
            path.write_bytes(blob)
            path.chmod(0o644)
        (fixtures / "differential-corpus.sha256").write_bytes(
            _sha_manifest({name + ".pdf": hashlib.sha256(blob).hexdigest()
                           for name, blob in expected.items()})
        )
        (fixtures / "differential-corpus.sha256").chmod(0o644)
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        args = build_container_args(
            builder_id, fix_directory, prototype_directory, fixtures,
            output, docker=docker,
        )
        assert args[-1] == "/prototypes/build_sanitized_poppler.sh"
        args[-1] = SCRIPT
        try:
            result = runner(
                args, capture_output=True, text=True, timeout=590, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Source comparator did not finish") from error
        if result.returncode != 0:
            raise ValueError("Differential source compilation or run failed")
        if not result.stdout or len(result.stdout) > 300 * 1024:
            raise ValueError("Missing or oversized offline source results")
        if result.stdout.strip().splitlines()[-1:] != [
            "r116-differential-synthetic-execution-complete"
        ]:
            raise ValueError("Comparator did not attest bounded execution")
        observed = read_instrumented_results(output)
    differential_checks = verify_expected_parser_differentials(observed)
    original_signals = {
        case: pair["original"]["sanitizer"]
        for case, pair in observed["cases"].items()
        if pair["original"]["sanitizer"] != "none"
    }
    patched_signals = {
        case: pair["patched"]["sanitizer"]
        for case, pair in observed["cases"].items()
        if pair["patched"]["sanitizer"] != "none"
    }
    return {
        "status": "isolated_adversarial_source_comparison_only",
        "base_source_version": attestation["base_source_version"],
        "builder_image_id": builder_id,
        "original_source_sha256": attestation["baseline_sha256"],
        "prototype_source_sha256": attestation["prototype_source_sha256"],
        "corpus_sha256": corpus_sha256(),
        "observations": observed["cases"],
        "differential_checks": differential_checks,
        "original_sanitizer_findings": original_signals,
        "prototype_sanitizer_findings": patched_signals,
        "differential_evidence_not_cve_adjudication": True,
        "individual_cve_fix_verified": False,
        "all_selected_cve_fixes_verified": False,
        "cve_remediation_claimed": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "release_authorized": False,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source-directory", type=Path, required=True)
    cli.add_argument("--fix-directory", type=Path, required=True)
    cli.add_argument("--builder-image-id", required=True)
    cli.add_argument(
        "--prototype-directory", type=Path,
        default=Path(__file__).resolve().parent / "research_patches",
    )
    args = cli.parse_args()
    try:
        a, b, c = read_artifacts(
            args.source_directory, args.fix_directory, args.prototype_directory,
        )
        report = inspect_source_differential(
            a, b, c,
            builder_id=args.builder_image_id,
            fix_directory=args.fix_directory,
            prototype_directory=args.prototype_directory,
        )
    except (ValueError, OSError, TypeError, UnicodeError):
        print(json.dumps({
            "status": "error",
            "reason": "poppler_adversarial_differential_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
