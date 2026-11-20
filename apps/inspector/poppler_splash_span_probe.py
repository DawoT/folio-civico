"""R1.24: bound the real public SplashClip::testSpan arithmetic path.

A SHA-attested Debian source method test; NOT a PDF-parsed repro, CVE fix,
or authorization for OCI/runtime changes.
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

from poppler_isolated_sanitizer import (
    _sha_manifest, build_container_args, create_fixture_files, read_artifacts,
)
from poppler_reachability_probe import read_process_output
from poppler_semantic_research import inspect_semantic_prototypes
from poppler_splash_ymax_probe import (
    OVERLAY_FILENAME, SOURCE_PATH, SOURCE_YMAX_SHA256, VARIANTS,
    validate_overlay_patch, verify_actual_splash_results,
)
from poppler_splash_public_test_probe import verify_public_test_results

SCRIPT = "/prototypes/run_splash_span_probe.sh"
DONE = "r124-source-only-span-method-ubsan-complete"
TIMEOUT_SECONDS = 520
CONDITIONS = ("normal", "no_path_extreme", "outside_guard", "span_x_aa_overflow")
OVERFLOW = "runtime error: signed integer overflow: 536870919 * 4"
STDOUT = {
    "normal": "normal_span_inside\n",
    "no_path_extreme": "without_path_inside\n",
    "outside_guard": "outside_guard_rejected\n",
}


def verify_span_results(output: Path) -> dict:
    """Require all 12 bounded C++ subprocess results from three real sources."""
    result = {}
    for condition in CONDITIONS:
        variants = {}
        for variant in VARIANTS:
            code, stdout, stderr = read_process_output(
                output, f"{variant}-span_{condition}",
            )
            if condition == "span_x_aa_overflow":
                valid = (
                    code == 1
                    and stdout == ""
                    and OVERFLOW in stderr
                    and re.search(
                        rf"/work/{variant}/splash/SplashClip\.cc:\d+:\d+: "
                        r"runtime error: signed integer overflow:",
                        stderr,
                    ) is not None
                    and not re.search(
                        r"(?i)AddressSanitizer|DEADLYSIGNAL|LeakSanitizer|"
                        r"UndefinedBehaviorSanitizer:",
                        stderr,
                    )
                )
            else:
                valid = code == 0 and stdout == STDOUT[condition] and stderr == ""
            if not valid:
                raise ValueError(
                    "Splash testSpan actual-source evidence missing, "
                    "falsified or divergent"
                )
            variants[variant] = {
                "exit_code": code,
                "ubsan_signed_overflow": condition == "span_x_aa_overflow",
            }
        result[condition] = variants
    return {
        "cases": result,
        "public_method_called": "SplashClip::testSpan",
        "overflow_site": "SplashClip::testSpan spanXMin/spanXMax * splashAASize",
        "triangular_non_rectangular_clip_compiled": True,
        "no_path_extreme_short_circuits": True,
        "outside_rect_extreme_short_circuits": True,
        "all_three_variants_prove_residual_ub": True,
        "pdf_parser_reachability_verified": False,
        "additional_cve_remediation_verified": False,
    }


def inspect_span(
    sources: dict[str, bytes], fixes: dict[str, bytes],
    prototypes: dict[str, bytes], *,
    builder_id: str, fix_directory: Path, prototype_directory: Path,
    docker: str = "docker", runner: Callable = subprocess.run,
) -> dict:
    attestation = inspect_semantic_prototypes(sources, fixes, prototypes)
    overlay = validate_overlay_patch(prototype_directory)
    if attestation["prototype_source_sha256"][SOURCE_PATH] == SOURCE_YMAX_SHA256:
        raise ValueError("Sixth research overlay already in five-patch baseline")
    hashes = dict(attestation["prototype_source_sha256"])
    hashes[SOURCE_PATH] = SOURCE_YMAX_SHA256

    with tempfile.TemporaryDirectory(prefix="folio-r124-splash-span-") as tmp:
        temp = Path(tmp)
        fixtures, output = temp / "fixtures", temp / "results"
        create_fixture_files(fixtures, attestation)
        for name, entries in {
            "overlay.sha256": {
                OVERLAY_FILENAME: hashlib.sha256(overlay).hexdigest(),
            },
            "extended.sha256": hashes,
        }.items():
            path = fixtures / name
            path.write_bytes(_sha_manifest(entries))
            path.chmod(0o644)
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        args = build_container_args(
            builder_id, fix_directory, prototype_directory,
            fixtures, output, docker=docker,
        )
        if args[-1] != "/prototypes/build_sanitized_poppler.sh":
            raise ValueError("Unexpected isolated builder command")
        args[-1] = SCRIPT
        try:
            completed = runner(
                args, capture_output=True, text=True,
                timeout=TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Isolated testSpan method build incomplete") from exc
        if (
            completed.returncode != 0 or not completed.stdout
            or len(completed.stdout) > 200 * 1024
            or completed.stdout.strip().splitlines()[-1] != DONE
        ):
            raise ValueError("Isolated testSpan source-only contract incomplete")
        previous = verify_actual_splash_results(output)
        public = verify_public_test_results(output)
        span = verify_span_results(output)
    return {
        "status": "research_public_splash_testspan_residual_ub",
        "base_source_version": attestation["base_source_version"],
        "builder_image_id": builder_id,
        "five_prototype_splash_sha256":
            attestation["prototype_source_sha256"][SOURCE_PATH],
        "sixth_overlay_splash_sha256": SOURCE_YMAX_SHA256,
        "overlay_patch_sha256": hashlib.sha256(overlay).hexdigest(),
        "previous_nine_method_checks": previous,
        "previous_six_public_test_checks": public,
        "twelve_public_span_checks": span,
        "asan_ubsan_instrumentation": True,
        "full_poppler_library_compiled_in_this_experiment": False,
        "complete_splash_arithmetic_review": False,
        "pdf_parser_reproducer_verified": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "cve_remediation_claimed": False,
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
        sources, fixes, prototypes = read_artifacts(
            args.source_directory, args.fix_directory, args.prototype_directory,
        )
        result = inspect_span(
            sources, fixes, prototypes,
            builder_id=args.builder_image_id,
            fix_directory=args.fix_directory,
            prototype_directory=args.prototype_directory,
        )
    except (ValueError, OSError, TypeError, UnicodeError, KeyError):
        print(json.dumps({
            "status": "error",
            "reason": "splash_span_method_source_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
