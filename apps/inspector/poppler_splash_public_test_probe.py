"""R1.21: reproduce a residual SplashClip::test() overflow in real source.

The public method's rectangle precondition can accept x=536870919 inside a
large, finite, synthetic clip. When antialias is enabled, the *actual*
SplashClip::testClipPaths multiplies x*4 without checking signed overflow.
This is SOURCE-LEVEL C++ evidence, NOT a PDF parser exploit or CVE closure.
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

SCRIPT = "/prototypes/run_splash_public_test.sh"
DONE = "r121-source-only-public-test-ubsan-complete"
CONDITIONS = ("normal", "x_aa_overflow")
TIMEOUT_SECONDS = 420
UBSAN_OVERFLOW = "runtime error: signed integer overflow: 536870919 * 4"


def verify_public_test_results(output: Path) -> dict:
    """Check six real-method subprocess results, not arithmetic analogues."""
    cases = {}
    for condition in CONDITIONS:
        found = {}
        for variant in VARIANTS:
            code, stdout, stderr = read_process_output(
                output, f"{variant}-publictest_{condition}",
            )
            if condition == "normal":
                valid = (
                    code == 0 and stdout == "normal_public_test_passed\n"
                    and stderr == ""
                )
            else:
                valid = (
                    code == 1 and stdout == ""
                    and UBSAN_OVERFLOW in stderr
                    and re.search(
                        rf"/work/{variant}/splash/SplashClip\.cc:\d+:\d+: "
                        r"runtime error: signed integer overflow:",
                        stderr,
                    ) is not None
                    and not re.search(
                        r"(?i)(AddressSanitizer|DEADLYSIGNAL|LeakSanitizer|"
                        r"UndefinedBehaviorSanitizer:)",
                        stderr,
                    )
                )
            if not valid:
                raise ValueError(
                    "Synthetic public SplashClip test is incomplete, altered, "
                    "or did not reproduce the expected real-source overflow"
                )
            found[variant] = {
                "exit_code": code,
                "actual_source_ubsan_signed_overflow": code == 1,
            }
        cases[condition] = found
    return {
        "cases": cases,
        "public_method_called": "SplashClip::test",
        "overflow_site": "SplashClip::testClipPaths x *= splashAASize",
        "original_and_five_and_six_prototype_ub_reproduced": True,
        "normal_public_method_behavior_retained": True,
        "pdf_parser_reproducer_verified": False,
        "cve_remediation_claimed": False,
    }


def inspect_public_test(
    sources: dict[str, bytes], fixes: dict[str, bytes],
    prototypes: dict[str, bytes], *,
    builder_id: str, fix_directory: Path, prototype_directory: Path,
    docker: str = "docker", runner: Callable = subprocess.run,
) -> dict:
    attestation = inspect_semantic_prototypes(sources, fixes, prototypes)
    overlay = validate_overlay_patch(prototype_directory)
    if attestation["prototype_source_sha256"][SOURCE_PATH] == SOURCE_YMAX_SHA256:
        raise ValueError("R1.19 overlay already in five-prototype baseline")
    extended_hashes = dict(attestation["prototype_source_sha256"])
    extended_hashes[SOURCE_PATH] = SOURCE_YMAX_SHA256

    with tempfile.TemporaryDirectory(prefix="folio-r121-splash-public-") as temp:
        root = Path(temp)
        fixtures, output = root / "fixtures", root / "results"
        create_fixture_files(fixtures, attestation)
        manifests = {
            "overlay.sha256": {
                OVERLAY_FILENAME: hashlib.sha256(overlay).hexdigest(),
            },
            "extended.sha256": extended_hashes,
        }
        for name, digests in manifests.items():
            path = fixtures / name
            path.write_bytes(_sha_manifest(digests))
            path.chmod(0o644)
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        args = build_container_args(
            builder_id, fix_directory, prototype_directory,
            fixtures, output, docker=docker,
        )
        if args[-1] != "/prototypes/build_sanitized_poppler.sh":
            raise ValueError("Unexpected container builder entrypoint")
        args[-1] = SCRIPT
        try:
            completed = runner(
                args, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Isolated public Splash test did not finish") from exc
        if (
            completed.returncode != 0 or not completed.stdout
            or len(completed.stdout) > 180 * 1024
            or completed.stdout.strip().splitlines()[-1] != DONE
        ):
            raise ValueError("Isolated Splash test output missing or untrusted")
        # Retain all nine R1.19 differential method checks before accepting
        # the six new source-level public API results.
        previous = verify_actual_splash_results(output)
        current = verify_public_test_results(output)

    return {
        "status": "research_public_splash_method_residual_ub",
        "base_source_version": attestation["base_source_version"],
        "builder_image_id": builder_id,
        "five_prototype_splash_sha256":
            attestation["prototype_source_sha256"][SOURCE_PATH],
        "sixth_overlay_splash_sha256": SOURCE_YMAX_SHA256,
        "research_overlay_sha256": hashlib.sha256(overlay).hexdigest(),
        "previous_nine_method_checks": previous,
        "six_public_method_checks": current,
        "asan_ubsan_instrumentation": True,
        "complete_splash_arithmetic_review": False,
        "full_poppler_library_compiled_in_this_experiment": False,
        "reached_from_pdf_parser": False,
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
        report = inspect_public_test(
            sources, fixes, prototypes,
            builder_id=args.builder_image_id,
            fix_directory=args.fix_directory,
            prototype_directory=args.prototype_directory,
        )
    except (ValueError, OSError, UnicodeError, TypeError, KeyError):
        print(json.dumps({
            "status": "error",
            "reason": "splash_public_method_real_source_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
