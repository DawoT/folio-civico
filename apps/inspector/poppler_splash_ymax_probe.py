"""R1.19 source-only SplashClip yMaxAA guard, NOT an authorized CVE fix.

Strictly compares the real SplashClip::clipToPath in three separately compiled
source variants: SHA-pinned Debian, R1.13 five prototypes and those same five
plus a sixth TEMPORARY local overlay. No PDF parser, runtime, deploy or VEX.
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

SCRIPT = "/prototypes/run_splash_ymax_overlay.sh"
OVERLAY_FILENAME = "SplashClip-ymax-checked-research-overlay.patch"
OVERLAY_SHA256 = "fc2983047d1f87e072760a5fca4f2e7130829b6272f37fa3488b40d318374720"
SOURCE_YMAX_SHA256 = "6512113e7233bfdd18d0c910a8f565b4f88adbfe172db5002bf0ca4e9477bdf4"
SOURCE_PATH = "splash/SplashClip.cc"
VARIANTS = ("original", "patched", "extended")
CONDITIONS = ("normal", "ymin_overflow", "ymax_overflow")
DONE_MARKER = "r119-source-only-splash-ymax-experiment-complete"
TIMEOUT_SECONDS = 320


def validate_overlay_patch(directory: Path) -> bytes:
    """Refuse symlinked, changed, multi-target or unpinned research overlays."""
    path = directory / OVERLAY_FILENAME
    if (not path.is_file() or path.is_symlink()
            or not 0 < path.stat().st_size < 2048):
        raise ValueError("Missing or unsafe R1.19 research overlay")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != OVERLAY_SHA256:
        raise ValueError("R1.19 overlay no longer matches pinned source review")
    source = data.decode("utf-8", errors="strict")
    if (re.findall(r"(?m)^--- (.+)$", source) != ["a/" + SOURCE_PATH]
            or re.findall(r"(?m)^\+\+\+ (.+)$", source) != ["b/" + SOURCE_PATH]
            or source.count("-            yMaxAA = (yMaxI + 1) * splashAASize - 1;") != 1
            or source.count("+            int yMaxIPlusOne, yMaxAAPadded;") != 1
            or "checkedAdd(yMaxI, 1, &yMaxIPlusOne)" not in source
            or "checkedMultiply(yMaxIPlusOne, splashAASize, &yMaxAAPadded)" not in source
            or "checkedSubtraction(yMaxAAPadded, 1, &yMaxAA)" not in source):
        raise ValueError("R1.19 overlay modifies unexpected code")
    return data


def verify_actual_splash_results(output: Path) -> dict:
    """Demand nine actual bounded process outcomes incl. residual UB baseline."""
    cases = {}
    for condition in CONDITIONS:
        results = {}
        for variant in VARIANTS:
            code, stdout, stderr = read_process_output(
                output, variant + "-" + condition,
            )
            if condition == "normal":
                expected_code, expected_stdout = 0, "normal_path_accepted"
            elif condition == "ymin_overflow" and variant != "original":
                expected_code, expected_stdout = 0, "splash_ymin_checked_rejected"
            elif condition == "ymax_overflow" and variant == "extended":
                expected_code, expected_stdout = 0, "splash_ymax_checked_rejected"
            else:
                expected_code, expected_stdout = 1, ""
            if code != expected_code or stdout.strip() != expected_stdout:
                raise ValueError("Required actual-source Splash differential absent")
            if expected_code == 0:
                if stderr:
                    raise ValueError("Guard returned after an unexpected sanitizer warning")
            elif (not re.search(r"(?m)^/work/(original|patched)/splash/SplashClip\.cc:\d+:\d+: runtime error: signed integer overflow:", stderr)
                  or "536870919 * 4" not in stderr
                  or "AddressSanitizer" in stderr):
                raise ValueError("Expected exact SplashClip UBSan evidence missing")
            results[variant] = {
                "exit_code": code,
                "signed_integer_overflow_observed": code == 1,
                "controlled_rejection": expected_code == 0 and condition != "normal",
            }
        cases[condition] = results
    return {
        "cases": cases,
        "real_cpp_method_executed": True,
        "original_ymin_overflow_reproduced": True,
        "original_and_five_prototypes_ymax_overflow_reproduced": True,
        "sixth_overlay_ymax_rejected_without_ub": True,
        "existing_ymin_guard_retained": True,
        "normal_path_retained": True,
        "reached_by_pdf_parser": False,
        "cve_2026_102621_complete_fix_verified": False,
    }


def inspect_ymax_overlay(
    sources: dict[str, bytes], fixes: dict[str, bytes], prototypes: dict[str, bytes],
    *, builder_id: str, fix_directory: Path, prototype_directory: Path,
    docker: str = "docker", runner: Callable = subprocess.run,
) -> dict:
    attestation = inspect_semantic_prototypes(sources, fixes, prototypes)
    overlay = validate_overlay_patch(prototype_directory)
    if attestation["prototype_source_sha256"][SOURCE_PATH] == SOURCE_YMAX_SHA256:
        raise ValueError("Supplement already applied to pinned five-prototype base")
    extended_hashes = dict(attestation["prototype_source_sha256"])
    extended_hashes[SOURCE_PATH] = SOURCE_YMAX_SHA256

    with tempfile.TemporaryDirectory(prefix="folio-r119-splash-source-") as temp:
        root = Path(temp)
        fixtures, output = root / "fixtures", root / "results"
        create_fixture_files(fixtures, attestation)
        (fixtures / "overlay.sha256").write_bytes(_sha_manifest({
            OVERLAY_FILENAME: hashlib.sha256(overlay).hexdigest(),
        }))
        (fixtures / "extended.sha256").write_bytes(_sha_manifest(extended_hashes))
        for name in ("overlay.sha256", "extended.sha256"):
            (fixtures / name).chmod(0o644)
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        args = build_container_args(
            builder_id, fix_directory, prototype_directory, fixtures, output,
            docker=docker,
        )
        if args[-1] != "/prototypes/build_sanitized_poppler.sh":
            raise ValueError("Unexpected builder command")
        args[-1] = SCRIPT
        try:
            completed = runner(
                args, capture_output=True, text=True,
                timeout=TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("R1.19 isolated source-only build did not finish") from exc
        if (completed.returncode != 0 or not completed.stdout
                or len(completed.stdout) > 150 * 1024
                or completed.stdout.strip().splitlines()[-1] != DONE_MARKER):
            raise ValueError("R1.19 source-only comparison incomplete")
        checks = verify_actual_splash_results(output)

    return {
        "status": "research_source_only_splash_ymax_overlay",
        "base_source_version": attestation["base_source_version"],
        "builder_image_id": builder_id,
        "original_source_sha256": attestation["baseline_sha256"][SOURCE_PATH],
        "five_prototype_source_sha256": attestation["prototype_source_sha256"][SOURCE_PATH],
        "sixth_overlay_source_sha256": SOURCE_YMAX_SHA256,
        "overlay_patch_sha256": OVERLAY_SHA256,
        "strict_sha256_source_and_patch_attestation": True,
        "actual_method_checks": checks,
        "full_poppler_binary_compilation_verified": False,
        "pdf_parser_regression_verified": False,
        "cve_remediation_claimed": False,
        "all_selected_cve_fixes_verified": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "release_authorized": False,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source-directory", type=Path, required=True)
    cli.add_argument("--fix-directory", type=Path, required=True)
    cli.add_argument("--builder-image-id", required=True)
    cli.add_argument("--prototype-directory", type=Path,
                     default=Path(__file__).resolve().parent / "research_patches")
    args = cli.parse_args()
    try:
        sources, fixes, prototypes = read_artifacts(
            args.source_directory, args.fix_directory, args.prototype_directory,
        )
        outcome = inspect_ymax_overlay(
            sources, fixes, prototypes, builder_id=args.builder_image_id,
            fix_directory=args.fix_directory,
            prototype_directory=args.prototype_directory,
        )
    except (ValueError, OSError, UnicodeError, TypeError, KeyError):
        print(json.dumps({
            "status": "error",
            "reason": "splash_ymax_guard_research_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(outcome, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
