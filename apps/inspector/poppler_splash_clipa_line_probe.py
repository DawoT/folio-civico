"""R1.26: real SplashClip::clipAALine + tiny real bitmap, source-only UBSan.

The extreme x0/x1 arguments DELIBERATELY VIOLATE normal renderer bitmap
bounds. This proves missing defensive arithmetic checks in the C++ method,
NOT reachability through a PDF, a memory exploit or a CVE fix.
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
from poppler_splash_span_probe import verify_span_results

SCRIPT = "/prototypes/run_splash_clipa_line_probe.sh"
DONE = "r126-source-only-clipaaline-bitmap-ubsan-complete"
TIMEOUT_SECONDS = 590
CONDITIONS = ("normal_origin", "normal_in_bounds", "invalid_x0", "invalid_x1")
EXPECTED_NORMAL = {
    "normal_origin": "tiny_real_bitmap_origin_ok\n",
    "normal_in_bounds": "tiny_real_bitmap_in_bounds_ok\n",
}
OVERFLOW_OPERANDS = {
    "invalid_x0": "536870919",
    "invalid_x1": "536870920",
}
# Pinned R1.14 full Poppler research build, used ONLY to supply the real
# SplashBitmap constructor/destructor; not source→ELF runtime attestation.
HELPER_LIBRARY_SHA256 = "e4be4a8a2ca314740457a02f79527fe35f39272ea317e2076fb6c933a63c6195"
HELPER_LIBRARY_BYTES = 95862952


def validate_helper_library(path: Path) -> Path:
    """Require the actual, immutable-identified ELF, never a symlink or URI."""
    if (
        not path.is_absolute() or path.is_symlink() or not path.is_file()
        or path.stat().st_size != HELPER_LIBRARY_BYTES
        or any(char in str(path) for char in (",", "\n", "\r"))
    ):
        raise ValueError("Missing or invalid SHA-pinned Poppler research helper")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != HELPER_LIBRARY_SHA256:
        raise ValueError("Poppler helper binary differs from pinned R1.14 build")
    return path.resolve(strict=True)


def verify_clipaaline_results(output: Path) -> dict:
    """Demand 12 *real* process artifacts including exact UBSan diagnostics."""
    cases = {}
    for case in CONDITIONS:
        found = {}
        for variant in VARIANTS:
            exit_code, stdout, stderr = read_process_output(
                output, f"{variant}-clippaaline_{case}",
            )
            if case in EXPECTED_NORMAL:
                good = (
                    exit_code == 0 and stdout == EXPECTED_NORMAL[case]
                    and stderr == ""
                )
            else:
                operand = OVERFLOW_OPERANDS[case]
                pattern = (
                    rf"/work/{variant}/splash/SplashClip\.cc:\d+:\d+: "
                    rf"runtime error: signed integer overflow: {operand} \* 4 "
                    r"cannot be represented in type 'int'\n?"
                )
                good = (
                    exit_code == 1 and stdout == ""
                    and re.fullmatch(pattern, stderr) is not None
                )
            if not good:
                raise ValueError("clipAALine real-bitmap UBSan evidence incomplete")
            found[variant] = {
                "exit_code": exit_code,
                "signed_integer_overflow": case in OVERFLOW_OPERANDS,
            }
        cases[case] = found
    return {
        "cases": cases,
        "real_bitmap_dimensions": [64, 4],
        "real_bitmap_row_size": 8,
        "actual_method_called": "SplashClip::clipAALine",
        "normal_bitmap_bound_inputs_succeeded": True,
        "outside_bitmap_x0_and_x1_ub_reproduced_in_all_variants": True,
        "out_of_bounds_arguments_are_not_validated_renderer_inputs": True,
        "renderer_reachability_verified": False,
        "pdf_parser_reachability_verified": False,
        "cve_remediation_claimed": False,
    }


def inspect_clipa_line(
    sources: dict[str, bytes], fixes: dict[str, bytes],
    prototypes: dict[str, bytes], *,
    builder_id: str, fix_directory: Path, prototype_directory: Path,
    helper_library_path: Path, docker: str = "docker",
    runner: Callable = subprocess.run,
) -> dict:
    attestation = inspect_semantic_prototypes(sources, fixes, prototypes)
    overlay = validate_overlay_patch(prototype_directory)
    library = validate_helper_library(helper_library_path)
    if attestation["prototype_source_sha256"][SOURCE_PATH] == SOURCE_YMAX_SHA256:
        raise ValueError("Sixth research overlay already in five-prototype base")
    extended_hashes = dict(attestation["prototype_source_sha256"])
    extended_hashes[SOURCE_PATH] = SOURCE_YMAX_SHA256

    with tempfile.TemporaryDirectory(prefix="folio-r126-splash-aa-buffer-") as tmp:
        root = Path(tmp)
        fixtures, output = root / "fixtures", root / "results"
        create_fixture_files(fixtures, attestation)
        manifests = {
            "overlay.sha256": {
                OVERLAY_FILENAME: hashlib.sha256(overlay).hexdigest(),
            },
            "extended.sha256": extended_hashes,
            "helper-lib.sha256": {
                "libpoppler.so.147": HELPER_LIBRARY_SHA256,
            },
        }
        for name, items in manifests.items():
            file = fixtures / name
            file.write_bytes(_sha_manifest(items))
            file.chmod(0o644)
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        args = build_container_args(
            builder_id, fix_directory, prototype_directory, fixtures, output,
            docker=docker,
        )
        if args[-1] != "/prototypes/build_sanitized_poppler.sh":
            raise ValueError("Unexpected isolated builder entrypoint")
        # Bind one verified helper ELF read-only; never write into the host
        # binary, its directory or any operative Docker image.
        index = args.index("--entrypoint")
        args[index:index] = [
            "--mount",
            f"type=bind,source={library},target=/libhelper/libpoppler.so.147,readonly",
        ]
        args[-1] = SCRIPT
        try:
            completed = runner(
                args, capture_output=True, text=True,
                timeout=TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Offline Poppler real-bitmap clip test timed out") from exc
        if (
            completed.returncode != 0 or not completed.stdout
            or len(completed.stdout) > 220 * 1024
            or completed.stdout.strip().splitlines()[-1] != DONE
        ):
            raise ValueError("Incomplete real-bitmap source-method evidence")
        first = verify_actual_splash_results(output)
        public = verify_public_test_results(output)
        span = verify_span_results(output)
        bitmap = verify_clipaaline_results(output)

    return {
        "status": "research_clipaaline_tiny_real_bitmap_precondition_probe",
        "base_source_version": attestation["base_source_version"],
        "builder_image_id": builder_id,
        "five_prototype_splash_sha256":
            attestation["prototype_source_sha256"][SOURCE_PATH],
        "sixth_overlay_splash_sha256": SOURCE_YMAX_SHA256,
        "overlay_patch_sha256": hashlib.sha256(overlay).hexdigest(),
        "research_only_bitmap_helper_sha256": HELPER_LIBRARY_SHA256,
        "research_only_bitmap_helper_bytes": HELPER_LIBRARY_BYTES,
        "previous_nine_cliptopath_checks": first,
        "previous_six_public_test_checks": public,
        "previous_twelve_testspan_checks": span,
        "twelve_clipa_line_checks": bitmap,
        "asan_ubsan_instrumentation": True,
        "complete_splash_arithmetic_review": False,
        "full_poppler_source_to_runtime_elf_verified": False,
        "pdf_parser_reproducer_verified": False,
        "renderer_reachability_verified": False,
        "cve_remediation_claimed": False,
        "release_authorized": False,
    }


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--source-directory", type=Path, required=True)
    cli.add_argument("--fix-directory", type=Path, required=True)
    cli.add_argument("--builder-image-id", required=True)
    cli.add_argument("--helper-library-path", type=Path, required=True)
    cli.add_argument(
        "--prototype-directory", type=Path,
        default=Path(__file__).resolve().parent / "research_patches",
    )
    args = cli.parse_args()
    try:
        sources, fixes, prototypes = read_artifacts(
            args.source_directory, args.fix_directory, args.prototype_directory,
        )
        result = inspect_clipa_line(
            sources, fixes, prototypes,
            builder_id=args.builder_image_id,
            fix_directory=args.fix_directory,
            prototype_directory=args.prototype_directory,
            helper_library_path=args.helper_library_path,
        )
    except (ValueError, OSError, TypeError, UnicodeError, KeyError):
        print(json.dumps({
            "status": "error",
            "reason": "clipaaline_real_bitmap_source_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
