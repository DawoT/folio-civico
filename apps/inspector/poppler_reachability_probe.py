"""R1.17 exact-source reachability experiments: no CVE or runtime approval.

Calls the already-proven R1.16 isolated differential builder, then evaluates:
- actual SplashClip::clipToPath on three bounded numeric input conditions;
- real JBIG2 PDF rejection paths that prevent an invalid pageBitmap reaching reset;
- real PostScript Type42 conversion from an embedded, fixed synthetic TrueType.
These have DIFFERENT evidence levels; no case proves whole-CVE remediation.
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

from poppler_adversarial_corpus import synthetic_differential_pdfs
from poppler_adversarial_differential import (
    _read_bounded_text, read_instrumented_results, verify_expected_parser_differentials,
)
from poppler_isolated_sanitizer import (
    _sha_manifest, build_container_args, create_fixture_files, read_artifacts,
)
from poppler_reachability_corpus import (
    FONT_CASE_NAME, PAGE_DIMENSION_CASES, SYNTHETIC_TTF_SHA256,
    additional_corpus_sha256, additional_reachability_pdfs,
)
from poppler_semantic_research import inspect_semantic_prototypes

SCRIPT = "/prototypes/run_reachability_differential.sh"
SPLASH_CASES = ("normal", "ymin_overflow", "ymax_residual")
EXPECTED_CONTAINER_DONE = "r117-method-and-parser-reachability-complete"
TIMEOUT_SECONDS = 590


def read_process_output(output: Path, stem: str) -> tuple[int, str, str]:
    """Read bounded real process records; refuse symlinks or forged exit codes."""
    root = output / stem
    exit_text = _read_bounded_text(Path(str(root) + ".exit"), 8).strip()
    if not re.fullmatch(r"[0-9]{1,3}", exit_text):
        raise ValueError("Invalid or missing actual subprocess status")
    code = int(exit_text)
    if code > 255:
        raise ValueError("Invalid actual subprocess exit code")
    stdout = _read_bounded_text(Path(str(root) + ".stdout"), 2048)
    stderr = _read_bounded_text(Path(str(root) + ".stderr"), 16384)
    if code == 124 or code > 128:
        raise ValueError("Research process timed out or crashed")
    return code, stdout, stderr


def read_binary_output(output: Path, filename: str, limit: int) -> bytes:
    """Read an exact, bounded artifact, never follow symlinks."""
    path = output / filename
    if (not path.is_file() or path.is_symlink()
            or not 0 < path.stat().st_size < limit):
        raise ValueError("Missing, symlinked or oversized synthetic output")
    return path.read_bytes()


def verify_splash_method_cases(output: Path) -> dict:
    """Compare real source method, not an arithmetic analogue or PDF parser."""
    cases = {}
    for name in SPLASH_CASES:
        pairs = {}
        for variant in ("original", "patched"):
            code, stdout, stderr = read_process_output(
                output, variant + "-splash_" + name,
            )
            if name == "normal":
                valid = (code == 0 and stdout.strip() == "normal_path_accepted"
                         and stderr == "")
            elif name == "ymin_overflow" and variant == "patched":
                valid = (code == 0
                         and stdout.strip() == "splash_ymin_checked_rejected"
                         and stderr == "")
            else:
                # Exact pre/post source method must report signed overflow from
                # SplashClip.cc. Never accept another sanitizer error or signal.
                valid = (code == 1 and stdout == ""
                         and "SplashClip.cc:" in stderr
                         and "runtime error: signed integer overflow:" in stderr
                         and "536870919 * 4" in stderr
                         and "AddressSanitizer" not in stderr)
            if not valid:
                raise ValueError("SplashClip actual-source differential incomplete")
            pairs[variant] = {
                "exit_code": code,
                "ubsan_overflow_observed": code == 1,
                "guarded_rejection": (
                    name == "ymin_overflow" and variant == "patched"
                ),
            }
        cases[name] = pairs
    return {
        "cases": cases,
        "normal_path_functional_both": True,
        "actual_splash_method_ymin_guard_observed": True,
        "actual_splash_method_ymax_residual_ub_observed_both": True,
        "reached_through_pdf_parser": False,
        "splash_cve_fully_verified": False,
    }


def verify_jbig2_early_rejection(output: Path) -> dict:
    """Confirm the existing Trixie page guard on three real PDF inputs."""
    cases = {}
    for case in sorted(PAGE_DIMENSION_CASES):
        signatures = []
        for variant in ("original", "patched"):
            code, stdout, stderr = read_process_output(
                output, variant + "-" + case,
            )
            if (code != 0 or stdout != ""
                    or "Syntax Error: invalid width/height" not in stderr
                    or "runtime error:" in stderr
                    or "AddressSanitizer" in stderr
                    or "UndefinedBehaviorSanitizer" in stderr):
                raise ValueError("JBIG2 page rejection differs or contains sanitizer")
            raster = read_binary_output(output, variant + "-" + case + ".pgm",
                                        1024 * 1024)
            if not raster.startswith(b"P5"):
                raise ValueError("Synthetic JBIG2 PGM missing")
            signatures.append(hashlib.sha256(raster).hexdigest())
        if signatures[0] != signatures[1]:
            raise ValueError("JBIG2 invalid-page raster drifted")
        cases[case] = {
            "rejected_by_existing_width_height_guard": True,
            "raster_sha256": signatures[0],
            "baseline_equal_to_prototype": True,
        }
    return {
        "cases": cases,
        "invalid_page_cases_rejected_equally": len(cases),
        "null_bitmap_arithmetic_reproduced": False,
        "cve_2026_93312_fix_verified": False,
    }


def verify_synthetic_true_type(output: Path) -> dict:
    """Exact PostScript parity with two-glyph font; NOT glyph overflow."""
    digests = []
    for variant in ("original", "patched"):
        code, stdout, stderr = read_process_output(
            output, variant + "-" + FONT_CASE_NAME,
        )
        if (code != 0 or stdout != "" or "runtime error:" in stderr
                or "AddressSanitizer" in stderr or "UndefinedBehaviorSanitizer" in stderr):
            raise ValueError("Synthetic TrueType conversion failed or had sanitizer")
        postscript = read_binary_output(
            output, variant + "-" + FONT_CASE_NAME + ".ps", 131072,
        )
        if (not postscript.startswith(b"%!PS")
                or postscript.count(b"/FontType 42 def") != 1
                or postscript.count(b"/sfnts [") != 1
                or b"FolioSynthetic-Regular" not in postscript):
            raise ValueError("Synthetic font did not exercise Type42 output")
        digests.append(hashlib.sha256(postscript).hexdigest())
    if digests[0] != digests[1]:
        raise ValueError("PostScript Type42 output differs after research patches")
    return {
        "type42_postscript_baseline_equal_to_prototype": True,
        "type42_postscript_sha256": digests[0],
        "synthetic_ttf_sha256": SYNTHETIC_TTF_SHA256,
        "synthetic_true_type_pdf_parser_executed": True,
        "truetype_glyph_length_overflow_reproduced": False,
        "cve_2026_102620_fix_verified": False,
    }


def inspect_reachability(
    sources: dict[str, bytes], fixes: dict[str, bytes], prototypes: dict[str, bytes],
    *, builder_id: str, fix_directory: Path, prototype_directory: Path,
    docker: str = "docker", runner: Callable = subprocess.run,
) -> dict:
    attestation = inspect_semantic_prototypes(sources, fixes, prototypes)
    with tempfile.TemporaryDirectory(prefix="folio-r117-reachability-") as scratch:
        root = Path(scratch)
        fixtures = root / "fixtures"
        output = root / "results"
        create_fixture_files(fixtures, attestation)
        original_r116 = synthetic_differential_pdfs()
        additional = additional_reachability_pdfs()
        if set(original_r116) & set(additional):
            raise ValueError("Synthetic corpus name collision")
        all_cases = {**original_r116, **additional}
        for name, data in all_cases.items():
            target = fixtures / (name + ".pdf")
            if target.exists() and target.read_bytes() != data:
                raise ValueError("Synthetic corpus overwrote a fixture")
            target.write_bytes(data)
            target.chmod(0o644)
        manifests = {
            "differential-corpus.sha256": _sha_manifest({
                name + ".pdf": hashlib.sha256(data).hexdigest()
                for name, data in original_r116.items()
            }),
            "r117-corpus.sha256": _sha_manifest({
                name + ".pdf": hashlib.sha256(data).hexdigest()
                for name, data in additional.items()
            }),
        }
        for name, data in manifests.items():
            path = fixtures / name
            path.write_bytes(data)
            path.chmod(0o644)
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        args = build_container_args(
            builder_id, fix_directory, prototype_directory, fixtures, output,
            docker=docker,
        )
        if args[-1] != "/prototypes/build_sanitized_poppler.sh":
            raise ValueError("Unexpected research builder entrypoint")
        args[-1] = SCRIPT
        try:
            result = runner(
                args, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Isolated source reachability did not finish") from exc
        if (result.returncode != 0 or not result.stdout
                or len(result.stdout) > 300 * 1024
                or result.stdout.strip().splitlines()[-1] != EXPECTED_CONTAINER_DONE):
            raise ValueError("Isolated source reachability evidence incomplete")
        # Recheck all existing R1.16 real-PDF adversarial results.
        parser = read_instrumented_results(output)
        previous = verify_expected_parser_differentials(parser)
        splash = verify_splash_method_cases(output)
        jbig2 = verify_jbig2_early_rejection(output)
        type42 = verify_synthetic_true_type(output)
    return {
        "status": "source_method_reachability_research_only",
        "base_source_version": attestation["base_source_version"],
        "builder_image_id": builder_id,
        "source_sha256": attestation["prototype_source_sha256"],
        "research_patch_sha256": attestation["research_patch_sha256"],
        "new_pdf_corpus_sha256": additional_corpus_sha256(),
        "previous_parser_checks": previous,
        "actual_splash_method_checks": splash,
        "jbig2_invalid_page_checks": jbig2,
        "type42_checks": type42,
        "sanitizers": ["address", "undefined"],
        "leak_detection_performed": False,
        "all_three_cve_paths_verified": False,
        "cve_remediation_claimed": False,
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
        report = inspect_reachability(
            sources, fixes, prototypes, builder_id=args.builder_image_id,
            fix_directory=args.fix_directory,
            prototype_directory=args.prototype_directory,
        )
    except (ValueError, OSError, TypeError, UnicodeError, KeyError):
        print(json.dumps({
            "status": "error",
            "reason": "poppler_r117_source_reachability_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
