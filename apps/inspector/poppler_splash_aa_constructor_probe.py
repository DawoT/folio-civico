"""R1.27: build original Debian Poppler with ASan/UBSan and call real Splash ctors.

Extreme-width Mono1 bitmap has an ACTUAL ~64 MiB pixel allocation and one row.
The real constructor proves a C++ arithmetic path, not PDF reachability or a fix.
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

from poppler_isolated_sanitizer import IMAGE_ID_PATTERN, _sha_manifest
from poppler_reachability_probe import read_process_output

VERSION = "25.03.0-5+deb13u4"
# SHA of original Debian-patched Splash.cc inside the immutable builder.
SOURCE_SHA256 = "dbf3dcafa042348499ccefba4dd586979b7080ffa7064901a7ecebfc4c9fe27c"
PROBE_FILENAME = "splash_aa_width_constructor_probe.cc"
PROBE_SHA256 = "ca3fb4d5e62516a99e7a87338ef11fd9d0cef3e6683c1383e6f32504635d4aea"
SCRIPT_SHA256 = "f0fdf334902ccaa9ab2e576fb98ebca8464a423a0843ae15d372da132c5e48db"
SCRIPT = "/prototypes/run_splash_aa_width_constructor.sh"
DONE = "r127-real-splash-constructors-ubsan-complete"
TIMEOUT_SECONDS = 535
CONSTRUCTORS = ("params", "screen")
SCENARIOS = ("normal_aa", "normal_noaa", "wide_noaa", "wide_aa")
EXPECTED = {
    "normal_aa": "normal_with_antialias_constructed\n",
    "normal_noaa": "normal_without_antialias_constructed\n",
    "wide_noaa": "wide_allocated_bitmap_without_antialias_constructed\n",
}
OVERFLOW = "runtime error: signed integer overflow: 536870919 * 4 cannot be represented in type 'int'"


def check_prototypes(directory: Path) -> None:
    if (
        not directory.is_dir() or directory.is_symlink()
        or any(char in str(directory) for char in (",", "\n", "\r"))
    ):
        raise ValueError("Untrusted research prototype directory")
    path = directory / PROBE_FILENAME
    script = directory / Path(SCRIPT).name
    if not path.is_file() or path.is_symlink() or not script.is_file() or script.is_symlink():
        raise ValueError("Research method prototype or runner missing")
    if path.stat().st_size > 16 * 1024 or script.stat().st_size > 32 * 1024:
        raise ValueError("Oversized source-only research input")
    if hashlib.sha256(path.read_bytes()).hexdigest() != PROBE_SHA256:
        raise ValueError("Research method prototype SHA-256 mismatch")
    # Exact runner bytes are part of the experiment's chain of custody.
    # Checking only marker strings would admit shell mutations capable of
    # manufacturing or altering the otherwise verified sanitizer artifacts.
    script_bytes = script.read_bytes()
    if hashlib.sha256(script_bytes).hexdigest() != SCRIPT_SHA256:
        raise ValueError("Research constructor shell runner SHA-256 mismatch")
    script_text = script_bytes.decode("utf-8", errors="strict")
    for required in (
        "dbf3dcafa042348499ccefba4dd586979b7080ffa7064901a7ecebfc4c9fe27c",
        "-fsanitize=address,undefined",
        "-fno-sanitize=vptr",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DENABLE_UTILS=OFF",
        "libpoppler.a",
        "splash_aa_width_constructor_probe.cc",
        "for constructor in params screen",
        "for scenario in normal_aa normal_noaa wide_noaa wide_aa",
        "timeout --signal=TERM --kill-after=2s 8s",
    ):
        if required not in script_text:
            raise ValueError("Unexpected research build script")
    for forbidden in ("docker push", "docker tag", "wrangler deploy", "curl ", "wget "):
        if forbidden in script_text:
            raise ValueError("Prohibited operation in research script")


def build_args(
    image_id: str, prototypes: Path, fixtures: Path, results: Path,
    *, docker: str = "docker",
) -> list[str]:
    if not IMAGE_ID_PATTERN.fullmatch(image_id):
        raise ValueError("Research builder must be a content-addressed image")
    for directory in (prototypes, fixtures, results):
        if (
            not directory.is_dir() or directory.is_symlink()
            or any(char in str(directory) for char in (",", "\n", "\r"))
        ):
            raise ValueError("Untrusted builder mount")
    args = [
        docker, "run", "--rm", "--pull", "never", "--network", "none",
        "--read-only", "--user", "65534:65534",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--cpus", "2", "--memory", "6g",
        "--memory-swap", "6g",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=3g,mode=1777",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
    ]
    for directory, target in (
        (prototypes, "/prototypes"),
        (fixtures, "/fixtures"),
        (results, "/results"),
    ):
        suffix = ",readonly" if target != "/results" else ""
        args += [
            "--mount", f"type=bind,source={directory.resolve(strict=True)},target={target}{suffix}",
        ]
    return args + ["--entrypoint", "/bin/bash", image_id, SCRIPT]


def verify_results(directory: Path) -> dict:
    """Require 8 actual process results, not an exit-0 marker."""
    cases = {}
    for constructor in CONSTRUCTORS:
        scenarios = {}
        for scenario in SCENARIOS:
            code, stdout, stderr = read_process_output(
                directory, constructor + "-" + scenario,
            )
            if scenario == "wide_aa":
                line = 1454 if constructor == "params" else 1476
                expected = (
                    rf"/src/poppler-25\.03\.0/splash/Splash\.cc:{line}:\d+: "
                    + re.escape(OVERFLOW)
                    + r"\n?"
                )
                okay = (
                    code == 1 and stdout == ""
                    and re.fullmatch(expected, stderr) is not None
                )
            else:
                okay = code == 0 and stdout == EXPECTED[scenario] and stderr == ""
            if not okay:
                raise ValueError("Splash constructor UBSan evidence incomplete")
            scenarios[scenario] = {
                "exit_code": code,
                "signed_integer_overflow": scenario == "wide_aa",
            }
        cases[constructor] = scenarios
    return {
        "cases": cases,
        "actual_source_constructor_overflow_in_both_overloads": True,
        "allocated_wide_bitmap_required_before_constructor": True,
        "normal_small_aa_bitmap_constructed": True,
        "no_aa_wide_allocated_bitmap_did_not_overflow": True,
        "large_bitmap_renderer_preconditions_unverified": True,
        "renderer_reachability_verified": False,
        "pdf_parser_reachability_verified": False,
    }


def inspect_constructor(
    *, builder_id: str, prototype_directory: Path,
    runner: Callable = subprocess.run,
) -> dict:
    check_prototypes(prototype_directory)
    with tempfile.TemporaryDirectory(prefix="folio-r127-splash-width-") as tmp:
        root = Path(tmp)
        fixtures, results = root / "fixtures", root / "results"
        fixtures.mkdir(mode=0o755)
        results.mkdir(mode=0o777)
        results.chmod(0o777)
        path = fixtures / "probe-source.sha256"
        path.write_bytes(_sha_manifest({PROBE_FILENAME: PROBE_SHA256}))
        path.chmod(0o644)
        argv = build_args(builder_id, prototype_directory, fixtures, results)
        try:
            result = runner(
                argv, capture_output=True, text=True,
                timeout=TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Isolated original Splash constructor run incomplete") from exc
        if (
            result.returncode != 0 or not result.stdout
            or len(result.stdout) > 350 * 1024
            or result.stdout.strip().splitlines()[-1] != DONE
        ):
            raise ValueError("Isolated full Poppler source build incomplete")
        observed = verify_results(results)
    return {
        "status": "research_real_splash_aa_width_constructor_overflow",
        "original_debian_source_version": VERSION,
        "splash_cc_sha256": SOURCE_SHA256,
        "source_method_probe_sha256": PROBE_SHA256,
        "research_runner_script_sha256": SCRIPT_SHA256,
        "builder_image_id": builder_id,
        "actual_full_static_poppler_library_compiled_with_asan_ubsan": True,
        "ubsan_vptr_instrumentation": False,
        "asan_leak_detection_performed": False,
        "constructor_cases": observed,
        "complete_splash_arithmetic_review": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "pdf_parser_reproducer_verified": False,
        "renderer_reachability_verified": False,
        "cve_remediation_claimed": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--builder-image-id", required=True)
    parser.add_argument(
        "--prototype-directory", type=Path,
        default=Path(__file__).resolve().parent / "research_patches",
    )
    args = parser.parse_args()
    try:
        observed = inspect_constructor(
            builder_id=args.builder_image_id,
            prototype_directory=args.prototype_directory,
        )
    except (ValueError, OSError, TypeError, UnicodeError, KeyError):
        print(json.dumps({
            "status": "error",
            "reason": "splash_aa_constructor_source_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(observed, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
