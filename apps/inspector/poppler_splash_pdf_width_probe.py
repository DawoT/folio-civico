"""R1.31: instrumented PDF-to-Splash width experiment on pinned Debian Poppler.

This probes whether a synthetic /MediaBox width can reach the previously
reproduced constructor overflow. The PDF corpus is intentionally pathological;
a constructor harness is NOT a substitute. The report never authorizes release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

from poppler_adversarial_differential import _read_bounded_text
from poppler_isolated_sanitizer import IMAGE_ID_PATTERN, _sha_manifest
from poppler_splash_pdf_width_corpus import EXPECTED_PDF_SHA256, EXTREME_WIDTH, pdf_corpus

VERSION = "25.03.0-5+deb13u4"
SCRIPT = "/prototypes/run_splash_pdf_width_probe.sh"
RUNNER_SHA256 = "b534efee0a9e7807ed52ee73a668400d774fe937ab900b2f8d916c1ee2ed7397"
DONE = "r131-synthetic-pdf-width-research-complete"
TIMEOUT_SECONDS = 590
OVERFLOW = (
    "runtime error: signed integer overflow: "
    "536870919 * 4 cannot be represented in type 'int'"
)
SOURCE_SHA256 = {
    "splash/Splash.cc": "dbf3dcafa042348499ccefba4dd586979b7080ffa7064901a7ecebfc4c9fe27c",
    "poppler/SplashOutputDev.cc": "f551d09a1dce5dda5787cc66305714259a0ba24766a765cbbcd9af27cc0cd741",
    "splash/SplashBitmap.cc": "206d9f4a6e5bb9054e7ef769d3b0fa3e9332b0f2c65ba062fe40f922d80ef7f0",
}
CASE_NAMES = (
    "wide_metadata", "normal_noaa", "normal_aa",
    "scaled_wide_aa", "wide_noaa", "wide_aa", "wide_gray_aa",
)


def check_runner(path: Path) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 16 * 1024:
        raise ValueError("Missing or untrusted research runner")
    script_bytes = path.read_bytes()
    if hashlib.sha256(script_bytes).hexdigest() != RUNNER_SHA256:
        raise ValueError("PDF width research runner SHA-256 mismatch")
    script = script_bytes.decode("utf-8", errors="strict")
    for expected in (
        VERSION, *SOURCE_SHA256.values(), "-fsanitize=address,undefined",
        "-fno-sanitize=vptr", "-DBUILD_SHARED_LIBS=OFF",
        "-DENABLE_UTILS=ON", "pdftoppm", "pdfinfo",
        "timeout --signal=TERM --kill-after=2s 12s",
        "wide_aa", "wide_noaa", "wide_gray_aa", "scaled_wide_aa", "/dev/null",
    ):
        if expected not in script:
            raise ValueError("Unexpected source PDF research contract")
    for forbidden in ("docker push", "docker tag", "wrangler deploy", "curl ", "wget "):
        if forbidden in script:
            raise ValueError("Forbidden command in PDF research runner")


def build_args(
    image_id: str, prototypes: Path, fixtures: Path, results: Path,
    *, docker: str = "docker",
) -> list[str]:
    if not IMAGE_ID_PATTERN.fullmatch(image_id):
        raise ValueError("Expected content-addressed, local builder image")
    for directory in (prototypes, fixtures, results):
        if (not directory.is_dir() or directory.is_symlink()
                or any(c in str(directory) for c in (",", "\n", "\r"))):
            raise ValueError("Untrusted research mount")
    argv = [
        docker, "run", "--rm", "--pull", "never", "--network", "none",
        "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--cpus", "2", "--memory", "6g",
        "--memory-swap", "6g",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=3g,mode=1777",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
    ]
    for directory, target in (
        (prototypes, "/prototypes"), (fixtures, "/fixtures"), (results, "/results"),
    ):
        suffix = ",readonly" if target != "/results" else ""
        argv.extend([
            "--mount",
            f"type=bind,source={directory.resolve(strict=True)},target={target}{suffix}",
        ])
    return argv + ["--entrypoint", "/bin/bash", image_id, SCRIPT]


def _process(root: Path, name: str) -> tuple[int, str, str]:
    if name not in CASE_NAMES:
        raise ValueError("Unknown research process")
    stem = root / name
    raw_code = _read_bounded_text(Path(str(stem) + ".exit"), 8).strip()
    if not re.fullmatch(r"[0-9]{1,3}", raw_code) or int(raw_code) > 255:
        raise ValueError("Malformed PDF process exit code")
    stdout = _read_bounded_text(Path(str(stem) + ".stdout"), 8192)
    stderr = _read_bounded_text(Path(str(stem) + ".stderr"), 16384)
    if int(raw_code) > 128 and int(raw_code) != 124:
        raise ValueError("PDF research process crashed or killed")
    return int(raw_code), stdout, stderr


def _bitmap(root: Path, name: str, size: str) -> None:
    path = root / f"{name}.pbm"
    if not path.is_file() or path.is_symlink():
        raise ValueError("Missing or symlinked PBM control")
    width, height = (int(value) for value in size.split())
    header = f"P4\n{size}\n".encode("ascii")
    # P4 stores exactly ceil(width / 8) bytes per raster row.
    # A valid header without its pixel bytes is not evidence of rendering.
    expected_length = len(header) + ((width + 7) // 8) * height
    if expected_length >= 65536 or path.stat().st_size != expected_length:
        raise ValueError("Incomplete or oversized PBM control")
    if not path.read_bytes().startswith(header):
        raise ValueError("Unexpected rendered PDF dimensions")


def _no_sanitizer(stderr: str) -> bool:
    return not any(needle in stderr for needle in (
        "runtime error:", "AddressSanitizer", "UndefinedBehaviorSanitizer",
    ))


def verify_results(root: Path) -> dict:
    records = {name: _process(root, name) for name in CASE_NAMES}
    statuses = {name: code for name, (code, _, _) in records.items()}
    for name in ("normal_noaa", "normal_aa"):
        code, stdout, stderr = records[name]
        if code != 0 or stdout != "" or stderr != "":
            raise ValueError("Ordinary PDF raster control did not pass cleanly")
        _bitmap(root, name, "8 1")

    metadata_code, metadata, metadata_stderr = records["wide_metadata"]
    if not _no_sanitizer(metadata_stderr):
        raise ValueError("PDF metadata parser sanitizer failure")
    admitted = False
    if metadata_code == 0:
        match = re.search(
            r"^Page size:\s+([0-9.eE+-]+)\s+x\s+([0-9.eE+-]+)\s+pts\b",
            metadata, flags=re.MULTILINE,
        )
        if not match or not re.search(r"^Pages:\s+1\s*$", metadata, re.M):
            raise ValueError("PDF metadata did not identify one page and size")
        measured_width, measured_height = map(float, match.groups())
        admitted = (
            math.isfinite(measured_width) and
            math.isclose(measured_width, EXTREME_WIDTH, rel_tol=1e-5) and
            math.isclose(measured_height, 1, rel_tol=1e-5)
        )
    elif metadata_code not in (1, 2, 3, 99, 124):
        raise ValueError("Unrecognized PDF metadata process status")

    scaled_code, scaled_stdout, scaled_stderr = records["scaled_wide_aa"]
    if not _no_sanitizer(scaled_stderr):
        raise ValueError("Scaled PDF renderer sanitizer failure")
    scaled_render_succeeded = scaled_code == 0
    if not scaled_render_succeeded or scaled_stdout != "":
        raise ValueError("Scaled PDF raster control did not complete")
    _bitmap(root, "scaled_wide_aa", "32 1")

    wide_noaa_code, wide_noaa_stdout, wide_noaa_stderr = records["wide_noaa"]
    if (wide_noaa_code != 0 or wide_noaa_stdout != ""
            or not _no_sanitizer(wide_noaa_stderr)):
        raise ValueError("Wide no-AA PDF raster control did not complete")

    # SplashOutputDev::setVectorAntialias disables AA for Mono1, even if
    # the command line requests it. This mode is a *negative* control.
    mono_code, mono_stdout, mono_stderr = records["wide_aa"]
    if mono_code != 0 or mono_stdout != "" or mono_stderr != "":
        raise ValueError("Mono1 raster did not preserve its no-vector-AA guard")

    wide_aa_code, wide_aa_stdout, wide_aa_stderr = records["wide_gray_aa"]
    diagnostic = (
        rf"/src/poppler-25\.03\.0/splash/Splash\.cc:1454:\d+: "
        + re.escape(OVERFLOW) + r"\n?"
    )
    exact_overflow = (
        wide_aa_code == 1 and wide_aa_stdout == ""
        and re.fullmatch(diagnostic, wide_aa_stderr) is not None
    )
    if (not exact_overflow and (
            wide_aa_stdout != "" or not _no_sanitizer(wide_aa_stderr))):
        raise ValueError("Unexpected or counterfeit sanitizer evidence")
    if exact_overflow and not admitted:
        raise ValueError("Constructor overflow without PDF dimension admission")
    return {
        "process_exit_codes": statuses,
        "ordinary_pdf_controls_passed": True,
        "mono1_vector_antialias_disabled_by_outputdev": True,
        "synthetic_extreme_pdf_page_metadata_admitted": admitted,
        "scaled_extreme_pdf_raster_succeeded": scaled_render_succeeded,
        "pdf_parser_to_splash_constructor_ubsan_observed": exact_overflow,
        "renderer_reachability_verified": exact_overflow,
        "pdf_parser_reproducer_verified": exact_overflow,
        "source_binary_equivalence_to_runtime_verified": False,
        "cve_remediation_claimed": False,
        "release_authorized": False,
    }


def inspect_pdf_width(
    *, builder_id: str, prototype_directory: Path,
    runner: Callable = subprocess.run,
) -> dict:
    if (not prototype_directory.is_dir() or prototype_directory.is_symlink()
            or any(c in str(prototype_directory) for c in (",", "\n", "\r"))):
        raise ValueError("Untrusted runner directory")
    check_runner(prototype_directory / Path(SCRIPT).name)
    corpus = pdf_corpus()
    with tempfile.TemporaryDirectory(prefix="folio-r131-pdf-width-") as tmp:
        root = Path(tmp)
        fixtures, results = root / "fixtures", root / "results"
        fixtures.mkdir(mode=0o755)
        results.mkdir(mode=0o777)
        results.chmod(0o777)
        for name, pdf in corpus.items():
            fixture = fixtures / f"{name}.pdf"
            fixture.write_bytes(pdf)
            fixture.chmod(0o644)
        manifest = _sha_manifest({
            f"{name}.pdf": sha for name, sha in EXPECTED_PDF_SHA256.items()
        })
        (fixtures / "r131-corpus.sha256").write_bytes(manifest)
        (fixtures / "r131-corpus.sha256").chmod(0o644)
        argv = build_args(builder_id, prototype_directory, fixtures, results)
        try:
            completed = runner(
                argv, capture_output=True, text=True,
                timeout=TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("No complete isolated PDF-to-Splash experiment") from exc
        if (completed.returncode != 0 or not completed.stdout
                or len(completed.stdout) > 400_000
                or completed.stdout.strip().splitlines()[-1] != DONE):
            raise ValueError("Instrumented Debian Poppler PDF build failed")
        details = verify_results(results)
    return {
        "status": ("research_pdf_to_splash_constructor_ubsan"
                   if details["renderer_reachability_verified"]
                   else "research_pdf_width_reachability_inconclusive"),
        "debian_poppler_source_version": VERSION,
        "debian_source_sha256": SOURCE_SHA256,
        "research_runner_sha256": RUNNER_SHA256,
        "synthetic_pdf_sha256": EXPECTED_PDF_SHA256,
        "builder_image_id": builder_id,
        "asan_ubsan_instrumented_pdf_parser": True,
        "experimental_result": details,
        "source_binary_equivalence_to_runtime_verified": False,
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
        report = inspect_pdf_width(
            builder_id=args.builder_image_id,
            prototype_directory=args.prototype_directory,
        )
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        print(json.dumps({
            "status": "error",
            "reason": "splash_pdf_width_instrumented_research_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
