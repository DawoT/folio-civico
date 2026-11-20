"""R1.14: isolated ASan/UBSan build of Poppler research source, not a release.

The operator builds the existing Poppler builder stage locally and supplies its
content-addressed Docker image ID plus the official R1.11/R1.12 artifacts.
The runner NEVER builds/changes a runtime image, changes CVE states, publishes
OCI, accesses the network inside the test container or uses personal PDFs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from fixtures import _pdf, _stream, malformed_pdf, native_pdf, scanned_pdf
from poppler_backport_feasibility import FIX_PATCH_SHA256
from poppler_semantic_research import (
    CHANGED_PATHS, DIRECT_FIXES, RESEARCH_FILENAMES, RESEARCH_PROTOTYPES,
    inspect_semantic_prototypes,
)
from poppler_source_patch_probe import ARCHIVE_NAMES, CVE_SOURCE_PATHS
from smoke_real_engines import parse_pgm, require_visible_synthetic_ink

TIMEOUT_SECONDS = 480
IMAGE_ID_PATTERN = re.compile(r"sha256:[a-f0-9]{64}\Z")
ALLOWED_BINARY_RESULTS = frozenset(("native", "scanned", "clipped", "sampled32"))


def clipped_pdf() -> bytes:
    """Synthetic non-rectangular vector clipping path, no institutional text."""
    content = (
        b"q\n60 60 m\n500 75 l\n310 710 l\nh\nW n\n"
        b"BT\n/F1 24 Tf\n100 450 Td\n(OBRA 2026) Tj\nET\nQ\n"
    )
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"),
        _stream(content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ])


def sampled_32bit_pdf() -> bytes:
    """Sampled Type 0 PDF function with 32-bit/component inputs."""
    payload = b"\x00" * 12 + b"\xff" * 12
    function = _stream(
        payload,
        b"/FunctionType 0 /Domain [0 1] /Range [0 1 0 1 0 1] "
        b"/Size [2] /BitsPerSample 32 /Order 1 "
        b"/Encode [0 1] /Decode [0 1 0 1 0 1]",
    )
    return _pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Contents 4 0 R /Resources << /Shading << /Sh1 5 0 R >> >> >>"),
        _stream(b"q\n/Sh1 sh\nQ\n"),
        (b"<< /ShadingType 2 /ColorSpace /DeviceRGB "
         b"/Coords [0 0 612 0] /Domain [0 1] "
         b"/Function 6 0 R /Extend [true true] >>"),
        function,
    ])


def read_artifacts(
    source_directory: Path, fix_directory: Path, prototype_directory: Path,
) -> tuple[dict[str, bytes], dict[str, bytes], dict[str, bytes]]:
    def read_checked(directory: Path, filenames: dict[str, str], limit: int) -> dict[str, bytes]:
        values = {}
        for key, filename in filenames.items():
            path = directory / filename
            if (not path.is_file() or path.is_symlink()
                    or not 0 < path.stat().st_size <= limit):
                raise ValueError("Missing, symlinked or oversized research input")
            values[key] = path.read_bytes()
        return values

    sources = read_checked(
        source_directory, {name: name for name in ARCHIVE_NAMES.values()},
        8 * 1024 * 1024,
    )
    fixes = read_checked(
        fix_directory, {name: name + ".patch" for name in FIX_PATCH_SHA256}, 64 * 1024,
    )
    research = read_checked(prototype_directory, RESEARCH_FILENAMES, 64 * 1024)
    return sources, fixes, research


def _sha_manifest(values: dict[str, str]) -> bytes:
    if not values or any(
        not re.fullmatch(r"[a-f0-9]{64}", digest)
        or name.startswith("/") or ".." in Path(name).parts
        or "\n" in name or " " in name
        for name, digest in values.items()
    ):
        raise ValueError("Unsafe source hash manifest")
    return "".join(
        f"{digest}  {name}\n" for name, digest in sorted(values.items())
    ).encode("ascii")


def create_fixture_files(directory: Path, report: dict) -> None:
    directory.mkdir(mode=0o755, exist_ok=True)
    inputs = {
        "native.pdf": native_pdf(),
        "scanned.pdf": scanned_pdf(),
        "clipped.pdf": clipped_pdf(),
        "sampled32.pdf": sampled_32bit_pdf(),
        "truncated.pdf": malformed_pdf(),
    }
    expected_baseline = report["baseline_sha256"]
    expected_modified = report["prototype_source_sha256"]
    manifests = {
        "baseline.sha256": _sha_manifest(expected_baseline),
        "patched.sha256": _sha_manifest(expected_modified),
        "direct-patches.sha256": _sha_manifest({
            cve + ".patch": FIX_PATCH_SHA256[cve] for cve in DIRECT_FIXES
        }),
        "research-patches.sha256": _sha_manifest({
            RESEARCH_FILENAMES[cve]: RESEARCH_PROTOTYPES[cve]
            for cve in RESEARCH_PROTOTYPES
        }),
    }
    for name, payload in {**inputs, **manifests}.items():
        path = directory / name
        path.write_bytes(payload)
        path.chmod(0o644)


def build_container_args(
    builder_id: str, fix_directory: Path, prototype_directory: Path,
    fixtures: Path, output: Path, *, docker: str = "docker",
) -> list[str]:
    if not IMAGE_ID_PATTERN.fullmatch(builder_id):
        raise ValueError("Builder must be a content-addressed local Docker image")
    proposed = [
        (fix_directory, "/fixes", True),
        (prototype_directory, "/prototypes", True),
        (fixtures, "/fixtures", True),
        (output, "/results", False),
    ]
    for host, _, _ in proposed:
        if (not host.is_dir() or host.is_symlink()
                or any(symbol in str(host) for symbol in (",", "\\n", "\\r"))):
            raise ValueError("Untrusted container mount")
    mounts = [(host.resolve(strict=True), target, readonly)
              for host, target, readonly in proposed]
    command = [
        docker, "run", "--rm", "--pull", "never", "--network", "none",
        "--read-only", "--user", "65534:65534",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--cpus", "2",
        "--memory", "6g", "--memory-swap", "6g",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=3g,mode=1777",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
    ]
    for host, target, read_only in mounts:
        flag = ",readonly" if read_only else ""
        command += ["--mount", f"type=bind,source={host},target={target}{flag}"]
    return command + [
        "--entrypoint", "/bin/bash", builder_id,
        "/prototypes/build_sanitized_poppler.sh",
    ]


def inspect_results(output: Path) -> dict:
    artifacts = {}
    for name in sorted(ALLOWED_BINARY_RESULTS):
        raster = output / (name + ".pgm")
        if (not raster.is_file() or raster.is_symlink()
                or raster.stat().st_size > 8 * 1024 * 1024 + 128):
            raise ValueError("Expected synthetic raster missing or oversized")
        width, height, pixels = parse_pgm(raster.read_bytes())
        if name != "sampled32":
            require_visible_synthetic_ink((width, height, pixels))
        else:
            # A full-page shading must not silently turn into an all-white page.
            if sum(byte < 230 for byte in pixels) < 64:
                raise ValueError("32-bit sampled shading did not render")
        artifacts[name] = {
            "width": width, "height": height,
            "ink_pixels": sum(byte < 230 for byte in pixels),
            "raster_sha256": hashlib.sha256(pixels).hexdigest(),
        }
    for name in ("native.txt", "scanned.txt"):
        file = output / name
        if (not file.is_file() or file.is_symlink()
                or file.stat().st_size > 128 * 1024):
            raise ValueError("Synthetic output text unavailable or untrusted")
    text = (output / "native.txt").read_text("utf-8", errors="strict")
    if "EXPEDIENTE OBRA 2026" not in text:
        raise ValueError("Native synthetic text was lost")
    scanned = (output / "scanned.txt").read_text("utf-8", errors="strict")
    if scanned.strip():
        raise ValueError("Image-only synthetic PDF acquired fake text layer")
    return artifacts



def build_baseline_args(
    builder_id: str, fixtures: Path, baseline: Path, *, docker: str = "docker",
) -> list[str]:
    """Run the already-installed UNPATCHED builder tools as a fidelity control."""
    if not IMAGE_ID_PATTERN.fullmatch(builder_id):
        raise ValueError("Baseline builder image must be content-addressed")
    for directory in (fixtures, baseline):
        if (not directory.is_dir() or directory.is_symlink()
                or any(symbol in str(directory) for symbol in (",", "\\n", "\\r"))):
            raise ValueError("Unsafe baseline mount")
    script = (
        "set -euo pipefail\n"
        "export LD_LIBRARY_PATH=/opt/folio-poppler/lib\n"
        "for sample in native scanned clipped sampled32; do\n"
        "  /opt/folio-poppler/bin/pdftoppm -f 1 -l 1 -singlefile "
        "-gray -scale-to 850 /fixtures/$sample.pdf /baseline/$sample "
        ">/baseline/$sample.log 2>&1\n"
        "done\n"
        "/opt/folio-poppler/bin/pdftotext -enc UTF-8 "
        "/fixtures/native.pdf /baseline/native.txt\n"
        "/opt/folio-poppler/bin/pdftotext -enc UTF-8 "
        "/fixtures/scanned.pdf /baseline/scanned.txt\n"
    )
    return [
        docker, "run", "--rm", "--pull", "never", "--network", "none",
        "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--cpus", "1", "--memory", "2g",
        "--mount", f"type=bind,source={fixtures.resolve(strict=True)},target=/fixtures,readonly",
        "--mount", f"type=bind,source={baseline.resolve(strict=True)},target=/baseline",
        "--entrypoint", "/bin/bash", builder_id, "-c", script,
    ]


def compare_synthetic_parity(baseline: Path, patched: Path) -> dict[str, bool]:
    original = inspect_results(baseline)
    rebuilt = inspect_results(patched)
    for name in ALLOWED_BINARY_RESULTS:
        if (original[name]["raster_sha256"] != rebuilt[name]["raster_sha256"]
                or original[name]["width"] != rebuilt[name]["width"]
                or original[name]["height"] != rebuilt[name]["height"]):
            raise ValueError("Synthetic raster drift in sanitized Poppler")
    for filename in ("native.txt", "scanned.txt"):
        original_file, patched_file = baseline / filename, patched / filename
        if original_file.is_symlink() or patched_file.is_symlink():
            raise ValueError("Synthetic text comparison links are unsafe")
        if original_file.read_bytes() != patched_file.read_bytes():
            raise ValueError("Synthetic PDF text changed after research patches")
    return {"four_rasters_pixel_identical": True, "two_text_outputs_identical": True}


def inspect_isolated_build(
    sources: dict[str, bytes], fixes: dict[str, bytes],
    prototypes: dict[str, bytes], *,
    builder_id: str,
    prototype_directory: Path,
    fix_directory: Path,
    docker: str = "docker",
    runner=subprocess.run,
) -> dict:
    # R1.13's strict verified source/patch procedure is a prerequisite,
    # never a replacement for compilation or the separate release gate.
    attestation = inspect_semantic_prototypes(sources, fixes, prototypes)
    with tempfile.TemporaryDirectory(prefix="folio-r114-isolated-") as temp:
        root = Path(temp)
        fixtures = root / "fixtures"
        outputs = root / "output"
        create_fixture_files(fixtures, attestation)
        outputs.mkdir(mode=0o777)
        outputs.chmod(0o777)  # synthetic content only, rootless container writer
        args = build_container_args(
            builder_id, fix_directory, prototype_directory,
            fixtures, outputs, docker=docker,
        )
        try:
            completed = runner(
                args, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Sanitizer container did not complete") from error
        if (completed.returncode != 0
                or re.search(r"(?i)(ERROR: AddressSanitizer|AddressSanitizer:DEADLYSIGNAL|UndefinedBehaviorSanitizer|runtime error:)",
                             completed.stdout + completed.stderr)):
            raise ValueError("Sanitizer build or synthetic PDF regression failed")
        final = completed.stdout.strip().splitlines()[-1]
        try:
            declared = json.loads(final)
        except (IndexError, json.JSONDecodeError) as error:
            raise ValueError("Sanitizer report missing") from error
        if (declared.get("build") != "asan_ubsan_complete"
                or declared.get("native_pdf") != "parsed"
                or declared.get("scan_pdf") != "parsed"
                or declared.get("clip_pdf") != "rendered"
                or declared.get("sampled_function_32bit") != "rendered"
                or declared.get("pdfinfo_sanitized_link_verified") is not False
                or declared.get("release_authorized") is not False
                or type(declared.get("malformed_exit")) is not int
                or not 0 <= declared["malformed_exit"] < 128):
            raise ValueError("Incomplete sanitizer declaration")
        results = inspect_results(outputs)
        baseline = root / "baseline"
        baseline.mkdir(mode=0o777)
        baseline.chmod(0o777)
        try:
            comparison = runner(
                build_baseline_args(builder_id, fixtures, baseline, docker=docker),
                capture_output=True, text=True, timeout=120, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("Pinned Poppler baseline regression unavailable") from error
        if comparison.returncode != 0:
            raise ValueError("Pinned Poppler baseline regression failed")
        parity = compare_synthetic_parity(baseline, outputs)
    return {
        "status": "research_sanitizer_build_completed",
        "base_source_version": attestation["base_source_version"],
        "builder_image_id": builder_id,
        "source_sha256": attestation["prototype_source_sha256"],
        "research_prototype_sha256": attestation["research_patch_sha256"],
        "sanitizers": ["address", "undefined"],
        "asan_leak_detection_enabled": False,
        "synthetic_fixtures": results,
        "baseline_parity": parity,
        "malformed_exit": declared["malformed_exit"],
        "research_binary_compiled": True,
        "pdfinfo_sanitized_link_verified": False,
        "source_binary_equivalence_to_runtime_verified": False,
        "cve_fixes_verified": False,
        "image_release_authorized": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-directory", type=Path, required=True)
    parser.add_argument("--fix-directory", type=Path, required=True)
    parser.add_argument("--builder-image-id", required=True)
    parser.add_argument(
        "--prototype-directory", type=Path,
        default=Path(__file__).resolve().parent / "research_patches",
    )
    args = parser.parse_args()
    try:
        sources, fixes, research = read_artifacts(
            args.source_directory, args.fix_directory, args.prototype_directory,
        )
        report = inspect_isolated_build(
            sources, fixes, research, builder_id=args.builder_image_id,
            prototype_directory=args.prototype_directory,
            fix_directory=args.fix_directory,
        )
    except (ValueError, OSError, TypeError, UnicodeError):
        print(json.dumps({
            "status": "error",
            "reason": "isolated_poppler_sanitizer_evidence_incomplete",
            "release_authorized": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
