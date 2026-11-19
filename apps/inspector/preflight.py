"""Fail-closed local capacity and dependency checks before Docker builds/smokes.

This script never installs packages, pulls images, deletes files or contacts the
network. Run it before a manual build to avoid filling a shared Docker host.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import re
import os
import tempfile

GIB = 1024 ** 3
MIN_BUILD_FREE_BYTES = 8 * GIB
MIN_SMOKE_FREE_BYTES = 1 * GIB
MIN_SMOKE_SCRATCH_BYTES = 128 * 1024 * 1024
MIN_AVAILABLE_RAM_BYTES = 4 * GIB
ENGINE_TOOLS = ("clamscan", "qpdf", "pdfdetach", "pdfinfo", "pdftotext",
                "pdftoppm", "tesseract")


def evaluate_requirements(mode: str, free_bytes: int,
                          available: dict[str, bool],
                          signatures_ready: bool = False,
                          available_ram_bytes: int | None = None) -> list[str]:
    """Pure deterministic readiness gate with descriptive failure codes."""
    if mode not in ("build", "smoke"):
        raise ValueError("Unknown inspection preflight mode")
    minimum = MIN_BUILD_FREE_BYTES if mode == "build" else MIN_SMOKE_FREE_BYTES
    errors = []
    if free_bytes < minimum:
        errors.append(f"insufficient_disk:need_{minimum // GIB}_GiB_free")
    if available_ram_bytes is not None and available_ram_bytes < MIN_AVAILABLE_RAM_BYTES:
        errors.append("insufficient_memory:need_4_GiB_available")
    required = ("docker",) if mode == "build" else ENGINE_TOOLS
    for name in required:
        if not available.get(name, False):
            errors.append(f"missing_engine:{name}")
    if mode == "smoke" and not signatures_ready:
        errors.append("missing_or_stale_clamav_signatures")
    return errors


def _memory_available() -> int:
    try:
        content = Path("/proc/meminfo").read_text(encoding="utf-8")
        found = re.search(r"^MemAvailable:\s*(\d+)\s+kB$", content, re.MULTILINE)
        return int(found.group(1)) * 1024 if found else 0
    except OSError:
        return 0


def _docker_root_free() -> int | None:
    try:
        # Never build in a Docker daemon reached over TCP/SSH or a remote
        # context; that could mutate resources outside the local host.
        docker_host = os.environ.get("DOCKER_HOST", "")
        if docker_host and not docker_host.startswith("unix://"):
            return None
        context = subprocess.run(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            capture_output=True, check=False, text=True, timeout=5
        )
        if context.returncode != 0 or not context.stdout.strip().startswith("unix://"):
            return None
        result = subprocess.run(
            ["docker", "info", "--format", "{{.DockerRootDir}}"],
            capture_output=True, check=False, text=True, timeout=5
        )
        root = Path(result.stdout.strip())
        if result.returncode != 0 or not root.is_absolute() or not root.is_dir():
            return None
        return shutil.disk_usage(root).free
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def inspect_host(mode: str, root: Path, database: Path) -> dict:
    """Observe only the host filesystem, RAM, Docker root and binaries."""
    free = shutil.disk_usage(root).free
    ram = _memory_available()
    relevant = ("docker",) if mode == "build" else ENGINE_TOOLS
    available = {name: shutil.which(name) is not None for name in relevant}
    signatures_ready = False
    if mode == "smoke":
        from inspector import require_fresh_signatures, ScannerUnavailable
        try:
            require_fresh_signatures(database)
            signatures_ready = True
        except (ScannerUnavailable, OSError):
            signatures_ready = False
    problems = evaluate_requirements(
        mode, free, available, signatures_ready, available_ram_bytes=ram
    )
    if mode == "smoke":
        scratch_free = shutil.disk_usage(tempfile.gettempdir()).free
        if scratch_free < MIN_SMOKE_SCRATCH_BYTES:
            problems.append("insufficient_scratch:need_128_MiB_free")
    if mode == "build" and available["docker"]:
        docker_free = _docker_root_free()
        if docker_free is None:
            problems.append("docker_daemon_or_storage_unavailable")
        elif docker_free < MIN_BUILD_FREE_BYTES:
            problems.append("insufficient_docker_storage:need_8_GiB_free")
    return {
        "mode": mode,
        "ready": not problems,
        "free_gib": round(free / GIB, 2),
        "minimum_gib": (MIN_BUILD_FREE_BYTES if mode == "build"
                        else MIN_SMOKE_FREE_BYTES) // GIB,
        "available_ram_gib": round(ram / GIB, 2),
        "minimum_available_ram_gib": 4,
        "problems": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("build", "smoke"), required=True)
    parser.add_argument("--database", type=Path, default=Path("/opt/clamdb"))
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    result = inspect_host(args.mode, args.root, args.database)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
