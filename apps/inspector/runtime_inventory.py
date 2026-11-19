"""Read-only installed-package ownership for dynamically linked PDF engines.

Executed with Python from the repository against the existing local image:
docker run --network none --read-only ... --entrypoint python3 IMAGE -c "..."
No document bytes or network resources are inspected.

Important: ldd cannot prove absence of dlopen, static linkage, plugin calls,
shell processes or exploitability. Unknown library owners stay UNKNOWN and all
Trivy findings remain blocking irrespective of this report.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

ENGINE_NAMES = (
    "clamscan", "qpdf", "pdfdetach", "pdfinfo", "pdftotext", "pdftoppm", "tesseract"
)
LIBRARY_PATH = re.compile(r"(?:=>\s*)?(/(?:usr/)?lib(?:64)?/[^\s(]+)")


def installed_owner(path: str) -> str | None:
    """Map a trusted ELF filename to its Debian package name."""
    candidates = [os.path.realpath(path), path]
    for candidate in dict.fromkeys(candidates):
        try:
            result = subprocess.run(
                ["dpkg-query", "-S", candidate],
                capture_output=True, text=True, timeout=4, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("Debian package ownership unavailable") from error
        if result.returncode == 0 and ": " in result.stdout:
            package = result.stdout.split(": ", 1)[0].split(":", 1)[0]
            if re.fullmatch(r"[a-z0-9][a-z0-9.+_-]{0,127}", package):
                return package
    return None


def inventory() -> dict:
    engines: dict[str, list[str]] = {}
    missing_ownership: dict[str, int] = {}
    for name in ENGINE_NAMES:
        path = shutil.which(name)
        if not path:
            raise RuntimeError("Mandatory scanner engine missing")
        try:
            linked = subprocess.run(
                ["ldd", path], capture_output=True, text=True,
                timeout=12, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("Could not enumerate engine linkage") from error
        if linked.returncode != 0 or "not found" in linked.stdout:
            raise RuntimeError("Required native libraries unavailable")
        owners: set[str] = set()
        unresolved = 0
        executable_owner = installed_owner(path)
        if executable_owner:
            owners.add(executable_owner)
        else:
            unresolved += 1
        for match in LIBRARY_PATH.finditer(linked.stdout):
            library_owner = installed_owner(match.group(1))
            if library_owner:
                owners.add(library_owner)
            else:
                unresolved += 1
        if not owners:
            raise RuntimeError("No Debian inventory for executable")
        engines[name] = sorted(owners)
        if unresolved:
            missing_ownership[name] = unresolved
    return {
        "source": "ldd-dpkg-query",
        "engines": engines,
        "unmapped_libraries": missing_ownership,
    }


def main() -> int:
    try:
        result = inventory()
    except (OSError, RuntimeError, ValueError):
        print(json.dumps({"status": "error", "reason": "runtime_inventory_unavailable"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
