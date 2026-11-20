"""Static ELF exported-symbol comparison for experimental util-linux DSOs.

This is a *partial* research check, not an ABI certification, CVE fix or release
approval. Never loads any candidate ELF. Debian packages are only extracted
into a private disposable directory for readelf/nm metadata inspection.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile

LIBRARIES = {
    "libuuid1": "libuuid.so.1",
    "libblkid1": "libblkid.so.1",
    "libmount1": "libmount.so.1",
    "libsmartcols1": "libsmartcols.so.1",
    "libfdisk1": "libfdisk.so.1",
}


def _run(argv: list[str], *, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Cannot inspect candidate ELF metadata") from error
    if result.returncode != 0:
        raise ValueError("Candidate ELF metadata rejected")
    return result.stdout


def elf_surface(path: Path) -> dict:
    """Return SONAME, NEEDED and exported versioned symbols without loading ELF."""
    dynamic = _run(["readelf", "-d", str(path)])
    sonames = re.findall(r"\(SONAME\)\s+Library soname: \[([^\]]+)\]", dynamic)
    if len(sonames) != 1:
        raise ValueError("Expected exactly one ELF SONAME")
    needed = sorted(set(re.findall(
        r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic
    )))
    exported = _run([
        "nm", "-D", "--defined-only", "--with-symbol-versions", str(path)
    ])
    symbols = set()
    for line in exported.splitlines():
        tokens = line.split()
        if len(tokens) >= 3 and len(tokens[1]) == 1 and tokens[1] != "U":
            symbols.add(tokens[-1])
    if not symbols:
        raise ValueError("No versioned dynamic symbol exports found")
    return {"soname": sonames[0], "needed": needed,
            "symbols": sorted(symbols)}


def _extract(source: Path, target: Path, package: str) -> Path:
    matches = list(source.glob(package + "_*.deb"))
    if len(matches) != 1 or matches[0].is_symlink():
        raise ValueError("Exactly one matching Debian shared-library package is required")
    root = target / package
    root.mkdir(mode=0o700, parents=True)
    _run(["dpkg-deb", "-x", str(matches[0]), str(root)], timeout=45)
    return _search_soname(root, LIBRARIES[package])


def _search_soname(root: Path, soname: str) -> Path:
    for file in root.rglob("*"):
        if file.is_file() and ".so." in file.name and not file.is_symlink():
            try:
                if elf_surface(file)["soname"] == soname:
                    return file
            except ValueError:
                pass
    raise ValueError("Expected library SONAME absent")


def compare_elf_surfaces(baseline: Path, candidate: Path, *,
                         baseline_kind: str = "folio1_experimental_not_official_debian") -> dict:
    """Compare library surfaces from experimental packages; no ABI pass claim."""
    if baseline_kind not in ("folio1_experimental_not_official_debian",
                             "debian_trixie_2.41.5_signed_apt"):
        raise ValueError("Unknown ELF ABI reference provenance")
    for folder in (baseline, candidate):
        if (not folder.is_absolute() or not folder.is_dir() or folder.is_symlink()
                or folder.resolve(strict=True) != folder
                or stat.S_IMODE(folder.stat().st_mode) != 0o700):
            raise ValueError("ELF inventory must read canonical private directories")
    rows = []
    with tempfile.TemporaryDirectory(prefix="folio-r137-elf-", dir="/tmp") as tmp:
        scratch = Path(tmp)
        for name, expected_soname in LIBRARIES.items():
            prev = elf_surface(_extract(baseline, scratch / "baseline", name))
            current = elf_surface(_extract(candidate, scratch / "candidate", name))
            old = set(prev["symbols"])
            new = set(current["symbols"])
            rows.append({
                "package": name, "expected_soname": expected_soname,
                "baseline_soname": prev["soname"],
                "candidate_soname": current["soname"],
                "baseline_export_count": len(old),
                "candidate_export_count": len(new),
                "removed_exports": sorted(old - new),
                "added_exports": sorted(new - old),
                "baseline_needed": prev["needed"],
                "candidate_needed": current["needed"],
                "new_needed": sorted(set(current["needed"]) - set(prev["needed"])),
            })
    regression = any(
        row["candidate_soname"] != row["baseline_soname"]
        or row["candidate_soname"] != row["expected_soname"]
        or row["removed_exports"] or row["new_needed"] for row in rows
    )
    return {
        "status": ("experimental_static_elf_regression_release_blocked"
                   if regression else "experimental_static_elf_surface_only_release_blocked"),
        "static_elf_regression_detected": bool(regression),
        "baseline_kind": baseline_kind,
        "candidate_kind": "folio2_experimental",
        "libraries": rows,
        "static_symbol_surface_unchanged": all(
            a["candidate_soname"] == a["baseline_soname"] == a["expected_soname"]
            and not a["removed_exports"] and not a["added_exports"]
            and not a["new_needed"] for a in rows
        ),
        "debian_trixie_abi_validated": False,
        "cve_remediated": False,
        "release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-dir", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--baseline-kind", choices=(
        "folio1_experimental_not_official_debian",
        "debian_trixie_2.41.5_signed_apt",
    ), default="folio1_experimental_not_official_debian")
    args = parser.parse_args()
    try:
        report = compare_elf_surfaces(
            args.baseline_dir, args.candidate_dir,
            baseline_kind=args.baseline_kind
        )
        print(json.dumps(report, sort_keys=True))
        return 3 if report["static_elf_regression_detected"] else 2
    except (ValueError, OSError, TypeError):
        print(json.dumps({"status": "error",
                          "reason": "experimental_static_elf_inspection_failed",
                          "release_authorized": False}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
