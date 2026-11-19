"""Bounded, read-only source-built OCR/PDF CVE review ledger.

These are selected open issues in the *Debian trixie source-package trackers*
as observed on 2026-11-19. They are NOT an exhaustive upstream advisory feed,
NOT proof that the custom source binary is affected, and never a VEX.
Binding each row to the strict offline ELF/model provenance inventory makes the
review backlog attributable to a particular local image and OCR model set. The release gate
is evaluated separately and must stay blocked for unassessed native code.
"""
from __future__ import annotations

import re

from audit_image import verify_native_source_inventory
from poppler_source_patch_probe import CVE_SOURCE_PATHS

SNAPSHOT_DATE = "2026-11-19"
SOURCE_CVES: dict[str, tuple[str, ...]] = {
    "tesseract": (
        "CVE-2026-119341", "CVE-2026-119340",
        "CVE-2026-119339", "CVE-2026-119338",
        "CVE-2026-88054", "CVE-2026-88053",
        "CVE-2026-88052", "CVE-2026-88051",
        "CVE-2026-88050", "CVE-2026-88049",
        "CVE-2026-88048", "CVE-2026-88047",
        "CVE-2026-73067", "CVE-2026-73066",
    ),
    "poppler": (
        "CVE-2026-107705",
        "CVE-2026-102621", "CVE-2026-102620",
        "CVE-2026-93653",
        "CVE-2026-93314", "CVE-2026-93313",
        "CVE-2026-93312", "CVE-2026-93311",
        "CVE-2019-9545", "CVE-2019-9543",
    ),
}
EXPECTED_CVE_COUNTS = {"tesseract": 14, "poppler": 10}
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def source_cve_ledger(inventory: dict, image: str) -> dict:
    """Return selected, unassessed CVEs linked to strict native ELF identity.

    The caller must first evaluate Trivy/SBOM; this function ALSO validates
    image mode, version, required utilities and every native SHA-256. It never
    classifies an individual CVE as fixed, affected, or not affected.
    """
    verify_native_source_inventory(inventory, image)
    if (set(SOURCE_CVES) != set(EXPECTED_CVE_COUNTS)
            or set(CVE_SOURCE_PATHS) != set(SOURCE_CVES["poppler"])):
        raise ValueError("Native advisory snapshot is incomplete")
    for name, ids in SOURCE_CVES.items():
        if (not isinstance(ids, tuple) or len(ids) != EXPECTED_CVE_COUNTS[name]
                or len(set(ids)) != len(ids)
                or any(not isinstance(cve, str) or not CVE_ID.fullmatch(cve)
                       for cve in ids)):
            raise ValueError("Native CVE snapshot is incomplete or malformed")
    components = []
    for item in inventory["components"]:
        name = item["name"]
        cves = sorted(SOURCE_CVES[name])
        components.append({
            "name": name,
            "version": item["version"],
            "executable_sha256": item["executable_sha256"],
            "library_sha256": item["library_sha256"],
            "provenance_sha256": item["provenance_sha256"],
            "tool_sha256": item["tool_sha256"],
            "model_sha256": item["model_sha256"],
            "source_build_status": "unassessed",
            "tracker": "https://security-tracker.debian.org/tracker/source-package/" + name,
            "cve_count": len(cves),
            "cves": [{
                "id": cve,
                "reference": "https://security-tracker.debian.org/tracker/" + cve,
                "disposition": "individual_review_required",
                "source_binary_applicability": "unassessed",
                **({
                    "source_path": CVE_SOURCE_PATHS[cve],
                    # Verified against Debian's Trixie source tracker on
                    # SNAPSHOT_DATE; not a binary vulnerability verdict.
                    "debian_trixie_source_status": "vulnerable",
                } if name == "poppler" else {}),
            } for cve in cves],
        })
    return {
        "status": "review_required" if components else "not_applicable",
        "snapshot_date": SNAPSHOT_DATE,
        "scope": "selected_open_debian_trixie_advisories_not_exhaustive",
        "source": "official_debian_security_tracker",
        "components": components,
        "selected_cve_total": sum(row["cve_count"] for row in components),
        "complete_source_advisory_coverage": False,
        "declares_not_affected": False,
        "release_authorized": False,
    }
