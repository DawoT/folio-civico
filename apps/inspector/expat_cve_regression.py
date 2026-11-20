"""Bounded, offline Expat regression probes with strictly blocked release decision.

R1.25 distinguishes limited runtime behavior tests from an exploit-complete
proof of a CVE fix. No VEX, suppression, classification or release permission.
Probes run *inside* the pinned image without network, capabilities or writes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import quote

IMAGE = "folio-civico-inspector:nonprivileged-experiment"
PACKAGE_VERSION = "2.10.0-1+folio1"
SOURCE_SHA = "b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f"
PATCH_SHA = "0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3"
EXPECTED_CVES = {
    "CVE-2026-113351": "HIGH",
    "CVE-2026-115506": "HIGH",
    "CVE-2026-117610": "HIGH",
    "CVE-2026-118370": "HIGH",
    "CVE-2026-124317": "UNKNOWN",
    "CVE-2026-128241": "UNKNOWN",
}
# Additional Trivy record: not covered by the Expat 2.10.0 security release.
# Expat upstream has no fix for this 2025 CVE at this cut.
EXPECTED_MEDIUM = {"CVE-2025-66382": "MEDIUM"}
PROBE_STATES = {
    "CVE-2026-113351": "parser_reset_reused_bounded",
    "CVE-2026-115506": "limited_amplification_rejected",
    "CVE-2026-117610": "empty_external_subparser_safe",
    "CVE-2026-118370": "not_exercised_requires_gigabyte_input",
}
IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{64}$")
MAX_INPUT_BYTES = 100_000
MAX_MILLISECONDS = 15_000
# XML_ERROR_AMPLIFICATION_LIMIT_BREACH as defined by Expat's public API.
XML_ERROR_AMPLIFICATION_LIMIT_BREACH = 43


def _xml_buffer(data: bytes) -> ctypes.Array:
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("Parser probe exceeds bounded input ceiling")
    return ctypes.create_string_buffer(data)


def _parse(lib: ctypes.CDLL, parser: int, data: bytes, final: bool) -> int:
    buffer = _xml_buffer(data)
    return lib.XML_Parse(parser, buffer, len(data), int(final))


def _new_parser(lib: ctypes.CDLL) -> int:
    parser = lib.XML_ParserCreate(None)
    if not parser:
        raise ValueError("Expat parser creation failed")
    return parser


def _probe_reset(lib: ctypes.CDLL) -> None:
    """Exercise bounded reset and reuse, NOT the multi-GB DoS workload."""
    parser = _new_parser(lib)
    try:
        first = b"<r>" + (b"<item/>" * 6000) + b"</r>"
        if _parse(lib, parser, first, True) != 1:
            raise ValueError("Expat parser failed bounded first parse")
        if lib.XML_ParserReset(parser, None) != 1:
            raise ValueError("Expat reset failed")
        if _parse(lib, parser, b"<second/>", True) != 1:
            raise ValueError("Expat failed parsing after reset")
    finally:
        lib.XML_ParserFree(parser)


def _probe_amplification(lib: ctypes.CDLL) -> None:
    """Check early rejection with a deliberately low, bounded threshold.

    This is a threshold-regression check. It does not attempt the original
    unbounded entity-expansion PoC, which could consume excessive CPU/RAM.
    """
    parser = _new_parser(lib)
    try:
        if lib.XML_SetBillionLaughsAttackProtectionActivationThreshold(parser, 1) != 1:
            raise ValueError("Cannot enable low activation threshold")
        if lib.XML_SetBillionLaughsAttackProtectionMaximumAmplification(parser, 2.0) != 1:
            raise ValueError("Cannot enable strict entity expansion limit")
        small = (
            b"<!DOCTYPE d [<!ENTITY a '1234567890'>"
            b"<!ENTITY b '&a;&a;&a;&a;'>"
            b"<!ENTITY c '&b;&b;&b;&b;'>]><d>&c;</d>"
        )
        if _parse(lib, parser, small, True) != 0:
            raise ValueError("Entity expansion unexpectedly accepted")
        error = lib.XML_GetErrorCode(parser)
        description = lib.XML_ErrorString(error)
        if error != XML_ERROR_AMPLIFICATION_LIMIT_BREACH or (
            not isinstance(description, bytes) or b"amplification" not in description.lower()
        ):
            raise ValueError("Expat rejected entity input for an unrelated reason")
    finally:
        lib.XML_ParserFree(parser)


def _probe_empty_external(lib: ctypes.CDLL) -> None:
    """Regression for the zero-byte, non-final external-subparser path."""
    parent = _new_parser(lib)
    child = None
    try:
        child = lib.XML_ExternalEntityParserCreate(parent, None, None)
        if not child:
            raise ValueError("Expat external entity subparser unavailable")
        if _parse(lib, child, b"", False) != 1:
            raise ValueError("Empty non-final external XML parse rejected")
        if _parse(lib, child, b"", True) != 1:
            raise ValueError("Empty final external XML parse rejected")
    finally:
        if child:
            lib.XML_ParserFree(child)
        lib.XML_ParserFree(parent)


def runtime_probes() -> dict:
    """Run from the filesystem of the immutable experimental Docker image."""
    package = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", "libexpat1"],
        capture_output=True, text=True, check=True, timeout=8,
    ).stdout.strip()
    if package != PACKAGE_VERSION:
        raise ValueError("Installed Expat package version changed")
    library = Path("/lib/x86_64-linux-gnu/libexpat.so.1")
    resolved = library.resolve(strict=True)
    allowed = (Path("/lib/x86_64-linux-gnu").resolve(),
               Path("/usr/lib/x86_64-linux-gnu").resolve())
    if not any(resolved.is_relative_to(base) for base in allowed):
        raise ValueError("Expat library path escaped trusted system directory")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    lib = ctypes.CDLL(str(library))
    lib.XML_ExpatVersion.restype = ctypes.c_char_p
    if lib.XML_ExpatVersion() != b"expat_2.10.0":
        raise ValueError("Expat runtime version differs from installed package")
    lib.XML_ParserCreate.argtypes = [ctypes.c_char_p]
    lib.XML_ParserCreate.restype = ctypes.c_void_p
    lib.XML_Parse.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.c_int, ctypes.c_int]
    lib.XML_Parse.restype = ctypes.c_int
    lib.XML_ParserReset.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.XML_ParserReset.restype = ctypes.c_int
    lib.XML_ParserFree.argtypes = [ctypes.c_void_p]
    lib.XML_ParserFree.restype = None
    lib.XML_ExternalEntityParserCreate.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.XML_ExternalEntityParserCreate.restype = ctypes.c_void_p
    lib.XML_SetBillionLaughsAttackProtectionActivationThreshold.argtypes = [
        ctypes.c_void_p, ctypes.c_ulonglong,
    ]
    lib.XML_SetBillionLaughsAttackProtectionActivationThreshold.restype = ctypes.c_int
    lib.XML_SetBillionLaughsAttackProtectionMaximumAmplification.argtypes = [
        ctypes.c_void_p, ctypes.c_float,
    ]
    lib.XML_SetBillionLaughsAttackProtectionMaximumAmplification.restype = ctypes.c_int
    lib.XML_GetErrorCode.argtypes = [ctypes.c_void_p]
    lib.XML_GetErrorCode.restype = ctypes.c_int
    lib.XML_ErrorString.argtypes = [ctypes.c_int]
    lib.XML_ErrorString.restype = ctypes.c_char_p

    start = time.monotonic()
    _probe_reset(lib)
    _probe_amplification(lib)
    _probe_empty_external(lib)
    if (time.monotonic() - start) * 1000 > MAX_MILLISECONDS:
        raise ValueError("Safe regression probes exceeded execution budget")
    return {
        "status": "bounded_probes_passed_not_release",
        "engine_version": "expat_2.10.0",
        "package_version": package,
        "libexpat_sha256": digest,
        "cve_probes": dict(PROBE_STATES),
        "max_input_bytes": MAX_INPUT_BYTES,
        "max_milliseconds": MAX_MILLISECONDS,
        "release_authorized": False,
        "vex": "not_issued",
    }


def verify_probe_evidence(
    scan: dict, sbom: dict, native: dict, probes: dict, image_id: str,
) -> dict:
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise ValueError("Pinned immutable Docker image ID is required")
    if (not isinstance(scan, dict)
            or scan.get("ArtifactName") != IMAGE
            or scan.get("ArtifactType") != "container_image"):
        raise ValueError("Trivy scan image identity mismatch")
    items = scan.get("Results")
    if not isinstance(items, list) or not items or not any(
        isinstance(s, dict) and s.get("Type") == "debian" for s in items
    ):
        raise ValueError("Debian scan coverage missing")
    counts = Counter()
    expat_cv_es: dict[str, str] = {}
    for section in items:
        if not isinstance(section, dict) or not isinstance(section.get("Target"), str):
            raise ValueError("Malformed vulnerability scan target")
        for item in section.get("Vulnerabilities") or []:
            if not isinstance(item, dict) or item.get("Severity") not in (
                "CRITICAL", "HIGH", "UNKNOWN", "MEDIUM", "LOW"
            ):
                raise ValueError("Malformed vulnerability record")
            if not isinstance(item.get("VulnerabilityID"), str):
                raise ValueError("Missing CVE ID")
            counts[item["Severity"]] += 1
            if item.get("PkgName") == "libexpat1":
                if item.get("InstalledVersion") != PACKAGE_VERSION:
                    raise ValueError("Expat alert version conflicts with runtime")
                if item["VulnerabilityID"] in expat_cv_es:
                    raise ValueError("Duplicate Expat alert")
                expat_cv_es[item["VulnerabilityID"]] = item["Severity"]
    if expat_cv_es != {**EXPECTED_CVES, **EXPECTED_MEDIUM}:
        raise ValueError("All seven reported Expat advisories must remain visible")
    if (not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX"
            or not isinstance(sbom.get("metadata"), dict)):
        raise ValueError("Missing CycloneDX")
    container = sbom["metadata"].get("component")
    if (not isinstance(container, dict) or container.get("name") != IMAGE
            or container.get("type") != "container" or [
                x.get("value") for x in container.get("properties", [])
                if isinstance(x, dict) and x.get("name") == "aquasecurity:trivy:ImageID"
            ] != [image_id]):
        raise ValueError("SBOM immutable image ID mismatch")
    expat_components = [
        c for c in sbom.get("components", [])
        if isinstance(c, dict) and c.get("name") == "libexpat1"
    ]
    if len(expat_components) != 1 or (
        expat_components[0].get("version") != PACKAGE_VERSION
        or not isinstance(expat_components[0].get("purl"), str)
        or not expat_components[0]["purl"].startswith(
            "pkg:deb/debian/libexpat1@" + quote(PACKAGE_VERSION, safe="") + "?"
        )
    ):
        raise ValueError("Expat CycloneDX package identity mismatch")
    if not isinstance(native, dict) or any((
        native.get("source") != "folio-expat-local-provenance-v1",
        native.get("package") != "libexpat1",
        native.get("package_version") != PACKAGE_VERSION,
        native.get("runtime_version") != "expat_2.10.0",
        native.get("source_sha256") != SOURCE_SHA,
        native.get("patch_sha256") != PATCH_SHA,
        native.get("native_cve_coverage") != "unassessed",
        native.get("xmlwf_present") is not False,
    )):
        raise ValueError("Unverified source/patch/native provenance")
    if not isinstance(probes, dict) or (
        probes.get("status") != "bounded_probes_passed_not_release"
        or probes.get("engine_version") != native["runtime_version"]
        or probes.get("package_version") != PACKAGE_VERSION
        or probes.get("cve_probes") != PROBE_STATES
        or probes.get("max_input_bytes") != MAX_INPUT_BYTES
        or probes.get("max_milliseconds") != MAX_MILLISECONDS
        or probes.get("release_authorized") is not False
        or probes.get("vex") != "not_issued"
        or probes.get("libexpat_sha256") != native.get("library_sha256")
        or not isinstance(probes.get("libexpat_sha256"), str)
        or not SHA.fullmatch(probes["libexpat_sha256"])
    ):
        raise ValueError("Incomplete or mismatched bounded regression evidence")
    return {
        "status": "expat_bounded_probes_release_blocked",
        "release_authorized": False,
        "scanner_gate": "blocked",
        "native_cve_coverage": "unassessed",
        "vex": "not_issued",
        "image_id": image_id,
        "expat_high_still_reported": 4,
        "expat_unknown_still_reported": 2,
        "expat_medium_still_reported": 1,
        "bounded_runtime_probes_passed": 3,
        "unexercised_large_attribute_overflow": True,
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "unknown": counts["UNKNOWN"],
        "libexpat_sha256": probes["libexpat_sha256"],
        "source_sha256": SOURCE_SHA,
        "patch_sha256": PATCH_SHA,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe", action="store_true")
    mode.add_argument("--verify", action="store_true")
    for flag in ("scan","sbom","native","probes"):
        parser.add_argument("--"+flag, type=Path)
    parser.add_argument("--image-id")
    args = parser.parse_args()
    try:
        if args.probe:
            print(json.dumps(runtime_probes(), sort_keys=True))
            return 0
        if not all((args.scan,args.sbom,args.native,args.probes,args.image_id)):
            raise ValueError("Missing exact scanner and runtime evidence")
        result = verify_probe_evidence(
            json.loads(args.scan.read_text(encoding="utf-8")),
            json.loads(args.sbom.read_text(encoding="utf-8")),
            json.loads(args.native.read_text(encoding="utf-8")),
            json.loads(args.probes.read_text(encoding="utf-8")),
            args.image_id,
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "error",
                          "reason": "expat_bounded_regression_evidence_invalid"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    # The official gate retains all reported advisories. Never return 0.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
