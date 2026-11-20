"""Strict signed-Talos-native identity comparison: release ALWAYS blocked.

Verifies integrity of the ClamAV vendor artifact evidence, native runtime
bytes, and unsuppressed Trivy/CycloneDX. This is not a CVE-specific VEX.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from urllib.parse import quote

from clamav_vendor_evidence import TALOS_FINGERPRINT
from clamav_runtime_inventory import VERSION

IMAGE = "folio-civico-inspector:nonprivileged-experiment"
IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
SHA = re.compile(r"^[a-f0-9]{64}$")
CVES = (
    "CVE-2026-20213", "CVE-2026-20214", "CVE-2026-20215",
    "CVE-2026-20216", "CVE-2026-20217", "CVE-2026-20243",
    "CVE-2026-20244",
)
MEDIUM_CVES = (
    "CVE-2026-20031", "CVE-2026-20339", "CVE-2026-20345",
    "CVE-2026-20346", "CVE-2026-20347", "CVE-2026-20348",
)
NATIVE_REQUIRED = (
    "/usr/local/bin/clamscan",
    "/usr/local/sbin/clamd",
    "/usr/local/lib/libclamav.so.12.1.0",
    "/usr/local/lib/libclamav_rust.a",
)


def _signed_files(value: object) -> list[dict]:
    if not isinstance(value, list) or len(value) < 2 or len(value) > 200:
        raise ValueError("Signed native file inventory missing or unbounded")
    paths = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ValueError("Malformed signed native file entry")
        path, digest = entry["path"], entry["sha256"]
        if (not isinstance(path, str)
                or not path.startswith(("/usr/local/bin/",
                                        "/usr/local/sbin/",
                                        "/usr/local/lib/"))
                or "//" in path or "/../" in path
                or not isinstance(digest, str)
                or not SHA.fullmatch(digest)):
            raise ValueError("Malformed native ELF path or digest")
        paths.append(path)
    if paths != sorted(set(paths)):
        raise ValueError("Duplicated or unordered signed native code")
    return value


def verify_signed_vendor_evidence(
    scan: dict, sbom: dict, vendor: dict, runtime: dict, image_id: str,
) -> dict:
    if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
        raise ValueError("Immutable Docker ID required for Talos analysis")
    if (not isinstance(scan, dict) or scan.get("ArtifactName") != IMAGE
            or scan.get("ArtifactType") != "container_image"):
        raise ValueError("Scan image mismatch")
    sections = scan.get("Results")
    if (not isinstance(sections, list) or not sections or
            not any(isinstance(x, dict) and x.get("Type") == "debian"
                    for x in sections)):
        raise ValueError("Debian scanner coverage missing")
    counts = Counter()
    clam = {}
    for section in sections:
        if not isinstance(section, dict) or not isinstance(section.get("Target"), str):
            raise ValueError("Malformed scan target")
        findings = section.get("Vulnerabilities") or []
        if not isinstance(findings, list):
            raise ValueError("Malformed scanner records")
        for item in findings:
            if (not isinstance(item, dict) or
                item.get("Severity") not in
                ("CRITICAL", "HIGH", "UNKNOWN", "MEDIUM", "LOW") or
                not isinstance(item.get("VulnerabilityID"), str)):
                raise ValueError("Invalid scanner vulnerability record")
            counts[item["Severity"]] += 1
            if item.get("PkgName") == "clamav":
                if item.get("InstalledVersion") != VERSION:
                    raise ValueError("ClamAV scanner package version mismatch")
                name = item["VulnerabilityID"]
                if name in clam:
                    raise ValueError("Duplicate Talos CVE entry")
                clam[name] = item["Severity"]
    expected = {**{name: "HIGH" for name in CVES},
                **{name: "MEDIUM" for name in MEDIUM_CVES}}
    if clam != expected:
        raise ValueError("ClamAV's seven HIGH and six MEDIUM must remain visible")
    if counts["CRITICAL"] != 0 or counts["UNKNOWN"] < 1:
        raise ValueError("Scanner blocker coverage is incomplete")

    if (not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX"
            or not isinstance(sbom.get("metadata"), dict)):
        raise ValueError("CycloneDX identity missing")
    component = sbom["metadata"].get("component")
    if (not isinstance(component, dict) or
            component.get("type") != "container" or component.get("name") != IMAGE):
        raise ValueError("CycloneDX image mismatch")
    ids = [
        x.get("value")
        for x in component.get("properties", [])
        if isinstance(x, dict) and x.get("name") == "aquasecurity:trivy:ImageID"
    ]
    if ids != [image_id]:
        raise ValueError("CycloneDX immutable image ID mismatch")
    components = sbom.get("components")
    if not isinstance(components, list):
        raise ValueError("CycloneDX components missing")
    matches = [c for c in components if isinstance(c, dict)
               and c.get("name") == "clamav"]
    if (len(matches) != 1 or matches[0].get("version") != VERSION
            or not isinstance(matches[0].get("purl"), str)
            or not matches[0]["purl"].startswith(
                "pkg:deb/debian/clamav@" + quote(VERSION, safe="") + "?"
            )):
        raise ValueError("Vendor Debian package cannot be matched to SBOM")

    if not isinstance(vendor, dict) or any((
        vendor.get("source") != "talos-detached-debian-package-v1",
        vendor.get("signature_verified") is not True,
        vendor.get("signer_fingerprint") != TALOS_FINGERPRINT,
        vendor.get("package") != "clamav",
        vendor.get("package_version") != VERSION,
        vendor.get("architecture") != "amd64",
        vendor.get("vendor_patched_floor") != "1.5.3",
        vendor.get("release_authorized") is not False,
    )):
        raise ValueError("Talos detached-signature claim not verified")
    file_sha = vendor.get("signed_deb_sha256")
    if not isinstance(file_sha, str) or not SHA.fullmatch(file_sha):
        raise ValueError("Signed .deb SHA-256 missing")
    if not isinstance(runtime, dict) or any((
        runtime.get("source") != "folio-clamav-installed-native-v1",
        runtime.get("package") != "clamav",
        runtime.get("package_version") != VERSION,
        runtime.get("architecture") != "amd64",
        runtime.get("clamscan_version") != "ClamAV 1.5.5",
        runtime.get("dpkg_verify_clean") is not True,
        runtime.get("shared_library_linked") is not True,
        runtime.get("release_authorized") is not False,
    )):
        raise ValueError("Installed ClamAV runtime metadata inconsistent")
    files = _signed_files(vendor.get("files"))
    installed = _signed_files(runtime.get("files"))
    if files != installed:
        raise ValueError("Installed ClamAV executable bytes differ from signed .deb")
    paths = {row["path"] for row in files}
    if not set(NATIVE_REQUIRED).issubset(paths):
        raise ValueError("Required ClamAV core native code was not covered")

    return {
        "status": "signed_talos_native_match_release_blocked",
        "release_authorized": False,
        "scanner_gate": "blocked",
        "vex": "not_issued",
        "cve_applicability": "individually_unassessed",
        "vendor_signer_fingerprint": TALOS_FINGERPRINT,
        "signed_deb_sha256": file_sha,
        "image_id": image_id,
        "vendor_patched_floor": "1.5.3",
        "vendor_signed_files_matched": len(files),
        "native_binary_sha256_match": True,
        "dpkg_verify_clean": True,
        "clamav_high_still_reported": 7,
        "clamav_medium_still_reported": 6,
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "unknown": counts["UNKNOWN"],
        "other_unknown_still_blocking": counts["UNKNOWN"],
        "artifact_release_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("scan","sbom","vendor","runtime"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    try:
        result = verify_signed_vendor_evidence(
            *(json.loads(getattr(args,name).read_text(encoding="utf-8"))
              for name in ("scan","sbom","vendor","runtime")),
            args.image_id,
        )
    except (ValueError, TypeError, OSError, KeyError, AttributeError):
        print(json.dumps({"status":"error",
                          "reason":"signed_talos_native_evidence_invalid"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2  # Native equivalence is not CVE-specific release approval.


if __name__=="__main__":
    raise SystemExit(main())
