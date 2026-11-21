# R1.56 — G2 / Evidence of current inspector source in a local native engine image

**Date:** 2026-11-21. **Issue:** [#75](https://github.com/DawoT/folio-civico/issues/75). **Status:** experiment technically verified, `release_authorized=false`. This is NOT the approved inspector OCI image and does not authorize Preview, production, PDF institutional data, Cloudflare changes, CVE waivers or VEX.

## The problem and source baseline

The R1.55 experimental image physically removed ten unnecessary ClamAV tools and fifteen privileged CLIs, but ran a historical version of `inspector.py`. Its embedded `inspector.py` SHA-256 `dda871954d8cf2ba7a0c8054a472fd7b37d36e784f83bf3c9fd41b800edf4eea` (30,907 bytes) differs from the actual `main` source SHA-256 `1da9a2d04b4c5f1add849d3ec66e3208bdd42876d80bfb252f47e650de52bf5d` (37,066 bytes). Moreover, the production Dockerfile now copies seven Python modules, not five.

The image was built from source files in `main@cb5ed0c747e87d3c346814ec28fdb126e26bdf46`; after incorporating `main@8cbf6b6bb9707d7697b84e06aa5565d6d0b9fc24` by an ordinary merge, `git diff origin/main HEAD --` **all seven actual inspector source files was empty**, so the very same source hashes remain current. The experiment uses a **pinned immutable local** R1.55 base ID `sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327`. The Dockerfile retains the runtime config, UID 65534, disabled network, ClamAV and OCR native dependencies; the complete filesystem is re-flattened from `scratch`, not layered on top of removed binaries.

## Adversarial RED → GREEN

The initial experiment `sha256:5aa1c53b90ef2d12da05b4b976df2e0372fa4b7a592c0f51969a00e7b73a57f2` copied seven current sources but preserved a pre-existing compiled `inspector.cpython-312.pyc`. **Do not use this prototype even as parity evidence.** Its discovery is the reason R1.56 now requires removal of exactly two legacy entries, protected by the source image SHA-256 `834cf9412cec3e83fee99c0480847e50d0d32952bd1f768dc08033682bfc81ea`. The Dockerfile checks this hash *before* deleting the specific bytecode and its empty directory. The final validator rejects any other removal, new code, executable mutation, permission drift, source mismatch or layer inheritance. No deleting or rewriting host files.

The first rootfs comparison failed due to a mistaken assumption of `0o644` source modes: both baseline and new code files actually have mode `0o664` with UID 65534. The validator now checks the **observed unchanged mode** and each exact source SHA rather than presenting a mode change as source parity. Mode hardening to remove group-write would require separate acceptance and a new image digest; a read-only runtime filesystem remains mandatory.

## Immutable experiment and actual gate outcome

| Property | Pinned R1.55 | R1.56 current-code experiment |
|---|---|---|
| Exact local image ID | `sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327` | `sha256:a073902d8b86c7acbb6c885ed2af714ad7bb89c878b53deac9b7ad866c4e47e4` |
| Complete rootfs records | 6503 | 6503 |
| Current code changes | — | three replacements, two new modules, two unchanged modules |
| Bytecode removal | historical cache present | exactly two entries removed and hash attested |
| Native binaries, models, signatures | pinned | unchanged, with matching source-to-ELF evidence |
| Trivy findings, same DB snapshot | 51 HIGH, 13 UNKNOWN, 114 MEDIUM, 126 LOW | **identical individual records** |
| CycloneDX OS/Python packages | pinned | **identical individual components** |
| OCI metadata and layers | nonroot, scratch-flattened | same config, independent flattened layer |
| G2 scanner decision | blocked | **blocked** |
| Allowed to release | no | **no** |

The counts above are from the **new scanner DB snapshot on the same date and two specific digests**, *not* the earlier R1.55 55 HIGH / 15 UNKNOWN snapshot. This cannot be claimed as a security remediation or CVE suppression. Source-built Poppler/Tesseract applicability remains unassessed and ten November ClamAV advisory CVEs need individually signed provenance/applicability confirmation.

The full inventory and source/parity audit command
`bash apps/inspector/scan_current_code_parity_r156_research.sh sha256:a073902d8b86c7acbb6c885ed2af714ad7bb89c878b53deac9b7ad866c4e47e4`
returned **exit 2, expected**, with `main_code_parity=verified_by_sha256`, `same_all_trivy_findings=true`, `same_cyclonedx_packages=true`, `same_elf_and_ocr_models=true`, `suid_sgid_after=0`, `scanner_gate=blocked`, `release_authorized=false`. Malformed CLI input returns **exit 3**, with no release.

## Runtime validation on the new digest

In a disposable container, as UID 65534, with `--network none`, `--read-only`, no capabilities or privilege escalation, bounded memory/CPU/processes and bounded private tmpfs:

- Real ClamAV EICAR detection, native text PDF and Spanish OCR, malformed, encrypted and embedded-file PDFs rejected; encrypted content was stopped before Poppler (**exit 0**).
- Actual HTTP request on loopback, health, unauthorized access, tampered SHA-256, signed/unsigned mode synthetic manifest contract (**exit 0**).
- Fresh ClamAV databases verified; logical +72h expiry correctly blocks further admission (**exit 0**).
- One initial smoke invocation mistakenly used `python3 -I` for the helper script itself, which removes its script directory from `sys.path` and caused `ModuleNotFoundError: fixtures`; the shipped inspector entrypoint explicitly restores its own trusted directory, whereas the canonical helper smoke is run without `-I`. Corrected invocation **passed**. Neither bug was covered up.

All tests use synthetic bytes, never institutional PDFs or real authorization tokens.

## Reproducible commands and next gate

```sh
# Build is offline from one immutable local image; the local tag cannot be overwritten.
bash apps/inspector/build_current_code_parity_r156_research.sh
# The scanner requires the exact new ID, and returns exit 2 while release is blocked.
bash apps/inspector/scan_current_code_parity_r156_research.sh sha256:a073902d8b86c7acbb6c885ed2af714ad7bb89c878b53deac9b7ad866c4e47e4
# Actual AV, OCR, HTTP, expiry; exit 2 if all pass (release still blocked).
bash apps/inspector/smoke_current_code_parity_r156_research.sh sha256:a073902d8b86c7acbb6c885ed2af714ad7bb89c878b53deac9b7ad866c4e47e4
python3 -m unittest discover -s apps/inspector/tests
sh scripts/ci.sh
```

Rebuilding later on another host or after signature expiry produces a new digest and requires new source hashes, signatures, vulnerability DB/scan, full runtime smoke and an explicit decision. Existing research tags are **not** release identities.

**Next milestone:** remediate actual vulnerabilities in a newly sourced, vendor-signed package/runtime, complete Poppler/Tesseract source→ELF/advisory coverage, refresh ClamAV signatures and G4 vector/mixed-page regional evidence, and obtain authorized G2/G4 acceptance on a **single exact final digest**. Until then `release_authorized=false`. No production deployment or waiver has been performed.
