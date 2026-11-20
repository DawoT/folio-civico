#!/usr/bin/env bash
# R1.20: immutable experimental CVE scan + CycloneDX + offline native evidence.
# It NEVER replaces audit_image.sh or grants a release/VEX.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_scan_option"}\n'
  exit 3
fi
IMAGE="folio-civico-inspector:expat-experiment"
command -v docker >/dev/null
command -v trivy >/dev/null
python3 apps/inspector/preflight.py --mode build >/dev/null
BEFORE="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-expat-trivy.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT

# Full advisory database refresh and no vulnerability suppressions.
trivy image --scanners vuln --format json --output "$OUT/scan.json" \
  --no-progress --image-src docker "$IMAGE"
trivy image --scanners vuln --format cyclonedx --output "$OUT/sbom.json" \
  --no-progress --image-src docker "$IMAGE"

# Each collector executes inside the SAME immutable local Docker image ID,
# without network, privilege, host volumes, user PDFs, or published ports.
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --memory 4g --memory-swap 4g --entrypoint python3 "$BEFORE" \
  -I -c "$(cat apps/inspector/source_inventory.py)" --mode experiment \
  > "$OUT/native.json"
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --memory 4g --memory-swap 4g --entrypoint python3 "$BEFORE" \
  -I -c "$(cat apps/inspector/expat_runtime_inventory.py)" \
  > "$OUT/expat.json"

AFTER="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"image_changed_during_scan"}\n'
  exit 3
fi

# Evidence consistency is a strict prerequisite, NOT a gate bypass.
python3 apps/inspector/expat_evidence.py \
  --vulnerabilities "$OUT/scan.json" \
  --sbom "$OUT/sbom.json" \
  --source-inventory "$OUT/native.json" \
  --expat-inventory "$OUT/expat.json" \
  --image-id "$BEFORE" --image "$IMAGE"

# Return the authoritative experimental block after evidence validation.
# Even if zero blockers are reported, unassessed CVEs keep exit code 2.
python3 apps/inspector/expat_prototype_scan.py --input "$OUT/scan.json" --image "$IMAGE"
