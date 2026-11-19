#!/usr/bin/env bash
# Optional local security gate, NOT part of the lightweight CI test suite.
# Scans ONLY Folio Civico's known local Docker image. Never pushes/deploys.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

IMAGE="folio-civico-inspector:validation"
command -v docker >/dev/null
command -v trivy >/dev/null
# Repo and Docker daemon must have adequate space, and the daemon must be local.
python3 apps/inspector/preflight.py --mode build >/dev/null

BEFORE="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-civico-scan.XXXXXX")"
trap 'rm -rf -- "$OUTPUT"' EXIT

# Do not suppress findings, ignore unfixed issues, or skip DB updates.
# Missing database, failed scan or empty output must never become "passed".
trivy image --scanners vuln --format json --output "$OUTPUT/vulns.json" \
  --no-progress --image-src docker "$IMAGE"
trivy image --scanners vuln --format cyclonedx --output "$OUTPUT/sbom.json" \
  --no-progress --image-src docker "$IMAGE"

AFTER="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"image_changed_during_audit"}\n'
  exit 3
fi

python3 apps/inspector/audit_image.py \
  --vulnerabilities "$OUTPUT/vulns.json" \
  --sbom "$OUTPUT/sbom.json" --image "$IMAGE"
