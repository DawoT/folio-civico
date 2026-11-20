#!/usr/bin/env bash
# Observational scan for the Expat local experiment; NEVER replaces audit_image.sh.
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
BEFORE="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-expat-trivy.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
# Do not skip DB updates, hide unfixed advisories or use ignore files.
trivy image --scanners vuln --format json --output "$OUT/scan.json" \
  --no-progress --image-src docker "$IMAGE"
AFTER="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"image_changed_during_scan"}\n'
  exit 3
fi
# Always exits 2 when valid: the underlying inspector release gate is blocked.
python3 apps/inspector/expat_prototype_scan.py --input "$OUT/scan.json" --image "$IMAGE"
