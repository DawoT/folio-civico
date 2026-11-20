#!/usr/bin/env bash
# Differential GnuPG removal evidence; unassessed CVE gate ALWAYS blocked.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_scan_option"}\n'
  exit 3
fi
command -v trivy >/dev/null
command -v docker >/dev/null
SOURCE="folio-civico-inspector:expat-experiment"
IMAGE="folio-civico-inspector:runtime-pruned-experiment"
BEFORE="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
AFTER="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-prune-trivy.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
for label in before after; do
  if [[ "$label" == "before" ]]; then ref="$SOURCE"; else ref="$IMAGE"; fi
  trivy image --scanners vuln --format json --output "$OUT/${label}-scan.json" \
    --no-progress --image-src docker "$ref"
  trivy image --scanners vuln --format cyclonedx --output "$OUT/${label}-sbom.json" \
    --no-progress --image-src docker "$ref"
done
if [[ "$BEFORE" != "$(docker image inspect "$SOURCE" --format '{{.Id}}')" || \
      "$AFTER" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_changed_during_scan"}\n'
  exit 3
fi
python3 apps/inspector/runtime_prune_comparison.py \
  --before-scan "$OUT/before-scan.json" --after-scan "$OUT/after-scan.json" \
  --before-sbom "$OUT/before-sbom.json" --after-sbom "$OUT/after-sbom.json" \
  --before-id "$BEFORE" --after-id "$AFTER"
