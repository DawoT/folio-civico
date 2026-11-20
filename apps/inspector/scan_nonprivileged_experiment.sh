#!/usr/bin/env bash
# R1.24: immutable-image evidence, never CVE suppression/release approval.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_scan_option"}\n'
  exit 3
fi
command -v docker >/dev/null
command -v trivy >/dev/null
SOURCE="folio-civico-inspector:flat-runtime-experiment"
IMAGE="folio-civico-inspector:nonprivileged-experiment"
BEFORE="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
AFTER="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-privilege.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
for label in before after; do
  if [[ "$label" == "before" ]]; then ref="$SOURCE"; digest="$BEFORE"; else
    ref="$IMAGE"; digest="$AFTER"
  fi
  docker image inspect "$ref" --format '{{json .}}' > "$OUT/${label}-inspect.json"
  trivy image --scanners vuln --format json --output "$OUT/${label}-scan.json" \
    --no-progress --image-src docker "$ref"
  trivy image --scanners vuln --format cyclonedx --output "$OUT/${label}-sbom.json" \
    --no-progress --image-src docker "$ref"
  # Read-only attestation needs DAC_READ_SEARCH to enumerate root-owned
  # APT cache directories. This capability is NEVER used by the inspector.
  docker run --rm --network none --read-only --cap-drop ALL \
    --cap-add DAC_READ_SEARCH --user 0:0 \
    --security-opt no-new-privileges --pids-limit 64 \
    --memory 4g --memory-swap 4g --entrypoint python3 "$digest" \
    -I -c "$(cat apps/inspector/privilege_surface.py)" \
    > "$OUT/${label}-inventory.json"
done
if [[ "$BEFORE" != "$(docker image inspect "$SOURCE" --format '{{.Id}}')" || \
      "$AFTER" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_changed_during_scan"}\n'
  exit 3
fi
python3 apps/inspector/privilege_gate.py \
  --before-scan "$OUT/before-scan.json" --after-scan "$OUT/after-scan.json" \
  --before-sbom "$OUT/before-sbom.json" --after-sbom "$OUT/after-sbom.json" \
  --before-inspect "$OUT/before-inspect.json" --after-inspect "$OUT/after-inspect.json" \
  --before-inventory "$OUT/before-inventory.json" \
  --after-inventory "$OUT/after-inventory.json"
