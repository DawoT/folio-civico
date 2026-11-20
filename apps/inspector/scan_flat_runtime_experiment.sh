#!/usr/bin/env bash
# Strict SBOM/native provenance comparison of parent and flattened experiment.
# No CVE ignore rules, signed exceptions or production gate modifications.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_scan_option"}\n'
  exit 3
fi
command -v trivy >/dev/null
command -v docker >/dev/null
SOURCE="folio-civico-inspector:headless-pruned-experiment"
IMAGE="folio-civico-inspector:flat-runtime-experiment"
BEFORE="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
AFTER="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-flat-scan.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
for label in before after; do
  if [[ "$label" == "before" ]]; then
    ref="$SOURCE"; digest="$BEFORE"
  else
    ref="$IMAGE"; digest="$AFTER"
  fi
  docker image inspect "$ref" --format '{{json .}}' > "$OUT/${label}-inspect.json"
  trivy image --scanners vuln --format json --output "$OUT/${label}-scan.json" \
    --no-progress --image-src docker "$ref"
  trivy image --scanners vuln --format cyclonedx --output "$OUT/${label}-sbom.json" \
    --no-progress --image-src docker "$ref"
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --memory 4g --memory-swap 4g --entrypoint python3 "$digest" \
    -I -c "$(cat apps/inspector/source_inventory.py)" --mode experiment \
    > "$OUT/${label}-native.json"
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --memory 4g --memory-swap 4g --entrypoint python3 "$digest" \
    -I -c "$(cat apps/inspector/expat_runtime_inventory.py)" \
    > "$OUT/${label}-expat.json"
done
if [[ "$BEFORE" != "$(docker image inspect "$SOURCE" --format '{{.Id}}')" || \
      "$AFTER" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_changed_during_scan"}\n'
  exit 3
fi
python3 apps/inspector/flat_runtime_comparison.py \
  --before-scan "$OUT/before-scan.json" --after-scan "$OUT/after-scan.json" \
  --before-sbom "$OUT/before-sbom.json" --after-sbom "$OUT/after-sbom.json" \
  --before-inspect "$OUT/before-inspect.json" --after-inspect "$OUT/after-inspect.json" \
  --before-native "$OUT/before-native.json" --after-native "$OUT/after-native.json" \
  --before-expat "$OUT/before-expat.json" --after-expat "$OUT/after-expat.json"
