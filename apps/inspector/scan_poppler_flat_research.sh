#!/usr/bin/env bash
# R1.42: independent Trivy/SBOM/native fingerprint proof for local scratch image.
# No VEX/ignore rules; a valid research differential exits 2 (BLOCKED).
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_flat_scan_option"}\n'
  exit 3
fi
command -v trivy >/dev/null
command -v docker >/dev/null
python3 apps/inspector/preflight.py --mode build >/dev/null

SOURCE="folio-civico-inspector:poppler-experiment"
IMAGE="folio-civico-inspector:poppler-flat-research"
EXPECTED_SOURCE_ID="sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f"
SOURCE_ID="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
if [[ "$SOURCE_ID" != "$EXPECTED_SOURCE_ID" ]]; then
  printf '{"status":"error","reason":"unapproved_poppler_source_id"}\n'
  exit 3
fi
FLAT_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ ! "$SOURCE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || [[ ! "$FLAT_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || [[ "$SOURCE_ID" == "$FLAT_ID" ]]; then
  printf '{"status":"error","reason":"invalid_flat_scan_image_identity"}\n'
  exit 3
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/folio-poppler-flat-r142.XXXXXX")"
chmod 700 "$WORK"
trap 'rm -rf -- "$WORK"' EXIT

# Refresh DB first, then pin the same local database snapshot for both scans.
# This is a comparative research check, not the strict release audit.
trivy image --download-db-only --no-progress
for which in before after; do
  if [[ "$which" == before ]]; then
    REF="$SOURCE"; DIGEST="$SOURCE_ID"
  else
    REF="$IMAGE"; DIGEST="$FLAT_ID"
  fi
  docker image inspect "$DIGEST" --format '{{json .}}' > "$WORK/${which}-inspect.json"
  trivy image --scanners vuln --skip-db-update --no-progress \
    --image-src docker --format json --output "$WORK/${which}-scan.json" "$REF"
  trivy image --scanners vuln --skip-db-update --no-progress \
    --image-src docker --format cyclonedx --output "$WORK/${which}-sbom.json" "$REF"
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$DIGEST" -I -c \
    "$(cat apps/inspector/source_inventory.py)" --mode experiment \
    > "$WORK/${which}-native.json"
done
if [[ "$SOURCE_ID" != "$(docker image inspect "$SOURCE" --format '{{.Id}}')" ]] \
    || [[ "$FLAT_ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"flat_scan_image_changed"}\n'
  exit 3
fi

python3 apps/inspector/poppler_flat_comparison.py \
  --before-scan "$WORK/before-scan.json" \
  --after-scan "$WORK/after-scan.json" \
  --before-sbom "$WORK/before-sbom.json" \
  --after-sbom "$WORK/after-sbom.json" \
  --before-inspect "$WORK/before-inspect.json" \
  --after-inspect "$WORK/after-inspect.json" \
  --before-native "$WORK/before-native.json" \
  --after-native "$WORK/after-native.json"
