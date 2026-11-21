#!/usr/bin/env bash
# R1.42: real offline OCR text-hash comparison on two fixed local image IDs.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_quality_option"}\n'
  exit 3
fi
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
if [[ ! "$SOURCE_ID" =~ ^sha256:[a-f0-9]{64}$ ]] \
    || [[ ! "$FLAT_ID" =~ ^sha256:[a-f0-9]{64}$ ]] \
    || [[ "$SOURCE_ID" == "$FLAT_ID" ]]; then
  printf '{"status":"error","reason":"invalid_quality_image_id"}\n'
  exit 3
fi
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-poppler-flat-quality.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
SCRIPT="$(cat apps/inspector/ocr_quality_matrix.py)"
for variant in before after; do
  if [[ "$variant" == before ]]; then ID="$SOURCE_ID"; else ID="$FLAT_ID"; fi
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$ID" -c "$SCRIPT" > "$OUT/${variant}.json"
done
if [[ "$SOURCE_ID" != "$(docker image inspect "$SOURCE" --format '{{.Id}}')" ]] \
    || [[ "$FLAT_ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"quality_tag_changed"}\n'
  exit 3
fi
python3 apps/inspector/ocr_quality_matrix.py --compare \
  "$OUT/before.json" "$OUT/after.json"
