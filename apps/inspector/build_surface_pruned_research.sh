#!/usr/bin/env bash
# R1.46 — local-only runtime surface reduction; no registry push or deployment.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_surface_build_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build >/dev/null
SOURCE="folio-civico-inspector:gnupg-pruned-research-r145"
TARGET="folio-civico-inspector:surface-pruned-research-r146"
EXPECTED="sha256:8e3bba6979ed0664531db7bd7fd55124afa7bb8afadae5df8b4d849f1c9ac3d2"
SOURCE_ID="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
if [[ "$SOURCE_ID" != "$EXPECTED" ]]; then
  printf '{"status":"error","reason":"unapproved_R145_base"}\n'
  exit 3
fi
SOURCE_PIN="folio-civico-inspector:surface-source-${SOURCE_ID#sha256:}"
PIN_ID="$(docker image inspect "$SOURCE_PIN" --format '{{.Id}}' 2>/dev/null || true)"
if [[ -n "$PIN_ID" && "$PIN_ID" != "$SOURCE_ID" ]]; then
  printf '{"status":"error","reason":"source_alias_conflict"}\n'
  exit 3
fi
if [[ -z "$PIN_ID" ]]; then docker tag "$SOURCE_ID" "$SOURCE_PIN"; fi
test "$(docker image inspect "$SOURCE_PIN" --format '{{.Id}}')" = "$SOURCE_ID"

docker build --pull=false --network=none \
  --file apps/inspector/Dockerfile.surface-pruned-research \
  --build-arg "RESEARCH_BASE=$SOURCE_PIN" \
  --tag "$TARGET" .
TARGET_ID="$(docker image inspect "$TARGET" --format '{{.Id}}')"
if [[ ! "$TARGET_ID" =~ ^sha256:[0-9a-f]{64}$ || "$TARGET_ID" == "$SOURCE_ID" ]]; then
  printf '{"status":"error","reason":"invalid_R146_image_id"}\n'
  exit 3
fi
test "$(docker image inspect "$SOURCE" --format '{{.Id}}')" = "$SOURCE_ID"

for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$TARGET_ID" "/srv/folio-inspector/$smoke"
done
docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 "$TARGET_ID" -c \
  "$(cat apps/inspector/smoke_signature_freshness.py)"

test "$(docker image inspect "$TARGET" --format '{{.Id}}')" = "$TARGET_ID"
printf '{"status":"surface_prune_smoke_passed_release_blocked","release_authorized":false}\n'
exit 2
