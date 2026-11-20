#!/usr/bin/env bash
# R1.22 manual-only, isolated image. No release, registry, or remote changes.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_headless_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build
BASE="folio-civico-inspector:runtime-pruned-experiment"
IMAGE="folio-civico-inspector:headless-pruned-experiment"
BEFORE="$(docker image inspect "$BASE" --format '{{.Id}}')"
docker build --file apps/inspector/Dockerfile.headless-pruned-experiment \
  --tag "$IMAGE" apps/inspector
AFTER="$(docker image inspect "$BASE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"parent_image_changed"}\n'
  exit 3
fi
for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$IMAGE" "/srv/folio-inspector/$smoke"
done
printf '{"status":"headless_experiment_smoked","release_authorized":false}\n'
