#!/usr/bin/env bash
# R1.29 local-only image. Never push, release, deploy, or VEX.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_libmount_build_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build
SOURCE="folio-civico-inspector:privileged-loader-removed-experiment"
TARGET="folio-civico-inspector:libmount-pruned-experiment"
OLD="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
docker build --file apps/inspector/Dockerfile.libmount-prune-experiment \
  --tag "$TARGET" apps/inspector
if [[ "$OLD" != "$(docker image inspect "$SOURCE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"libmount_source_image_changed"}\n'
  exit 3
fi
TARGET_ID="$(docker image inspect "$TARGET" --format '{{.Id}}')"
for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$TARGET_ID" "/srv/folio-inspector/$smoke"
done
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$TARGET_ID" -I -c \
  "$(cat apps/inspector/libmount_prune_smoke.py)"
printf '{"status":"libmount_runtime_pruned_and_smoked","release_authorized":false}\n'
