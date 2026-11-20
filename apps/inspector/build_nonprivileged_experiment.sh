#!/usr/bin/env bash
# R1.24 manual-only local prototype. Does not publish or authorize anything.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_privilege_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build
BASE="folio-civico-inspector:flat-runtime-experiment"
IMAGE="folio-civico-inspector:nonprivileged-experiment"
BEFORE="$(docker image inspect "$BASE" --format '{{.Id}}')"
docker build --file apps/inspector/Dockerfile.nonprivileged-experiment \
  --tag "$IMAGE" apps/inspector
if [[ "$BEFORE" != "$(docker image inspect "$BASE" --format '{{.Id}}')" ]]; then
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
# Independent negative control: kernel denies administrative commands at
# UID 65534, CapEff=0, NoNewPrivs=1 and a read-only root filesystem.
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$IMAGE" -I -c \
  "$(cat apps/inspector/privilege_denial_smoke.py)"
printf '{"status":"nonprivileged_smoked","release_authorized":false}\n'
