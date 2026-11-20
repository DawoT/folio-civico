#!/usr/bin/env bash
# R1.27 local-only experimental image; no deploy, push, VEX or waiver.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_clamav_cli_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build
BASE="folio-civico-inspector:nonprivileged-experiment"
IMAGE="folio-civico-inspector:clamav-cli-limited-experiment"
BASE_ID="$(docker image inspect "$BASE" --format '{{.Id}}')"
docker build --file apps/inspector/Dockerfile.clamav-cli-experiment \
  --tag "$IMAGE" apps/inspector
if [[ "$BASE_ID" != "$(docker image inspect "$BASE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"source_image_changed_during_build"}\n'
  exit 3
fi
for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$IMAGE" "/srv/folio-inspector/$smoke"
done
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$IMAGE" -I -c \
  "$(cat apps/inspector/clamav_cli_denial_smoke.py)"
printf '{"status":"clamav_cli_experiment_smoked","release_authorized":false}\n'
