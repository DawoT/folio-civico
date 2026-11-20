#!/usr/bin/env bash
# R1.28: local experimental build and real-engine security tests ONLY.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_loader_build_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build
SOURCE="folio-civico-inspector:clamav-cli-limited-experiment"
TARGET="folio-civico-inspector:privileged-loader-removed-experiment"
SOURCE_ID="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
docker build --file apps/inspector/Dockerfile.privileged-loader-experiment \
  --tag "$TARGET" apps/inspector
if [[ "$SOURCE_ID" != "$(docker image inspect "$SOURCE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"privileged_loader_source_image_changed"}\n'
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
  "$(cat apps/inspector/privileged_loader_smoke.py)"
printf '{"status":"privileged_elf_loader_experiment_smoked","release_authorized":false}\n'
