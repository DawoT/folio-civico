#!/usr/bin/env bash
# Execute the CURRENT repository smoke logic against an existing local image.
# Does not rebuild, mutate tags, mount files, process user data or deploy.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_raster_guard_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build >/dev/null
IMAGE="folio-civico-inspector:poppler-experiment"
BEFORE="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --cpus 1 \
  --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 "$BEFORE" \
  -c '__file__="/srv/folio-inspector/smoke_real_engines.py"; import base64,sys; data=base64.b64decode(sys.argv[1]); sys.argv=[__file__]; exec(compile(data,__file__,"exec"))' \
  "$(base64 -w0 apps/inspector/smoke_real_engines.py)"
test "$BEFORE" = "$(docker image inspect "$IMAGE" --format '{{.Id}}')"
