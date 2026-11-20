#!/usr/bin/env bash
# R1.23: only build a local flattened image; never replace active image tags.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_flatten_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build
BASE="folio-civico-inspector:headless-pruned-experiment"
IMAGE="folio-civico-inspector:flat-runtime-experiment"
BEFORE="$(docker image inspect "$BASE" --format '{{.Id}}')"
docker build --file apps/inspector/Dockerfile.flat-runtime-experiment \
  --tag "$IMAGE" apps/inspector
AFTER="$(docker image inspect "$BASE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"parent_image_changed"}\n'
  exit 3
fi
# Build is not evidence enough: one final OCI layer and real offline engine
# smoke are required before any CVE assessment can be attempted.
# BuildKit emits a second EMPTY tar layer for WORKDIR. Verify the
# only shared DiffID with the ancestor is that exact empty tar, not an old
# filesystem layer, and that the new content layer is actually independent.
python3 - "$BASE" "$IMAGE" <<'PY'
import json
import subprocess
import sys

EMPTY = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
def layers(name):
    p = subprocess.run(["docker", "image", "inspect", name], capture_output=True,
                       text=True, check=True, timeout=20)
    return json.loads(p.stdout)[0]["RootFS"]["Layers"]
before, after = layers(sys.argv[1]), layers(sys.argv[2])
if len(before) < 2 or len(after) != 2 or after.count(EMPTY) != 1 or (
    set(after) & set(before)
) - {EMPTY}:
    raise SystemExit("Historical nonempty OCI layer inherited: flat image blocked")
PY
for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$IMAGE" "/srv/folio-inspector/$smoke"
done
printf '{"status":"flat_runtime_smoked","historical_layers_removed":true,"release_authorized":false}\n'
