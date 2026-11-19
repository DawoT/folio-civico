#!/usr/bin/env bash
# Execute the CURRENT inspector and smoke logic against existing local image
# engines. Image's on-disk Python code stays unchanged; the smoke imports the
# current source in memory, not the previously baked image module.
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
  -c 'import base64,sys,types; module=types.ModuleType("inspector"); module.__file__="/srv/folio-inspector/inspector.py"; sys.modules["inspector"]=module; exec(compile(base64.b64decode(sys.argv[1]),module.__file__,"exec"),module.__dict__); path="/srv/folio-inspector/smoke_real_engines.py"; smoke=base64.b64decode(sys.argv[2]); sys.argv=[path]; exec(compile(smoke,path,"exec"),{"__name__":"__main__","__file__":path,"__package__":None})' \
  "$(base64 -w0 apps/inspector/inspector.py)" \
  "$(base64 -w0 apps/inspector/smoke_real_engines.py)"
test "$BEFORE" = "$(docker image inspect "$IMAGE" --format '{{.Id}}')"
