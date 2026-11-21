#!/usr/bin/env bash
# R1.48: local-only removal of 15 privileged/admin CLI paths; NEVER RELEASE.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_arguments","release_authorized":false}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build >/dev/null
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}')" == unix://* ]]
SOURCE="folio-civico-inspector:folio2-runtime-research-r147"
CANDIDATE="folio-civico-inspector:privileged-cli-pruned-research-r148"
PIN="sha256:c506a8b40953167ee4f6486cb90217298a39ce680f0bdd5fdc3a8b9638ddb92d"
[[ "$(docker image inspect "$SOURCE" --format '{{.Id}}')" == "$PIN" ]]
ALIAS="folio-civico-inspector:privileged-cli-source-${PIN#sha256:}"
OLD="$(docker image inspect "$ALIAS" --format '{{.Id}}' 2>/dev/null || true)"
if [[ -n "$OLD" && "$OLD" != "$PIN" ]]; then
  printf '{"status":"error","reason":"pinned_alias_changed","release_authorized":false}\n'
  exit 3
fi
if [[ -z "$OLD" ]]; then docker tag "$PIN" "$ALIAS"; fi
[[ "$(docker image inspect "$ALIAS" --format '{{.Id}}')" == "$PIN" ]]
docker build --pull=false --network=none \
  --file apps/inspector/Dockerfile.privileged-cli-research \
  --build-arg "RESEARCH_BASE=$ALIAS" --tag "$CANDIDATE" apps/inspector
NEW_ID="$(docker image inspect "$CANDIDATE" --format '{{.Id}}')"
[[ "$NEW_ID" =~ ^sha256:[a-f0-9]{64}$ && "$NEW_ID" != "$PIN" ]]
[[ "$(docker image inspect "$SOURCE" --format '{{.Id}}')" == "$PIN" ]]
for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$NEW_ID" "/srv/folio-inspector/$smoke"
done
docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 "$NEW_ID" -c "$(cat apps/inspector/smoke_signature_freshness.py)"
[[ "$(docker image inspect "$CANDIDATE" --format '{{.Id}}')" == "$NEW_ID" ]]
printf '{"status":"privileged_entrypoints_removed_smokes_passed_release_blocked","release_authorized":false}\n'
exit 2
