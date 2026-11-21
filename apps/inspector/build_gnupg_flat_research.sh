#!/usr/bin/env bash
# R1.45 — research-only GnuPG pruning from immutable R1.42 Poppler flat image.
# Never change the deployable inspector, push an image or open network in Docker.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_gnupg_research_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build >/dev/null
SOURCE="folio-civico-inspector:poppler-flat-research"
TARGET="folio-civico-inspector:gnupg-pruned-research-r145"
EXPECTED="sha256:a68bce319afff0a0f50d50f5a717e077061dbe1eb93c9465910d7f002ba23f18"
BASE_ID="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
if [[ "$BASE_ID" != "$EXPECTED" ]]; then
  printf '{"status":"error","reason":"poppler_flat_source_identity_changed"}\n'
  exit 3
fi
# A local digest-derived tag prevents accidentally consuming a mutable source
# tag if another operation replaces it before Docker reads FROM.
BASE_PIN="folio-civico-inspector:gnupg-prune-source-${BASE_ID#sha256:}"
ALIASED="$(docker image inspect "$BASE_PIN" --format '{{.Id}}' 2>/dev/null || true)"
if [[ -n "$ALIASED" && "$ALIASED" != "$EXPECTED" ]]; then
  printf '{"status":"error","reason":"local_source_alias_mismatch"}\n'
  exit 3
fi
if [[ -z "$ALIASED" ]]; then
  docker tag "$EXPECTED" "$BASE_PIN"
fi
test "$(docker image inspect "$BASE_PIN" --format '{{.Id}}')" = "$EXPECTED"

docker build --pull=false --network=none \
  --file apps/inspector/Dockerfile.gnupg-prune-research \
  --build-arg "RESEARCH_BASE=$BASE_PIN" \
  --tag "$TARGET" .
AFTER_ID="$(docker image inspect "$TARGET" --format '{{.Id}}')"
if [[ ! "$AFTER_ID" =~ ^sha256:[a-f0-9]{64}$ || "$AFTER_ID" == "$EXPECTED" ]]; then
  printf '{"status":"error","reason":"candidate_immutable_identity_invalid"}\n'
  exit 3
fi
test "$(docker image inspect "$SOURCE" --format '{{.Id}}')" = "$EXPECTED"
test "$(docker image inspect "$BASE_PIN" --format '{{.Id}}')" = "$EXPECTED"

# Real parsing remains strictly synthetic and sandboxed in this research image.
for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$AFTER_ID" "/srv/folio-inspector/$smoke"
done
docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 "$AFTER_ID" -c \
  "$(cat apps/inspector/smoke_signature_freshness.py)"
test "$(docker image inspect "$TARGET" --format '{{.Id}}')" = "$AFTER_ID"
printf '{"status":"synthetic_smoke_complete_research_only","release_authorized":false}\n'
exit 2
