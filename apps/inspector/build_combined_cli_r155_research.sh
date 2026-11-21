#!/usr/bin/env bash
# R1.55: intentionally non-deployable offline local image hardening.
# Verified output ID is specific to this laboratory; never publish it.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
fail() {
  printf '{"status":"combined_cli_local_image_not_verified","release_authorized":false}\n'
  exit 3
}
[[ "$#" -eq 0 ]] || fail
command -v docker >/dev/null || fail
command -v python3 >/dev/null || fail
if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST:-}" != unix://* ]]; then fail; fi
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" == unix://* ]] || fail
python3 apps/inspector/preflight.py --mode build >/dev/null || fail

BASE="folio-civico-inspector:privileged-cli-pruned-research-r148"
CAND="folio-civico-inspector:combined-clamav-cli-r155-local"
BASE_PIN="sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a"
NEW_PIN="sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327"
[[ "$(docker image inspect "$BASE" --format '{{.Id}}' 2>/dev/null)" == "$BASE_PIN" ]] || fail

EXISTING="$(docker image inspect "$CAND" --format '{{.Id}}' 2>/dev/null || true)"
if [[ -n "$EXISTING" && "$EXISTING" != "$NEW_PIN" ]]; then fail; fi
if [[ -z "$EXISTING" ]]; then
  docker build --pull=false --network=none \
    --file apps/inspector/Dockerfile.combined-cli-r155-research \
    --build-arg "RESEARCH_BASE=$BASE" \
    --tag "$CAND" apps/inspector || fail
fi
[[ "$(docker image inspect "$BASE" --format '{{.Id}}')" == "$BASE_PIN" ]] || fail
[[ "$(docker image inspect "$CAND" --format '{{.Id}}')" == "$NEW_PIN" ]] || fail
# A new digest from a future local build is NOT interchangeable with this one.
# It requires new independent scan+SBOM+fs/native evidence and image pinning.
printf '{"status":"combined_cli_local_image_digest_verified_release_blocked","image_id":"%s","release_authorized":false}\n' "$NEW_PIN"
exit 2
