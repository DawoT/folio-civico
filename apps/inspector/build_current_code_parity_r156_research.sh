#!/usr/bin/env bash
# Offline source-to-image code parity lab. Never push, deploy, bypass CVE gate.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
fail() {
  printf '{"status":"current_code_parity_build_not_verified","release_authorized":false}\n'
  exit 3
}
[[ "$#" -eq 0 ]] || fail
for cmd in docker git python3; do command -v "$cmd" >/dev/null || fail; done
[[ -z "${DOCKER_HOST:-}" || "${DOCKER_HOST:-}" == unix://* ]] || fail
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" == unix://* ]] || fail
python3 apps/inspector/preflight.py --mode build >/dev/null || fail
FILES=(inspector.py qpdf_paint_triage_r154.py qpdf_scoped_gate_r155.py fixtures.py preflight.py smoke_real_engines.py smoke_http_real.py)
SOURCES=()
for name in "${FILES[@]}"; do SOURCES+=("apps/inspector/$name"); done
git ls-files --error-unmatch -- "${SOURCES[@]}" >/dev/null || fail
git diff --quiet HEAD -- "${SOURCES[@]}" || fail
git diff --cached --quiet HEAD -- "${SOURCES[@]}" || fail

BASE="folio-civico-inspector:combined-clamav-cli-r155-local"
EXPECTED="sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327"
CAND="folio-civico-inspector:current-code-parity-no-pyc-r156-local"
[[ "$(docker image inspect "$BASE" --format '{{.Id}}' 2>/dev/null)" == "$EXPECTED" ]] || fail
# Prevent a later worktree from silently replacing an image already measured.
if docker image inspect "$CAND" >/dev/null 2>&1; then fail; fi
docker build --pull=false --network=none \
  --file apps/inspector/Dockerfile.current-code-parity-r156-research \
  --build-arg "RESEARCH_BASE=$BASE" \
  --tag "$CAND" apps/inspector || fail
[[ "$(docker image inspect "$BASE" --format '{{.Id}}')" == "$EXPECTED" ]] || fail
ID="$(docker image inspect "$CAND" --format '{{.Id}}')" || fail
[[ "$ID" =~ ^sha256:[a-f0-9]{64}$ && "$ID" != "$EXPECTED" ]] || fail
printf '{"status":"current_code_parity_image_built_research_only","base_id":"%s","candidate_id":"%s","source_commit":"%s","release_authorized":false}\n' "$EXPECTED" "$ID" "$(git rev-parse HEAD)"
exit 2
