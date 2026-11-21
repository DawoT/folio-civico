#!/usr/bin/env bash
# R1.56 synthetic real-engine and HTTP checks on one immutable Docker ID.
# Exit 2 => real behavior verified but security release BLOCKED.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
error() {
  printf '{"status":"current_code_parity_real_smoke_failed","release_authorized":false}\n'
  exit 3
}
trap 'error' ERR
[[ "$#" -eq 1 && "$1" =~ ^sha256:[a-f0-9]{64}$ ]] || error
for command_name in docker python3 timeout; do command -v "$command_name" >/dev/null || error; done
[[ -z "${DOCKER_HOST:-}" || "${DOCKER_HOST:-}" == unix://* ]] || error
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" == unix://* ]] || error
IMAGE="folio-civico-inspector:current-code-parity-no-pyc-r156-local"
ID="$1"
[[ "$(docker image inspect "$IMAGE" --format '{{.Id}}' 2>/dev/null)" == "$ID" ]] || error
COMMON=(
  --rm --pull never --network none --read-only
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777
  --entrypoint python3
)
# Run synthetic smoke scripts as actual files: python -I removes their script
# directory from sys.path, unlike the inspector's trusted-path entrypoint.
timeout 180s docker run "${COMMON[@]}" "$ID" \
  /srv/folio-inspector/smoke_real_engines.py --database /opt/clamdb || error
timeout 120s docker run "${COMMON[@]}" "$ID" \
  /srv/folio-inspector/smoke_http_real.py || error
timeout 30s docker run "${COMMON[@]}" "$ID" -c \
  "$(cat apps/inspector/smoke_signature_freshness.py)" || error
[[ "$(docker image inspect "$IMAGE" --format '{{.Id}}')" == "$ID" ]] || error
printf '{"status":"current_main_real_engine_and_http_smokes_verified_release_blocked","candidate_id":"%s","release_authorized":false}\n' "$ID"
exit 2
