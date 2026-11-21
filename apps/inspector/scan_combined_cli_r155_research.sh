#!/usr/bin/env bash
# R1.55, G2: strict offline research comparison of immutable local images.
# Exit 2 = credible hardening evidence with release BLOCKED; exit 3 = invalid.
# Do not build, push, deploy, issue VEX, or read institutional documents.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

error() {
  printf '{"status":"combined_cli_evidence_incomplete","scanner_gate":"blocked","release_authorized":false}\n'
  exit 3
}
[[ "$#" -eq 0 ]] || error
for cmd in docker trivy python3 timeout; do command -v "$cmd" >/dev/null || error; done
if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST:-}" != unix://* ]]; then error; fi
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" == unix://* ]] || error

BASE="folio-civico-inspector:privileged-cli-pruned-research-r148"
CAND="folio-civico-inspector:combined-clamav-cli-r155-local"
BASE_PIN="sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a"
NEW_PIN="sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327"
[[ "$(docker image inspect "$BASE" --format '{{.Id}}' 2>/dev/null)" == "$BASE_PIN" ]] || error
[[ "$(docker image inspect "$CAND" --format '{{.Id}}' 2>/dev/null)" == "$NEW_PIN" ]] || error

PRIVATE="$(mktemp -d /tmp/folio-r155-combined-evidence.XXXXXX)" || error
chmod 700 "$PRIVATE"
trap 'rm -rf -- "$PRIVATE"' EXIT
# One DB snapshot, two unsuppressed scans and two immutable source/image IDs.
trivy image --download-db-only --no-progress >/dev/null
native="$(cat apps/inspector/source_inventory.py)"
fs="$(cat apps/inspector/runtime_executable_surface_inventory.py)"
for side in base cand; do
  if [[ "$side" == base ]]; then REF="$BASE"; ID="$BASE_PIN"; else REF="$CAND"; ID="$NEW_PIN"; fi
  docker image inspect "$ID" --format '{{json .}}' > "$PRIVATE/${side}-inspect.json"
  trivy image --scanners vuln --skip-db-update --no-progress --image-src docker \
    --format json --output "$PRIVATE/${side}-scan.json" "$REF"
  trivy image --scanners vuln --skip-db-update --no-progress --image-src docker \
    --format cyclonedx --output "$PRIVATE/${side}-sbom.json" "$REF"
  timeout 90s docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$ID" -I -c "$native" --mode experiment \
    > "$PRIVATE/${side}-native.json"
  # Forensic-only DAC_READ_SEARCH permits full hashing of /var/cache/apt etc.
  # No writable root, network, host mounts, public documents or service tokens.
  timeout 120s docker run --rm --pull never --network none --read-only \
    --user 0:0 --cap-drop ALL --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges --pids-limit 64 --cpus 1 \
    --memory 4g --memory-swap 4g \
    --entrypoint python3 "$ID" -I -c "$fs" \
    > "$PRIVATE/${side}-fs.json"
done
timeout 90s docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$BASE_PIN" -I -c \
  "$(cat apps/inspector/clamav_runtime_inventory.py)" \
  > "$PRIVATE/base-clamav.json"
timeout 90s docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$NEW_PIN" -I -c \
  "$(cat apps/inspector/clamav_cli_native_inventory.py)" \
  > "$PRIVATE/cand-clamav.json"

[[ "$(docker image inspect "$BASE" --format '{{.Id}}')" == "$BASE_PIN" ]] || error
[[ "$(docker image inspect "$CAND" --format '{{.Id}}')" == "$NEW_PIN" ]] || error
python3 apps/inspector/combined_cli_prune_r155.py \
  --base-scan "$PRIVATE/base-scan.json" \
  --cand-scan "$PRIVATE/cand-scan.json" \
  --base-sbom "$PRIVATE/base-sbom.json" \
  --cand-sbom "$PRIVATE/cand-sbom.json" \
  --base-inspect "$PRIVATE/base-inspect.json" \
  --cand-inspect "$PRIVATE/cand-inspect.json" \
  --base-native "$PRIVATE/base-native.json" \
  --cand-native "$PRIVATE/cand-native.json" \
  --base-fs "$PRIVATE/base-fs.json" \
  --cand-fs "$PRIVATE/cand-fs.json" \
  --base-clamav "$PRIVATE/base-clamav.json" \
  --cand-clamav "$PRIVATE/cand-clamav.json"
