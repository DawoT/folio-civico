#!/usr/bin/env bash
# R1.56: local source-to-container parity; all CVEs remain release-blocking.
# Usage: bash apps/inspector/scan_current_code_parity_r156_research.sh sha256:<64 hex>
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
failure() {
  printf '{"status":"current_code_parity_evidence_incomplete","scanner_gate":"blocked","release_authorized":false}\n'
  exit 3
}
trap 'failure' ERR
[[ "$#" -eq 1 && "$1" =~ ^sha256:[0-9a-f]{64}$ ]] || failure
for cmd in docker git python3 trivy timeout; do command -v "$cmd" >/dev/null || failure; done
[[ -z "${DOCKER_HOST:-}" || "${DOCKER_HOST:-}" == unix://* ]] || failure
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" == unix://* ]] || failure
BASE="folio-civico-inspector:combined-clamav-cli-r155-local"
CAND="folio-civico-inspector:current-code-parity-no-pyc-r156-local"
BASE_PIN="sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327"
CAND_PIN="$1"
[[ "$CAND_PIN" != "$BASE_PIN" ]] || failure
[[ "$(docker image inspect "$BASE" --format '{{.Id}}' 2>/dev/null)" == "$BASE_PIN" ]] || failure
[[ "$(docker image inspect "$CAND" --format '{{.Id}}' 2>/dev/null)" == "$CAND_PIN" ]] || failure
FILES=(inspector.py qpdf_paint_triage_r154.py qpdf_scoped_gate_r155.py fixtures.py preflight.py smoke_real_engines.py smoke_http_real.py)
SOURCES=()
for name in "${FILES[@]}"; do SOURCES+=("apps/inspector/$name"); done
git ls-files --error-unmatch -- "${SOURCES[@]}" >/dev/null || failure
git diff --quiet HEAD -- "${SOURCES[@]}" || failure
git diff --cached --quiet HEAD -- "${SOURCES[@]}" || failure
PRIVATE="$(mktemp -d /tmp/folio-r156-code-parity.XXXXXXXX)" || failure
chmod 700 "$PRIVATE"
trap 'rm -rf -- "$PRIVATE"' EXIT

python3 - "$PRIVATE/main-manifest.json" <<'PY'
import hashlib, json, pathlib, sys
names = ("fixtures.py", "inspector.py", "preflight.py",
         "qpdf_paint_triage_r154.py", "qpdf_scoped_gate_r155.py",
         "smoke_http_real.py", "smoke_real_engines.py")
root = pathlib.Path("apps/inspector")
print("Comparing seven current inspector source SHA-256 values", file=sys.stderr)
manifest = {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names}
pathlib.Path(sys.argv[1]).write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
PY

trivy image --download-db-only --no-progress >/dev/null
FS_SCRIPT="$(cat apps/inspector/runtime_executable_surface_inventory.py)"
NATIVE_SCRIPT="$(cat apps/inspector/source_inventory.py)"
for side in base candidate; do
  if [[ "$side" == base ]]; then REF="$BASE"; ID="$BASE_PIN"; else REF="$CAND"; ID="$CAND_PIN"; fi
  docker image inspect "$ID" --format '{{json .}}' > "$PRIVATE/$side-inspect.json"
  trivy image --scanners vuln --skip-db-update --no-progress \
    --image-src docker --format json --output "$PRIVATE/$side-scan.json" "$REF"
  trivy image --scanners vuln --skip-db-update --no-progress \
    --image-src docker --format cyclonedx --output "$PRIVATE/$side-sbom.json" "$REF"
  timeout 120s docker run --rm --pull never --network none --read-only \
    --user 0:0 --cap-drop ALL --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges --pids-limit 64 --cpus 1 \
    --memory 4g --memory-swap 4g --entrypoint python3 "$ID" -I -c "$FS_SCRIPT" \
    > "$PRIVATE/$side-fs.json"
  timeout 90s docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$ID" -I -c "$NATIVE_SCRIPT" --mode experiment \
    > "$PRIVATE/$side-native.json"
done
[[ "$(docker image inspect "$BASE" --format '{{.Id}}')" == "$BASE_PIN" ]] || failure
[[ "$(docker image inspect "$CAND" --format '{{.Id}}')" == "$CAND_PIN" ]] || failure

code=0
result="$(python3 apps/inspector/current_code_parity_r156.py \
  --base-fs "$PRIVATE/base-fs.json" \
  --candidate-fs "$PRIVATE/candidate-fs.json" \
  --manifest "$PRIVATE/main-manifest.json" \
  --base-inspect "$PRIVATE/base-inspect.json" \
  --candidate-inspect "$PRIVATE/candidate-inspect.json" \
  --base-scan "$PRIVATE/base-scan.json" \
  --candidate-scan "$PRIVATE/candidate-scan.json" \
  --base-sbom "$PRIVATE/base-sbom.json" \
  --candidate-sbom "$PRIVATE/candidate-sbom.json" \
  --base-native "$PRIVATE/base-native.json" \
  --candidate-native "$PRIVATE/candidate-native.json" \
  --candidate-id "$CAND_PIN")" || code=$?
[[ "$code" -eq 2 && -n "$result" && "$result" != *$'\n'* && ${#result} -lt 8192 ]] || failure
printf '%s\n' "$result"
exit 2
