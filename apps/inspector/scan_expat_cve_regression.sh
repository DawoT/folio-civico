#!/usr/bin/env bash
# R1.25: read-only bounded parser regression + unchanged Trivy/SBOM blockers.
# Never supplies a VEX or CVE waiver. No test document or network is involved.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_expat_regression_option"}\n'
  exit 3
fi
command -v docker >/dev/null
command -v trivy >/dev/null
command -v timeout >/dev/null
IMAGE="folio-civico-inspector:nonprivileged-experiment"
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-expat-regression.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
trivy image --scanners vuln --format json --output "$OUT/scan.json" \
  --no-progress --image-src docker "$IMAGE"
trivy image --scanners vuln --format cyclonedx --output "$OUT/sbom.json" \
  --no-progress --image-src docker "$IMAGE"
# The pinned digest, not a mutable tag, runs both evidence probes.
for probe in native probes; do
  if [[ "$probe" == "native" ]]; then
    code="$(cat apps/inspector/expat_runtime_inventory.py)"
    args=()
  else
    code="$(cat apps/inspector/expat_cve_regression.py)"
    args=(--probe)
  fi
  # Bound the *process lifetime* as well as input size and CPU/memory.
  # Abnormal termination is a hard failure, never evidence of a CVE fix.
  timeout 60s docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$IMAGE_ID" -I -c "$code" "${args[@]}" \
    > "$OUT/${probe}.json"
done
if [[ "$IMAGE_ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_changed_during_expat_probe"}\n'
  exit 3
fi
python3 apps/inspector/expat_cve_regression.py --verify \
  --scan "$OUT/scan.json" --sbom "$OUT/sbom.json" \
  --native "$OUT/native.json" --probes "$OUT/probes.json" \
  --image-id "$IMAGE_ID"
