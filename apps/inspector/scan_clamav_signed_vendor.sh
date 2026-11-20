#!/usr/bin/env bash
# R1.26: independently verify Talos-signed package and compare native code
# against the pinned offline runtime. No VEX, waivers or deployment.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_signed_clamav_option"}\n'
  exit 3
fi
command -v docker >/dev/null
command -v trivy >/dev/null
command -v gpg >/dev/null
command -v dpkg-deb >/dev/null
command -v curl >/dev/null
command -v timeout >/dev/null
IMAGE="folio-civico-inspector:nonprivileged-experiment"
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-talos-verify.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
# Temporary .deb/.sig/GPG-home are destroyed by the verifier. This archive
# is NEVER copied to the image and is NEVER installed on the host.
timeout 360s python3 apps/inspector/clamav_vendor_evidence.py --vendor \
  > "$OUT/vendor.json"
trivy image --scanners vuln --format json --output "$OUT/scan.json" \
  --no-progress --image-src docker "$IMAGE"
trivy image --scanners vuln --format cyclonedx --output "$OUT/sbom.json" \
  --no-progress --image-src docker "$IMAGE"
# The container gets the immutable image ID, no network, no mount, no secrets
# and no write permissions. Runtime itself retains UID 65534 and CapEff=0.
timeout 100s docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$IMAGE_ID" -I -c \
  "$(cat apps/inspector/clamav_runtime_inventory.py)" \
  > "$OUT/runtime.json"
if [[ "$IMAGE_ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_changed_during_signed_scan"}\n'
  exit 3
fi
python3 apps/inspector/clamav_signed_gate.py \
  --scan "$OUT/scan.json" --sbom "$OUT/sbom.json" \
  --vendor "$OUT/vendor.json" --runtime "$OUT/runtime.json" \
  --image-id "$IMAGE_ID"
