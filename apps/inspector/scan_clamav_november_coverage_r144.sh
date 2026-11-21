#!/usr/bin/env bash
# R1.44: offline native ClamAV proof + same-DB Trivy advisory visibility.
# May download public signed Talos package and Trivy DB only on host.
# ALL result states, including evidence matched, are release BLOCKED.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_clamav_coverage_option"}\n'
  exit 3
fi
for command in docker trivy gpg dpkg-deb curl timeout; do
  command -v "$command" >/dev/null
done
python3 apps/inspector/preflight.py --mode build >/dev/null
IMAGE="folio-civico-inspector:expat-experiment"
EXPECTED="sha256:3447fed5e20f4c7f31110403738ffba08ab6b203141cea1b2158f60ef3ed5731"
ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ "$ID" != "$EXPECTED" ]]; then
  printf '{"status":"error","reason":"wrong_clamav_research_image"}\n'
  exit 3
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/folio-clamav-november-r144.XXXXXX")"
chmod 700 "$WORK"
trap 'rm -rf -- "$WORK"' EXIT

# Independent detached signature + every native code-bearing file SHA-256.
# No vendor package is installed; transient evidence is deleted on exit.
timeout 360s python3 apps/inspector/clamav_vendor_evidence.py --vendor \
  > "$WORK/talos-signed.json"

# Single local Trivy database snapshot; do not override the release gate.
trivy image --download-db-only --no-progress
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format json \
  --output "$WORK/trivy.json" "$IMAGE"
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format cyclonedx \
  --output "$WORK/sbom.json" "$IMAGE"

# Native code and dpkg -V verified WITHIN the exact immutable image ID.
timeout 90s docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$ID" -I -c \
  "$(cat apps/inspector/clamav_runtime_inventory.py)" \
  > "$WORK/native.json"

if [[ "$ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"research_image_changed_during_review"}\n'
  exit 3
fi
python3 apps/inspector/clamav_november_coverage_r144.py \
  --scan "$WORK/trivy.json" --sbom "$WORK/sbom.json" \
  --vendor "$WORK/talos-signed.json" --runtime "$WORK/native.json" \
  --image-id "$ID"
