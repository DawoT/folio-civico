#!/usr/bin/env bash
# R1.30 read-only CVE-specific evidence on immutable LOCAL R1.29 image.
# Success of evidence deliberately exits 2 (release blocked).
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_util_linux_cve_option"}\n'
  exit 3
fi
for command in python3 docker trivy timeout; do
  command -v "$command" >/dev/null
done
IMAGE="folio-civico-inspector:libmount-pruned-experiment"
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUT="$(mktemp -d "/tmp/folio-util-linux-cves.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT

# Tie scanner and local snapshot to immutable IDs; no image changes.
docker image inspect "$IMAGE" --format '{{json .}}' > "$OUT/inspect.json"
trivy image --scanners vuln --format json \
  --no-progress --image-src docker --output "$OUT/scan.json" "$IMAGE"
trivy image --scanners vuln --format cyclonedx \
  --no-progress --image-src docker --output "$OUT/sbom.json" "$IMAGE"

# Only the ordinary scanner runtime measures individual CVE entrypoint
# prerequisites, as UID 65534, no net, no privileges and read-only root.
timeout 120s docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$IMAGE_ID" -I -c \
  "$(cat apps/inspector/util_linux_cve_runtime.py)" \
  > "$OUT/runtime.json"

# Separate bounded audit-only root + DAC_READ_SEARCH allows exhaustive
# traversal of root-owned directories. These credentials never belong to
# Folio's runtime, are never used to process documents, and have no network.
timeout 120s docker run --rm --network none --read-only \
  --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0:0 \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$IMAGE_ID" -I -c \
  "$(cat apps/inspector/libmount_prune_surface.py)" \
  > "$OUT/libmount.json"
timeout 120s docker run --rm --network none --read-only \
  --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0:0 \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$IMAGE_ID" -I -c \
  "$(cat apps/inspector/privileged_loader_surface.py)" \
  > "$OUT/privileged.json"

if [[ "$IMAGE_ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"util_linux_cve_image_changed_during_probe"}\n'
  exit 3
fi

python3 apps/inspector/util_linux_cve_gate.py \
  --runtime "$OUT/runtime.json" \
  --scan "$OUT/scan.json" --sbom "$OUT/sbom.json" \
  --inspect "$OUT/inspect.json" \
  --libmount "$OUT/libmount.json" \
  --privileged "$OUT/privileged.json"
