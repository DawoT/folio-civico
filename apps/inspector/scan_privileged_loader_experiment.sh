#!/usr/bin/env bash
# R1.28: exact Trivy/SBOM/native/dpkg differential. Always release-blocked.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_loader_scan_option"}\n'
  exit 3
fi
for tool in docker trivy timeout; do
  command -v "$tool" >/dev/null
done
BEFORE="folio-civico-inspector:clamav-cli-limited-experiment"
AFTER="folio-civico-inspector:privileged-loader-removed-experiment"
BEFORE_ID="$(docker image inspect "$BEFORE" --format '{{.Id}}')"
AFTER_ID="$(docker image inspect "$AFTER" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-privileged-loader.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT

for step in before after; do
  if [[ "$step" == "before" ]]; then
    name="$BEFORE"; image_id="$BEFORE_ID"
  else
    name="$AFTER"; image_id="$AFTER_ID"
  fi
  docker image inspect "$name" --format '{{json .}}' \
    > "$OUT/${step}-inspect.json"
  trivy image --scanners vuln --format json \
    --no-progress --image-src docker --output "$OUT/${step}-scan.json" "$name"
  trivy image --scanners vuln --format cyclonedx \
    --no-progress --image-src docker --output "$OUT/${step}-sbom.json" "$name"
  # Audit *only*: root + DAC_READ_SEARCH reads the full filesystem for
  # SUID/SGID, including APT private dirs. Normal inspector probes remain
  # non-root with cap-drop ALL. Neither case accesses network/documents.
  timeout 120s docker run --rm --network none --read-only \
    --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0:0 \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$image_id" -I -c \
    "$(cat apps/inspector/privileged_loader_surface.py)" \
    > "$OUT/${step}-surface.json"
  for kind in dpkg clamav; do
    if [[ "$kind" == "dpkg" ]]; then
      code="$(cat apps/inspector/privileged_loader_dpkg.py)"
      arguments=(--inventory)
    else
      code="$(cat apps/inspector/clamav_cli_native_inventory.py)"
      arguments=()
    fi
    timeout 120s docker run --rm --network none --read-only \
      --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 \
      --cpus 1 --memory 4g --memory-swap 4g \
      --entrypoint python3 "$image_id" -I -c "$code" "${arguments[@]}" \
      > "$OUT/${step}-${kind}.json"
  done
done
if [[ "$BEFORE_ID" != "$(docker image inspect "$BEFORE" --format '{{.Id}}')" || \
      "$AFTER_ID" != "$(docker image inspect "$AFTER" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_changed_during_loader_scan"}\n'
  exit 3
fi
python3 apps/inspector/privileged_loader_gate.py \
  --before-scan "$OUT/before-scan.json" --after-scan "$OUT/after-scan.json" \
  --before-sbom "$OUT/before-sbom.json" --after-sbom "$OUT/after-sbom.json" \
  --before-inspect "$OUT/before-inspect.json" \
  --after-inspect "$OUT/after-inspect.json" \
  --before-surface "$OUT/before-surface.json" \
  --after-surface "$OUT/after-surface.json" \
  --before-dpkg "$OUT/before-dpkg.json" --after-dpkg "$OUT/after-dpkg.json" \
  --before-clamav "$OUT/before-clamav.json" \
  --after-clamav "$OUT/after-clamav.json"
