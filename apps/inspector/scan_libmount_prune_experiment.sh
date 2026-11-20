#!/usr/bin/env bash
# R1.29: image/Trivy/CycloneDX/ELF/DPKG differential, release always blocked.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_libmount_scan_option"}\n'
  exit 3
fi
for tool in docker trivy timeout; do
  command -v "$tool" >/dev/null
done
BEFORE="folio-civico-inspector:privileged-loader-removed-experiment"
AFTER="folio-civico-inspector:libmount-pruned-experiment"
OLD="$(docker image inspect "$BEFORE" --format '{{.Id}}')"
NEW="$(docker image inspect "$AFTER" --format '{{.Id}}')"
OUT="$(mktemp -d "/tmp/folio-libmount.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
for mode in before after; do
  if [[ "$mode" == "before" ]]; then
    ref="$BEFORE"; image_id="$OLD"
  else
    ref="$AFTER"; image_id="$NEW"
  fi
  docker image inspect "$ref" --format '{{json .}}' > "$OUT/$mode-inspect.json"
  trivy image --scanners vuln --format json \
    --no-progress --image-src docker --output "$OUT/$mode-scan.json" "$ref"
  trivy image --scanners vuln --format cyclonedx \
    --no-progress --image-src docker --output "$OUT/$mode-sbom.json" "$ref"
  # Audit-only DAC_READ_SEARCH and UID 0: enumerate every ELF even in
  # root-only APT cache. Normal inspector execution has no capabilities.
  timeout 120s docker run --rm --network none --read-only \
    --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0:0 \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$image_id" -I -c \
    "$(cat apps/inspector/libmount_prune_surface.py)" \
    > "$OUT/$mode-surface.json"
  timeout 120s docker run --rm --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$image_id" -I -c \
    "$(cat apps/inspector/libmount_prune_dpkg.py)" --inventory \
    > "$OUT/$mode-dpkg.json"
  timeout 120s docker run --rm --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$image_id" -I -c \
    "$(cat apps/inspector/clamav_cli_native_inventory.py)" \
    > "$OUT/$mode-clamav.json"
done
if [[ "$OLD" != "$(docker image inspect "$BEFORE" --format '{{.Id}}')" || \
      "$NEW" != "$(docker image inspect "$AFTER" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"libmount_image_changed_during_scan"}\n'
  exit 3
fi
python3 apps/inspector/libmount_prune_gate.py \
  --before-scan "$OUT/before-scan.json" --after-scan "$OUT/after-scan.json" \
  --before-sbom "$OUT/before-sbom.json" --after-sbom "$OUT/after-sbom.json" \
  --before-inspect "$OUT/before-inspect.json" \
  --after-inspect "$OUT/after-inspect.json" \
  --before-surface "$OUT/before-surface.json" \
  --after-surface "$OUT/after-surface.json" \
  --before-dpkg "$OUT/before-dpkg.json" --after-dpkg "$OUT/after-dpkg.json" \
  --before-clamav "$OUT/before-clamav.json" \
  --after-clamav "$OUT/after-clamav.json"
