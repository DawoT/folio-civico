#!/usr/bin/env bash
# R1.27: require signed Talos code preserved and all CVEs visible.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_clamav_cli_scan_option"}\n'
  exit 3
fi
for command in docker trivy gpg dpkg-deb curl timeout; do
  command -v "$command" >/dev/null
done
BEFORE="folio-civico-inspector:nonprivileged-experiment"
AFTER="folio-civico-inspector:clamav-cli-limited-experiment"
BEFORE_ID="$(docker image inspect "$BEFORE" --format '{{.Id}}')"
AFTER_ID="$(docker image inspect "$AFTER" --format '{{.Id}}')"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-clamav-cli.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT
# Verifies official .deb, detached GPG signature, exact native code hashes.
# The public package is never installed, and all downloads are transient.
timeout 360s python3 apps/inspector/clamav_vendor_evidence.py --vendor \
  > "$OUT/talos-vendor.json"
for label in source target; do
  if [[ "$label" == "source" ]]; then
    ref="$BEFORE"; image_id="$BEFORE_ID"
  else
    ref="$AFTER"; image_id="$AFTER_ID"
  fi
  docker image inspect "$ref" --format '{{json .}}' > "$OUT/${label}-inspect.json"
  trivy image --scanners vuln --format json --output "$OUT/${label}-scan.json" \
    --no-progress --image-src docker "$ref"
  trivy image --scanners vuln --format cyclonedx --output "$OUT/${label}-sbom.json" \
    --no-progress --image-src docker "$ref"
  for kind in cli native; do
    if [[ "$kind" == "cli" ]]; then
      probe="$(cat apps/inspector/clamav_cli_surface.py)"
    else
      if [[ "$label" == "source" ]]; then
        probe="$(cat apps/inspector/clamav_runtime_inventory.py)"
      else
        probe="$(cat apps/inspector/clamav_cli_native_inventory.py)"
      fi
    fi
    timeout 90s docker run --rm --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges --pids-limit 64 \
      --cpus 1 --memory 4g --memory-swap 4g \
      --entrypoint python3 "$image_id" -I -c "$probe" \
      > "$OUT/${label}-${kind}.json"
  done
done
if [[ "$BEFORE_ID" != "$(docker image inspect "$BEFORE" --format '{{.Id}}')" || \
      "$AFTER_ID" != "$(docker image inspect "$AFTER" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_changed_during_scan"}\n'
  exit 3
fi
python3 apps/inspector/clamav_cli_gate.py \
  --source-scan "$OUT/source-scan.json" --target-scan "$OUT/target-scan.json" \
  --source-sbom "$OUT/source-sbom.json" --target-sbom "$OUT/target-sbom.json" \
  --source-inspect "$OUT/source-inspect.json" --target-inspect "$OUT/target-inspect.json" \
  --source-cli "$OUT/source-cli.json" --target-cli "$OUT/target-cli.json" \
  --source-native "$OUT/source-native.json" --target-native "$OUT/target-native.json" \
  --talos-vendor "$OUT/talos-vendor.json"
