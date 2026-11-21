#!/usr/bin/env bash
# R1.45: same-DB Trivy/CycloneDX and immutable ELF differential; NEVER RELEASE.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_gnupg_scan_option"}\n'
  exit 3
fi
for command in docker trivy python3; do
  command -v "$command" >/dev/null
done
python3 apps/inspector/preflight.py --mode build >/dev/null
BEFORE="folio-civico-inspector:poppler-flat-research"
AFTER="folio-civico-inspector:gnupg-pruned-research-r145"
EXPECTED="sha256:a68bce319afff0a0f50d50f5a717e077061dbe1eb93c9465910d7f002ba23f18"
BEFORE_ID="$(docker image inspect "$BEFORE" --format '{{.Id}}')"
AFTER_ID="$(docker image inspect "$AFTER" --format '{{.Id}}')"
if [[ "$BEFORE_ID" != "$EXPECTED" \
      || ! "$AFTER_ID" =~ ^sha256:[a-f0-9]{64}$ \
      || "$AFTER_ID" == "$BEFORE_ID" ]]; then
  printf '{"status":"error","reason":"research_image_identity_mismatch"}\n'
  exit 3
fi
PRIVATE="$(mktemp -d "${TMPDIR:-/tmp}/folio-r145-differential.XXXXXX")"
chmod 700 "$PRIVATE"
trap 'rm -rf -- "$PRIVATE"' EXIT

# Update once, compare BOTH images against the SAME local DB snapshot. Never
# use --ignore-unfixed, exception files, or severity filters to alter findings.
trivy image --download-db-only --no-progress
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format json --output "$PRIVATE/before-scan.json" "$BEFORE"
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format json --output "$PRIVATE/after-scan.json" "$AFTER"
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format cyclonedx --output "$PRIVATE/before-sbom.json" "$BEFORE"
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format cyclonedx --output "$PRIVATE/after-sbom.json" "$AFTER"

docker image inspect "$BEFORE_ID" > "$PRIVATE/before-inspect-array.json"
docker image inspect "$AFTER_ID" > "$PRIVATE/after-inspect-array.json"
# Convert the Docker inspect single-element arrays without losing fields.
python3 - "$PRIVATE" <<'PY'
import json, pathlib, sys
base=pathlib.Path(sys.argv[1])
for prefix in ('before','after'):
    source=base/(prefix+'-inspect-array.json')
    parsed=json.loads(source.read_text(encoding='utf-8'))
    if not isinstance(parsed,list) or len(parsed)!=1:
        raise SystemExit('Expected one immutable Docker inspection record')
    (base/(prefix+'-inspect.json')).write_text(json.dumps(parsed[0]))
PY

# Native code and model inventories must remain bit-identical; never infer
# safety from missing package records or an ELF ldd snapshot alone.
for side in before after; do
  if [[ "$side" == "before" ]]; then ID="$BEFORE_ID"; else ID="$AFTER_ID"; fi
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$ID" -I -c \
    "$(cat apps/inspector/source_inventory.py)" --mode experiment \
    > "$PRIVATE/$side-native.json"
done
if [[ "$BEFORE_ID" != "$(docker image inspect "$BEFORE" --format '{{.Id}}')" \
      || "$AFTER_ID" != "$(docker image inspect "$AFTER" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_tag_changed_during_comparison"}\n'
  exit 3
fi

# Return 2 for valid evidence, 3 for malformed/insufficient evidence.
# Both statuses prohibit release. The raw reports stay in private tmpfs/files
# only for this invocation and are deleted when the script exits.
python3 apps/inspector/gnupg_flat_prune_comparison.py \
  --before-scan "$PRIVATE/before-scan.json" \
  --after-scan "$PRIVATE/after-scan.json" \
  --before-sbom "$PRIVATE/before-sbom.json" \
  --after-sbom "$PRIVATE/after-sbom.json" \
  --before-inspect "$PRIVATE/before-inspect.json" \
  --after-inspect "$PRIVATE/after-inspect.json" \
  --before-native "$PRIVATE/before-native.json" \
  --after-native "$PRIVATE/after-native.json" \
  --before-id "$BEFORE_ID" --after-id "$AFTER_ID"
