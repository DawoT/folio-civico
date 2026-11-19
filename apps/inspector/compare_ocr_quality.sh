#!/usr/bin/env bash
# Compare real OCR text over original synthetic documents only, offline.
# Diagnostic gate: never mutates approved image tags or cloud resources.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -gt 1 ]] || { [[ "$#" -eq 1 ]] && [[ "$1" != "--experiment" ]]; }; then
  printf '{"status":"error","reason":"unsupported_quality_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build >/dev/null
BASELINE="folio-civico-inspector:validation"
CANDIDATE="folio-civico-inspector:ocr-integrated"
if [[ "${1:-}" == "--experiment" ]]; then
  BASELINE="folio-civico-inspector:ocr-integrated"
  CANDIDATE="folio-civico-inspector:poppler-experiment"
fi
BEFORE_BASELINE="$(docker image inspect "$BASELINE" --format '{{.Id}}')"
BEFORE_CANDIDATE="$(docker image inspect "$CANDIDATE" --format '{{.Id}}')"
REPORTS="$(mktemp -d "${TMPDIR:-/tmp}/folio-ocr-quality.XXXXXX")"
trap 'rm -rf -- "$REPORTS"' EXIT
SCRIPT="$(cat apps/inspector/ocr_quality_matrix.py)"
for target in baseline candidate; do
  if [[ "$target" == "baseline" ]]; then
    image="$BEFORE_BASELINE"
  else
    image="$BEFORE_CANDIDATE"
  fi
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 --cpus 1 \
    --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$image" -c "$SCRIPT" > "$REPORTS/$target.json"
done
if [[ "$BEFORE_BASELINE" != "$(docker image inspect "$BASELINE" --format '{{.Id}}')" ]] \
  || [[ "$BEFORE_CANDIDATE" != "$(docker image inspect "$CANDIDATE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"quality_image_changed"}\n'
  exit 3
fi
python3 apps/inspector/ocr_quality_matrix.py --compare \
  "$REPORTS/baseline.json" "$REPORTS/candidate.json"
