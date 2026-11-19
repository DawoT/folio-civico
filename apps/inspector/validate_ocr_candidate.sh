#!/usr/bin/env bash
# RESEARCH ONLY: archive-free, curl-free Tesseract 5.5.4 candidate.
# Never deploy, push, or treat a custom compiler build as Trivy-covered.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BASE_IMAGE="folio-civico-inspector:validation"
IMAGE="folio-civico-inspector:ocr-candidate"
python3 apps/inspector/preflight.py --mode build
command -v docker >/dev/null
command -v trivy >/dev/null

# Requires only the already-validated local signed ClamAV image.
BASE_BEFORE="$(docker image inspect "$BASE_IMAGE" --format '{{.Id}}')"
docker build -f apps/inspector/Dockerfile.ocr-candidate \
  -t "$IMAGE" apps/inspector
BASE_AFTER="$(docker image inspect "$BASE_IMAGE" --format '{{.Id}}')"
if [[ "$BASE_BEFORE" != "$BASE_AFTER" ]]; then
  printf '{"status":"error","reason":"base_image_changed_during_build"}\n'
  exit 3
fi
CANDIDATE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"

# Real engines, real OCR (Spanish + English), no PDF text layer, and the
# actual private HTTP handler; each run has no outbound network or ports.
for script in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm \
    --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$CANDIDATE_ID" \
    "/srv/folio-inspector/$script"
done

OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-ocr-candidate.XXXXXX")"
trap 'rm -rf -- "$OUTPUT"' EXIT

trivy image --scanners vuln --format json \
  --output "$OUTPUT/vulnerabilities.json" --no-progress \
  --image-src docker "$IMAGE"
trivy image --scanners vuln --format cyclonedx \
  --output "$OUTPUT/sbom.json" --no-progress \
  --image-src docker "$IMAGE"

if [[ "$CANDIDATE_ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"candidate_image_changed_during_audit"}\n'
  exit 3
fi

GATE_EXIT=0
python3 apps/inspector/audit_image.py \
  --vulnerabilities "$OUTPUT/vulnerabilities.json" \
  --sbom "$OUTPUT/sbom.json" --image "$IMAGE" || GATE_EXIT=$?
if [[ "$GATE_EXIT" -ne 0 && "$GATE_EXIT" -ne 2 ]]; then
  exit "$GATE_EXIT"
fi

# Compiling Tesseract from source is NOT represented as an OS package.
# Trivy may show artificially fewer findings. Fail closed until an approved,
# comprehensive SBOM/advisory assessment covers the custom executable.
if ! python3 - "$OUTPUT/sbom.json" <<'PY'
import json,sys
try:
    components=json.load(open(sys.argv[1],encoding="utf-8")).get("components",[])
    covered=any(isinstance(c,dict)
                and c.get("name") in ("tesseract","tesseract-ocr","libtesseract5")
                and c.get("version") == "5.5.4"
                for c in components)
except (OSError,ValueError,TypeError):
    covered=False
raise SystemExit(0 if covered else 2)
PY
then
  printf '{"status":"blocked","reason":"ocr_not_tracked_in_sbom"}\n'
  exit 2
fi

# Never auto-promote this research image even if the scanner eventually
# recognizes the custom component. Review provenance and security separately.
printf '{"status":"blocked","reason":"experimental_custom_ocr_requires_review"}\n'
exit 2
