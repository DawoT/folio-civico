#!/usr/bin/env bash
# Optional local security gate, NOT part of the lightweight CI test suite.
# Scans ONLY Folio Civico's known local Docker image. Never pushes/deploys.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

IMAGE="folio-civico-inspector:validation"
# --candidate and --triage may be combined, without changing the CVE gate.
# The candidate tag is never promoted to the approved validation tag.
TRIAGE_MODE=""
CANDIDATE_MODE=0
if [[ "$#" -gt 2 ]]; then
  printf '{"status":"error","reason":"unsupported_audit_option"}\n'
  exit 3
fi
for option in "$@"; do
  case "$option" in
    --triage)
      if [[ -n "$TRIAGE_MODE" ]]; then
        printf '{"status":"error","reason":"duplicate_audit_option"}\n'
        exit 3
      fi
      TRIAGE_MODE="--triage"
      ;;
    --candidate)
      if [[ "$CANDIDATE_MODE" -eq 1 ]]; then
        printf '{"status":"error","reason":"duplicate_audit_option"}\n'
        exit 3
      fi
      CANDIDATE_MODE=1
      ;;
    *)
      printf '{"status":"error","reason":"unsupported_audit_option"}\n'
      exit 3
      ;;
  esac
done
if [[ "$CANDIDATE_MODE" -eq 1 ]]; then
  IMAGE="folio-civico-inspector:ocr-integrated"
fi
command -v docker >/dev/null
command -v trivy >/dev/null
# Repo and Docker daemon must have adequate space, and the daemon must be local.
python3 apps/inspector/preflight.py --mode build >/dev/null

BEFORE="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/folio-civico-scan.XXXXXX")"
trap 'rm -rf -- "$OUTPUT"' EXIT

# Do not suppress findings, ignore unfixed issues, or skip DB updates.
# Missing database, failed scan or empty output must never become "passed".
trivy image --scanners vuln --format json --output "$OUTPUT/vulns.json" \
  --no-progress --image-src docker "$IMAGE"
trivy image --scanners vuln --format cyclonedx --output "$OUTPUT/sbom.json" \
  --no-progress --image-src docker "$IMAGE"

AFTER="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"image_changed_during_audit"}\n'
  exit 3
fi

# Always run the authoritative gate first. Preserve its nonzero exit code.
# Any diagnostic failure or disagreement is a hard error, never a pass.
AUDIT_EXIT=0
python3 apps/inspector/audit_image.py \
  --vulnerabilities "$OUTPUT/vulns.json" \
  --sbom "$OUTPUT/sbom.json" --image "$IMAGE" || AUDIT_EXIT=$?
if [[ "$AUDIT_EXIT" -ne 0 && "$AUDIT_EXIT" -ne 2 ]]; then
  exit "$AUDIT_EXIT"
fi

if [[ "$TRIAGE_MODE" == "--triage" ]]; then
  # Inspect only the already-built local image. No host mounts, no network
  # access, no published ports, no image mutations or institutional data.
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$BEFORE" -c "$(cat apps/inspector/runtime_inventory.py)" \
    > "$OUTPUT/runtime-inventory.json"
  # The runtime check uses the immutable image ID, not the mutable tag.
  # Guard against a tag being repointed while the diagnostic ran.
  AFTER_TRIAGE="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
  if [[ "$BEFORE" != "$AFTER_TRIAGE" ]]; then
    printf '{"status":"error","reason":"image_changed_during_triage"}\n'
    exit 3
  fi
  TRIAGE_EXIT=0
  python3 apps/inspector/triage_image.py \
    --vulnerabilities "$OUTPUT/vulns.json" --sbom "$OUTPUT/sbom.json" \
    --inventory "$OUTPUT/runtime-inventory.json" --image "$IMAGE" || TRIAGE_EXIT=$?
  if [[ "$TRIAGE_EXIT" -ne "$AUDIT_EXIT" ]]; then
    printf '{"status":"error","reason":"triage_gate_mismatch"}\n'
    exit 3
  fi
fi

exit "$AUDIT_EXIT"
