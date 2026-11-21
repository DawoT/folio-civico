#!/usr/bin/env bash
# R1.51 research-only: identity of sixth Poppler ELF in an immutable local image.
# No new build, network, user documents, OCI publication, cloud or CVE waiver.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

error() {
  printf '{"status":"pdfimages_elf_provenance_incomplete","scanner_gate":"blocked","release_authorized":false}\n'
  exit 3
}
[[ "$#" -eq 0 ]] || error
if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" != unix://* ]]; then
  error
fi
LOCAL_SOCKET="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" || error
[[ "$LOCAL_SOCKET" == unix://* ]] || error

IMAGE_ID="sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a"
BEFORE="$(docker image inspect "$IMAGE_ID" --format '{{.Id}}' 2>/dev/null)" || error
[[ "$BEFORE" == "$IMAGE_ID" ]] || error
for file in source_inventory.py audit_image.py pdfimages_elf_provenance.py; do
  [[ -f "$ROOT/apps/inspector/$file" && ! -L "$ROOT/apps/inspector/$file" ]] || error
done

# Read-only source scripts enter a non-root, fully offline, capacity-bounded
# research container. Never mount the host repo, credentials or PDF corpora.
result=""
code=0
result="$(docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
  --mount "type=bind,source=$ROOT/apps/inspector/source_inventory.py,target=/probe/source_inventory.py,readonly" \
  --mount "type=bind,source=$ROOT/apps/inspector/audit_image.py,target=/probe/audit_image.py,readonly" \
  --mount "type=bind,source=$ROOT/apps/inspector/pdfimages_elf_provenance.py,target=/probe/pdfimages_elf_provenance.py,readonly" \
  --entrypoint python3 "$IMAGE_ID" -I -c \
  'import sys;sys.path.insert(0,"/probe");import pdfimages_elf_provenance as p;raise SystemExit(p.main())' \
  --image-id "$IMAGE_ID" 2>/dev/null)" || code=$?

[[ "$code" -eq 2 ]] || error
AFTER="$(docker image inspect "$IMAGE_ID" --format '{{.Id}}' 2>/dev/null)" || error
[[ "$AFTER" == "$BEFORE" ]] || error
# The Python verifier emits a strict, bounded one-line JSON and exits 2 only
# for the still-blocked, confirmed identity. Never reinterpret 2 as approval.
[[ "${#result}" -gt 80 && "${#result}" -lt 8192 && "$result" != *$'\n'* ]] || error
printf '%s\n' "$result"
exit 2
