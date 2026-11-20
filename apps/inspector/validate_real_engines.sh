#!/usr/bin/env bash
# Explicit opt-in: builds ONLY the Folio Cívico inspector image after safe
# local disk/RAM/Docker-daemon checks. Does not touch Cloudflare or other images.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ "$#" -gt 1 ]] || { [[ "$#" -eq 1 ]] && [[ "$1" != "--candidate" ]]; }; then
  printf '{"status":"error","reason":"unsupported_validation_option"}\n'
  exit 3
fi
IMAGE="folio-civico-inspector:validation"
if [[ "${1:-}" == "--candidate" ]]; then
  IMAGE="folio-civico-inspector:ocr-integrated"
fi
python3 apps/inspector/preflight.py --mode build

# Force a fresh signatures layer even if Docker reuses all code/toolchain
# layers. The image ID and available signatures must be rechecked afterward.
REFRESH_EPOCH="$(date -u +%s)"
docker build --pull \
  --build-arg "CLAMAV_SIGNATURE_REFRESH_EPOCH=$REFRESH_EPOCH" \
  --tag "$IMAGE" \
  apps/inspector

# Verify exactly the built artifact before running any parser smoke. An image
# tag may be retargeted, so no test may use the mutable name after this point.
IMAGE_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ ! "$IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  printf '{"status":"error","reason":"invalid_built_image_id"}\n'
  exit 3
fi

# GPG is required by Poppler in Trixie; curl is build-only. The source-built
# OCR binary must not reintroduce archive/XML libraries via dynamic links.
docker run --rm --pull never --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --entrypoint /bin/sh "$IMAGE_ID" \
  -c 'set -eu
      ! command -v curl
      test -r /opt/folio-ocr/source-provenance.json
      test ! -e /lib/x86_64-linux-gnu/libxml2.so.2
      test ! -e /lib/x86_64-linux-gnu/libarchive.so.13
      ! ldd /opt/folio-ocr/bin/tesseract | grep -E "(libarchive|libcurl|libxml2)"
      ! ldd /opt/folio-ocr/lib/libtesseract.so.5.5.4 | grep -E "(libarchive|libcurl|libxml2)"
      ! dpkg-query -W -f="\${Status}\\n" libxml2 libarchive13t64 libtesseract5 tesseract-ocr 2>/dev/null | grep -q "^install ok installed$"
      python3 -c "import json; p=json.load(open(\"/opt/folio-ocr/source-provenance.json\")); assert p == {\"name\":\"tesseract\",\"version\":\"5.5.4\",\"source_sha256\":\"a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4\",\"archive\":False,\"curl\":False}"'

# No network or public ports. The smoke CLI needs no production secrets.
# 4 GiB is the official ClamAV recommended container memory, not the old
# insufficient 768 MiB limit. No PDF/test file survives container exit.
docker run --rm --pull never \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --cpus 1 \
  --memory 4g \
  --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 \
  "$IMAGE_ID" \
  /srv/folio-inspector/smoke_real_engines.py --database /opt/clamdb

# Exercise the ACTUAL HTTP handler and patched engine on loopback inside
# the same network-disabled container. It receives only synthetic credentials.
docker run --rm --pull never \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --cpus 1 \
  --memory 4g \
  --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 \
  "$IMAGE_ID" \
  /srv/folio-inspector/smoke_http_real.py

# A logical future clock (not a system-clock change) must make signatures
# fail closed once the 72-hour freshness cap is exceeded.
docker run --rm --pull never \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --cpus 1 \
  --memory 4g \
  --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 \
  "$IMAGE_ID" -c "$(cat apps/inspector/smoke_signature_freshness.py)"

# Even though every smoke uses the immutable ID, changes to the candidate
# tag during validation are an error, not evidence for a different candidate.
AFTER_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ "$AFTER_ID" != "$IMAGE_ID" ]]; then
  printf '{"status":"error","reason":"image_changed_during_smoke"}\n'
  exit 3
fi
