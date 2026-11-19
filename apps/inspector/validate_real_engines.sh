#!/usr/bin/env bash
# Explicit opt-in: builds ONLY the Folio Cívico inspector image after safe
# local disk/RAM/Docker-daemon checks. Does not touch Cloudflare or other images.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python3 apps/inspector/preflight.py --mode build

docker build --pull \
  --tag folio-civico-inspector:validation \
  apps/inspector

# GPG is required by Poppler in Trixie; curl is build-only. The source-built
# OCR binary must not reintroduce archive/XML libraries via dynamic links.
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --entrypoint /bin/sh folio-civico-inspector:validation \
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
docker run --rm \
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
  folio-civico-inspector:validation \
  /srv/folio-inspector/smoke_real_engines.py --database /opt/clamdb

# Exercise the ACTUAL HTTP handler and patched engine on loopback inside
# the same network-disabled container. It receives only synthetic credentials.
docker run --rm \
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
  folio-civico-inspector:validation \
  /srv/folio-inspector/smoke_http_real.py
