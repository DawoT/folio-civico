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

# The runtime must not retain the build-only curl downloader.
# GPG is a required transitive dependency of Poppler in Debian Trixie.
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --entrypoint /bin/sh folio-civico-inspector:validation \
  -c '! command -v curl'

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
