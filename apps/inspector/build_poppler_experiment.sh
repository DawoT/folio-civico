#!/usr/bin/env bash
# Manual, disposable local research only. Does not overwrite validation or
# ocr-integrated tags, deploy, publish ports or access institutional files.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -gt 0 ]]; then
  printf '{"status":"error","reason":"unsupported_experiment_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build
BASE="folio-civico-inspector:ocr-integrated"
IMAGE="folio-civico-inspector:poppler-experiment"
BEFORE="$(docker image inspect "$BASE" --format '{{.Id}}')"
docker build --file apps/inspector/Dockerfile.poppler-experiment \
  --tag "$IMAGE" apps/inspector
AFTER="$(docker image inspect "$BASE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"candidate_image_changed"}\n'
  exit 3
fi

# Prove custom Poppler and no observed network/kerberos chain in PDF parsers.
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint /bin/sh "$IMAGE" -c '
    set -eu
    test -r /opt/folio-poppler/source-provenance.json
    for binary in pdfinfo pdftoppm pdftotext pdfdetach pdfattach; do
      resolved="$(command -v "$binary")"
      test "$resolved" = "/opt/folio-poppler/bin/$binary"
      linked="$(ldd "$resolved")"
      ! printf "%s\n" "$linked" | grep -E "not found|libcurl|libgssapi|libkrb5|libk5crypto"
    done
    for package in poppler-utils libpoppler147 libcurl3t64-gnutls libgssapi-krb5-2 libkrb5-3 libk5crypto3 libkrb5support0; do
      if dpkg-query -W "$package" >/dev/null 2>&1; then
        echo "Unexpected Debian Poppler/network package: $package" >&2
        exit 1
      fi
    done
    test -s /usr/share/tesseract-ocr/5/tessdata/spa.traineddata
    test -s /usr/share/tesseract-ocr/5/tessdata/eng.traineddata
  '

for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$IMAGE" "/srv/folio-inspector/$smoke"
done
