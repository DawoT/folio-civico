#!/usr/bin/env bash
# R1.42: local-only, disposable scratch flattening of Poppler research image.
# Does NOT publish, deploy, attest CVE applicability, or change candidate tags.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_flatten_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build

SOURCE="folio-civico-inspector:poppler-experiment"
IMAGE="folio-civico-inspector:poppler-flat-research"
EXPECTED_SOURCE_ID="sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f"
SOURCE_ID="$(docker image inspect "$SOURCE" --format '{{.Id}}')"
if [[ "$SOURCE_ID" != "$EXPECTED_SOURCE_ID" ]]; then
  printf '{"status":"error","reason":"unapproved_poppler_source_id"}\n'
  exit 3
fi
if [[ ! "$SOURCE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  printf '{"status":"error","reason":"invalid_poppler_source_image_id"}\n'
  exit 3
fi
# BuildKit may try to fetch local manifest-list repo@sha256 via a registry.
# Supply a content-derived LOCAL tag and verify its immutable image ID.
SOURCE_PIN="folio-civico-inspector:poppler-flat-source-${SOURCE_ID#sha256:}"
ALIAS_ID="$(docker image inspect "$SOURCE_PIN" --format '{{.Id}}' 2>/dev/null || true)"
if [[ -n "$ALIAS_ID" && "$ALIAS_ID" != "$SOURCE_ID" ]]; then
  printf '{"status":"error","reason":"poppler_source_alias_mismatch"}\n'
  exit 3
fi
if [[ -z "$ALIAS_ID" ]]; then
  docker tag "$SOURCE_ID" "$SOURCE_PIN"
fi
if [[ "$(docker image inspect "$SOURCE_PIN" --format '{{.Id}}')" != "$SOURCE_ID" ]]; then
  printf '{"status":"error","reason":"poppler_source_alias_resolution_failed"}\n'
  exit 3
fi

# All build stages consume already-existing local Docker images. No apt, no
# runtime RUN, no network, and no mutable source tag for the FROM reference.
docker build --pull=false --network=none \
  --file apps/inspector/Dockerfile.poppler-flat-research \
  --build-arg "POPPLER_FLAT_SOURCE=$SOURCE_PIN" \
  --tag "$IMAGE" apps/inspector
FLAT_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ ! "$FLAT_ID" =~ ^sha256:[0-9a-f]{64}$ || "$FLAT_ID" == "$SOURCE_ID" ]]; then
  printf '{"status":"error","reason":"invalid_flat_image_id"}\n'
  exit 3
fi
if [[ "$(docker image inspect "$SOURCE" --format '{{.Id}}')" != "$SOURCE_ID" ]]; then
  printf '{"status":"error","reason":"poppler_source_tag_changed"}\n'
  exit 3
fi

# Strict layer DiffID proof before any PDF parser is exercised.
python3 - "$SOURCE_ID" "$FLAT_ID" <<'PY'
import json
import re
import subprocess
import sys

EMPTY = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
def layers(image_id):
    proc = subprocess.run(
        ["docker", "image", "inspect", image_id],
        capture_output=True, text=True, check=True, timeout=25,
    )
    data = json.loads(proc.stdout)[0]["RootFS"]
    if data.get("Type") != "layers":
        raise ValueError("Unexpected Docker root filesystem type")
    return data["Layers"]

before, after = layers(sys.argv[1]), layers(sys.argv[2])
if (len(before) < 3 or len(after) != 2 or after.count(EMPTY) != 1
        or any(not re.fullmatch(r"sha256:[a-f0-9]{64}", x) for x in after)
        or (set(before) & set(after)) - {EMPTY}):
    raise SystemExit("Historical nonempty Docker layer survived scratch flattening")
PY

# Use the immutable, locally built ID for every real parser/HTTP/freshness smoke.
for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$FLAT_ID" "/srv/folio-inspector/$smoke"
done
docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --cpus 1 --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 "$FLAT_ID" -c \
  "$(cat apps/inspector/smoke_signature_freshness.py)"

if [[ "$SOURCE_ID" != "$(docker image inspect "$SOURCE" --format '{{.Id}}')" ]] \
    || [[ "$SOURCE_ID" != "$(docker image inspect "$SOURCE_PIN" --format '{{.Id}}')" ]] \
    || [[ "$FLAT_ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"source_or_flat_image_tag_changed"}\n'
  exit 3
fi
printf '{"status":"local_flattened_smoke_passed","release_authorized":false}\n'
