#!/usr/bin/env bash
# Isolated, manual CVE mitigation trial. No promotion, push or remote changes.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_experiment_option"}\n'
  exit 3
fi
python3 apps/inspector/preflight.py --mode build
BASE="folio-civico-inspector:poppler-experiment"
IMAGE="folio-civico-inspector:expat-experiment"
# Explicit research parent. Never build on an unexpected retargeted tag.
EXPECTED_BASE_ID="sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f"
BEFORE="$(docker image inspect "$BASE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$EXPECTED_BASE_ID" ]]; then
  printf '{"status":"error","reason":"invalid_experimental_base_image_id"}\n'
  exit 3
fi
# Local BuildKit cannot reliably resolve a local manifest list by repo@sha256
# without a registry lookup; verify a content-derived local alias instead.
BASE_PIN="folio-civico-inspector:expat-source-${BEFORE#sha256:}"
PINNED="$(docker image inspect "$BASE_PIN" --format '{{.Id}}' 2>/dev/null || true)"
if [[ -n "$PINNED" && "$PINNED" != "$BEFORE" ]]; then
  printf '{"status":"error","reason":"expat_base_alias_mismatch"}\n'
  exit 3
fi
if [[ -z "$PINNED" ]]; then
  docker tag "$BEFORE" "$BASE_PIN"
fi
if [[ "$(docker image inspect "$BASE_PIN" --format '{{.Id}}')" != "$BEFORE" ]]; then
  printf '{"status":"error","reason":"expat_base_alias_resolution_failed"}\n'
  exit 3
fi
docker build --pull=false --file apps/inspector/Dockerfile.expat-experiment \
  --build-arg "EXPAT_BASE_IMAGE=$BASE_PIN" \
  --tag "$IMAGE" apps/inspector
AFTER="$(docker image inspect "$BASE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"experimental_base_changed"}\n'
  exit 3
fi
EXPERIMENT_ID="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
if [[ ! "$EXPERIMENT_ID" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  printf '{"status":"error","reason":"invalid_experiment_image_id"}\n'
  exit 3
fi
# The runtime must resolve Expat 2.10.0 for actual PDF parser dependencies.
docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --memory 4g --memory-swap 4g \
  --entrypoint python3 "$EXPERIMENT_ID" -I -c '
import ctypes, subprocess
lib=ctypes.CDLL("libexpat.so.1")
lib.XML_ExpatVersion.restype=ctypes.c_char_p
assert lib.XML_ExpatVersion() == b"expat_2.10.0"
package=subprocess.check_output(
    ["dpkg-query","-W","-f=${Version}","libexpat1"],text=True,timeout=10)
assert package == "2.10.0-1+folio1"
assert subprocess.run(["/bin/sh","-c","! command -v xmlwf"],check=False,timeout=8).returncode == 0
for binary in ("/opt/folio-poppler/bin/pdfinfo",
               "/opt/folio-poppler/bin/pdftotext",
               "/opt/folio-poppler/bin/pdftoppm"):
    result=subprocess.run(["ldd",binary],capture_output=True,text=True,timeout=12,check=True)
    assert "libexpat.so.1 => /lib/x86_64-linux-gnu/" in result.stdout or (
        "libexpat.so.1 => /usr/lib/x86_64-linux-gnu/" in result.stdout)
    assert "not found" not in result.stdout
'
for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$EXPERIMENT_ID" "/srv/folio-inspector/$smoke"
done
if [[ "$BEFORE" != "$(docker image inspect "$BASE" --format '{{.Id}}')" ]] \
    || [[ "$BEFORE" != "$(docker image inspect "$BASE_PIN" --format '{{.Id}}')" ]] \
    || [[ "$EXPERIMENT_ID" != "$(docker image inspect "$IMAGE" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"experiment_image_changed_during_smoke"}\n'
  exit 3
fi
printf '{"status":"prototype_tested","release_authorized":false,"cve_gate":"blocked"}\n'
