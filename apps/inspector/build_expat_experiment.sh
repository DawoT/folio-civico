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
BEFORE="$(docker image inspect "$BASE" --format '{{.Id}}')"
docker build --file apps/inspector/Dockerfile.expat-experiment \
  --tag "$IMAGE" apps/inspector
AFTER="$(docker image inspect "$BASE" --format '{{.Id}}')"
if [[ "$BEFORE" != "$AFTER" ]]; then
  printf '{"status":"error","reason":"experimental_base_changed"}\n'
  exit 3
fi
# The runtime must resolve Expat 2.10.0 for actual PDF parser dependencies.
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --memory 4g --memory-swap 4g \
  --entrypoint python3 "$IMAGE" -I -c '
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
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$IMAGE" "/srv/folio-inspector/$smoke"
done
printf '{"status":"prototype_tested","release_authorized":false,"cve_gate":"blocked"}\n'
