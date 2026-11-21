#!/usr/bin/env bash
# R1.47 — eight verified but UNSIGNED local folio2 packages, research-only.
# Requires old R1.36 source and R1.37 binary directories; no host installs.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 4 || "$1" != "--source-dir" || "$3" != "--binary-dir" ]]; then
  printf '{"status":"error","reason":"source_and_binary_dirs_required","release_authorized":false}\n'
  exit 3
fi
SOURCE_DIR="$2"
BINARY_DIR="$4"

python3 - "$SOURCE_DIR" "$BINARY_DIR" <<'PY'
import pathlib,sys,hashlib
sys.path.insert(0,"apps/inspector")
from util_linux_folio2_binary import validate_source, SOURCE_VERSION, expected_binary_version
from util_linux_folio2_consumer_smoke import verify_binary_handoff
source,binaries=(pathlib.Path(x) for x in sys.argv[1:])
validate_source(source)
verify_binary_handoff(binaries)
expected={
    "util-linux":"99c9a623b957ef85bec89547ef437dc9b0a885b0a513d55b22aa3f8dd41f4210",
    "bsdutils":"87cc66547957259a411b5a48fbf1a77c105c982f853ff1181f194c553a290d21",
    "login":"a002b50c773b7d131b997a6cf455e13f04fe9df186ebfee06ecdbde2cee8be53",
    "libblkid1":"c9a66ba4240baf50d0b861817c9efc940facbd9dc8d35b762723a73a760177a1",
    "liblastlog2-2":"ff8b2db5217bbf61ee3a6345e627a15a4767743adcb47fa6b390a5a6615905d7",
    "libmount1":"12b47b934c0561dd120879b4b7f8a849558ec4c23b0ab546d4a3b7ff5f7e8c59",
    "libsmartcols1":"0a1f7ac40f3f6a7d783f43883e8259a1d12b0e72ed1d76718bde42615d235513",
    "libuuid1":"811ebda0609b334ca359e39dc9dc1c3f366e6b69f584ec2c69045b2cf8d2a155",
}
for name,pin in expected.items():
    pattern=name+"_*_amd64.deb"
    matches=list(binaries.glob(pattern))
    if len(matches)!=1 or matches[0].is_symlink():
        raise SystemExit("Invalid staged Debian package identity")
    blob=matches[0].read_bytes()
    if hashlib.sha256(blob).hexdigest()!=pin:
        raise SystemExit("Unsigned Debian binary hash changed")
PY

# A source guard check must return 2: static proof with release still blocked.
set +e
SOURCE_PROOF="$(python3 apps/inspector/util_linux_folio2_cve_regression.py --source-dir "$SOURCE_DIR")"
SOURCE_STATUS=$?
set -e
if [[ "$SOURCE_STATUS" -ne 2 ]]; then
  printf '{"status":"error","reason":"unverified_folio2_cve_source","release_authorized":false}\n'
  exit 3
fi
python3 -c 'import json,sys; r=json.loads(sys.argv[1]); assert r["source_cve_paths_accounted_for"] and r["release_authorized"] is False and r["unresolved_cve_paths"]==[]' "$SOURCE_PROOF"

python3 apps/inspector/preflight.py --mode build >/dev/null
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}')" == unix://* ]] || {
  printf '{"status":"error","reason":"local_docker_required"}\n'; exit 3;
}
BASE="folio-civico-inspector:surface-pruned-research-r146"
NEW="folio-civico-inspector:folio2-runtime-research-r147"
PIN="sha256:c0011755a54a4af8c749ef60a2d0f40be5a186dbb071ea19d760e34a7d8360ee"
test "$(docker image inspect "$BASE" --format '{{.Id}}')" = "$PIN"
BASE_ALIAS="folio-civico-inspector:folio2-local-source-${PIN#sha256:}"
ALIAS_ID="$(docker image inspect "$BASE_ALIAS" --format '{{.Id}}' 2>/dev/null || true)"
if [[ -n "$ALIAS_ID" && "$ALIAS_ID" != "$PIN" ]]; then
  printf '{"status":"error","reason":"research_base_alias_conflict"}\n'
  exit 3
fi
if [[ -z "$ALIAS_ID" ]]; then docker tag "$PIN" "$BASE_ALIAS"; fi
test "$(docker image inspect "$BASE_ALIAS" --format '{{.Id}}')" = "$PIN"

# BuildKit only sees eight COPY destinations from the private named context.
# Docker build has no network; no Dockerfile/apt state is modified in production.
docker build --pull=false --network=none \
  --build-context "folio2_debs=$BINARY_DIR" \
  --file apps/inspector/Dockerfile.util-linux-folio2-runtime-research \
  --build-arg "RESEARCH_BASE=$BASE_ALIAS" \
  --tag "$NEW" apps/inspector
NEW_ID="$(docker image inspect "$NEW" --format '{{.Id}}')"
if [[ ! "$NEW_ID" =~ ^sha256:[a-f0-9]{64}$ || "$NEW_ID" == "$PIN" ]]; then
  printf '{"status":"error","reason":"invalid_folio2_runtime_identity"}\n'
  exit 3
fi
test "$(docker image inspect "$BASE" --format '{{.Id}}')" = "$PIN"

for smoke in smoke_real_engines.py smoke_http_real.py; do
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --entrypoint python3 "$NEW_ID" "/srv/folio-inspector/$smoke"
done
docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --entrypoint python3 "$NEW_ID" -c "$(cat apps/inspector/smoke_signature_freshness.py)"
test "$(docker image inspect "$NEW" --format '{{.Id}}')" = "$NEW_ID"
printf '{"status":"unsigned_folio2_build_and_smokes_complete_release_blocked","release_authorized":false}\n'
exit 2
