#!/usr/bin/env bash
# R1.47: unsigned util-linux folio2 integration with same-DB CVE coverage; NEVER RELEASE.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 4 || "$1" != "--source-dir" || "$3" != "--binary-dir" ]]; then
  printf '{"status":"error","reason":"source_and_binary_dirs_required","release_authorized":false}\n'
  exit 3
fi
SOURCE_DIR="$2"
BINARY_DIR="$4"
for command in docker trivy python3; do
  command -v "$command" >/dev/null
done
python3 apps/inspector/preflight.py --mode build >/dev/null
BEFORE="folio-civico-inspector:surface-pruned-research-r146"
AFTER="folio-civico-inspector:folio2-runtime-research-r147"
EXPECTED="sha256:c0011755a54a4af8c749ef60a2d0f40be5a186dbb071ea19d760e34a7d8360ee"
BEFORE_ID="$(docker image inspect "$BEFORE" --format '{{.Id}}')"
AFTER_ID="$(docker image inspect "$AFTER" --format '{{.Id}}')"
if [[ "$BEFORE_ID" != "$EXPECTED" \
      || ! "$AFTER_ID" =~ ^sha256:[a-f0-9]{64}$ \
      || "$AFTER_ID" == "$BEFORE_ID" ]]; then
  printf '{"status":"error","reason":"research_image_identity_mismatch"}\n'
  exit 3
fi
PRIVATE="$(mktemp -d "${TMPDIR:-/tmp}/folio-r147-folio2-evidence.XXXXXX")"
chmod 700 "$PRIVATE"
trap 'rm -rf -- "$PRIVATE"' EXIT

# Only previously pinned, private unsigned sources/binaries are admissible.
python3 - "$SOURCE_DIR" "$BINARY_DIR" <<'PY'
import pathlib,sys
sys.path.insert(0,"apps/inspector")
from util_linux_folio2_binary import validate_source
from util_linux_folio2_consumer_smoke import verify_binary_handoff
validate_source(pathlib.Path(sys.argv[1]))
verify_binary_handoff(pathlib.Path(sys.argv[2]))
PY
set +e
python3 apps/inspector/util_linux_folio2_cve_regression.py \
  --source-dir "$SOURCE_DIR" > "$PRIVATE/source-report.json"
SOURCE_STATUS=$?
set -e
if [[ "$SOURCE_STATUS" -ne 2 ]]; then
  printf '{"status":"error","reason":"source_cve_scope_unverified","release_authorized":false}\n'
  exit 3
fi


# Update once, compare BOTH images against the SAME local DB snapshot. Never
# use --ignore-unfixed, exception files, or severity filters to alter findings.
trivy image --download-db-only --no-progress
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format json --output "$PRIVATE/before-scan.json" "$BEFORE"
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format json --output "$PRIVATE/after-scan.json" "$AFTER"
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format cyclonedx --output "$PRIVATE/before-sbom.json" "$BEFORE"
trivy image --scanners vuln --skip-db-update --no-progress \
  --image-src docker --format cyclonedx --output "$PRIVATE/after-sbom.json" "$AFTER"

docker image inspect "$BEFORE_ID" > "$PRIVATE/before-inspect-array.json"
docker image inspect "$AFTER_ID" > "$PRIVATE/after-inspect-array.json"
# Convert the Docker inspect single-element arrays without losing fields.
python3 - "$PRIVATE" <<'PY'
import json, pathlib, sys
base=pathlib.Path(sys.argv[1])
for prefix in ('before','after'):
    source=base/(prefix+'-inspect-array.json')
    parsed=json.loads(source.read_text(encoding='utf-8'))
    if not isinstance(parsed,list) or len(parsed)!=1:
        raise SystemExit('Expected one immutable Docker inspection record')
    (base/(prefix+'-inspect.json')).write_text(json.dumps(parsed[0]))
PY

# Native code and model inventories must remain bit-identical; never infer
# safety from missing package records or an ELF ldd snapshot alone.
for side in before after; do
  if [[ "$side" == "before" ]]; then ID="$BEFORE_ID"; else ID="$AFTER_ID"; fi
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$ID" -I -c \
    "$(cat apps/inspector/source_inventory.py)" --mode experiment \
    > "$PRIVATE/$side-native.json"
done

# Reject newly setuid/setgid executable paths; no privileged workload is run.
PRIVILEGE_SCRIPT="$(cat <<'PY'
import json,os,stat
record={}
for folder in ('/usr/bin','/usr/sbin'):
    for root, _, files in os.walk(folder):
        for name in files:
            path=os.path.join(root,name)
            try:
                mode=os.stat(path).st_mode
            except OSError:
                continue
            if mode & (stat.S_ISUID | stat.S_ISGID):
                record[path]=oct(mode & 0o7777)
print(json.dumps(record,sort_keys=True))
PY
)"
for side in before after; do
  if [[ "$side" == "before" ]]; then ID="$BEFORE_ID"; else ID="$AFTER_ID"; fi
  docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 \
    --cpus 1 --memory 1g --memory-swap 1g \
    --entrypoint python3 "$ID" -I -c "$PRIVILEGE_SCRIPT" \
    > "$PRIVATE/$side-privileges.json"
done

if [[ "$BEFORE_ID" != "$(docker image inspect "$BEFORE" --format '{{.Id}}')" \
      || "$AFTER_ID" != "$(docker image inspect "$AFTER" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_tag_changed_during_comparison"}\n'
  exit 3
fi

# Return 2 for valid evidence, 3 for malformed/insufficient evidence.
# Both statuses prohibit release. The raw reports stay in private tmpfs/files
# only for this invocation and are deleted when the script exits.
python3 apps/inspector/util_linux_folio2_runtime_audit.py \
  --before-scan "$PRIVATE/before-scan.json" \
  --after-scan "$PRIVATE/after-scan.json" \
  --before-sbom "$PRIVATE/before-sbom.json" \
  --after-sbom "$PRIVATE/after-sbom.json" \
  --before-inspect "$PRIVATE/before-inspect.json" \
  --after-inspect "$PRIVATE/after-inspect.json" \
  --before-native "$PRIVATE/before-native.json" \
  --after-native "$PRIVATE/after-native.json" \
  --source-report "$PRIVATE/source-report.json" \
  --before-privileges "$PRIVATE/before-privileges.json" \
  --after-privileges "$PRIVATE/after-privileges.json" \
  --before-id "$BEFORE_ID" --after-id "$AFTER_ID"
