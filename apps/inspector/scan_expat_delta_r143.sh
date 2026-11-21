#!/usr/bin/env bash
# R1.43: strict same-DB Trivy / CycloneDX / source-ELF differential.
# Local research only. A verified differential still exits 2 (BLOCKED).
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_expat_delta_option"}\n'
  exit 3
fi
command -v docker >/dev/null
command -v trivy >/dev/null
python3 apps/inspector/preflight.py --mode build >/dev/null
OLD="folio-civico-inspector:poppler-experiment"
NEW="folio-civico-inspector:expat-experiment"
OLD_ID="$(docker image inspect "$OLD" --format '{{.Id}}')"
NEW_ID="$(docker image inspect "$NEW" --format '{{.Id}}')"
if [[ "$OLD_ID" != "sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f" ]] \
    || [[ ! "$NEW_ID" =~ ^sha256:[a-f0-9]{64}$ ]] \
    || [[ "$OLD_ID" == "$NEW_ID" ]]; then
  printf '{"status":"error","reason":"invalid_expat_delta_images"}\n'
  exit 3
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/folio-expat-delta-r143.XXXXXX")"
chmod 700 "$WORK"
trap 'rm -rf -- "$WORK"' EXIT

# One fresh DB snapshot for BOTH scans; compare exact vulnerability records
# to rule out hiding CVEs from unrelated packages. No suppressions or VEX.
trivy image --download-db-only --no-progress
for variant in old new; do
  if [[ "$variant" == old ]]; then
    REF="$OLD"; ID="$OLD_ID"
  else
    REF="$NEW"; ID="$NEW_ID"
  fi
  trivy image --scanners vuln --skip-db-update --no-progress \
    --image-src docker --format json \
    --output "$WORK/${variant}-scan.json" "$REF"
  trivy image --scanners vuln --skip-db-update --no-progress \
    --image-src docker --format cyclonedx \
    --output "$WORK/${variant}-sbom.json" "$REF"
  timeout 90s docker run --rm --pull never --network none --read-only \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
    --entrypoint python3 "$ID" -I -c \
    "$(cat apps/inspector/source_inventory.py)" --mode experiment \
    > "$WORK/${variant}-native.json"
done

# Validate installed ELF, Debian version, source and patch fingerprints, and
# direct Poppler parser linkage in the same immutable experimental artifact.
timeout 90s docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$NEW_ID" -I -c \
  "$(cat apps/inspector/expat_runtime_inventory.py)" \
  > "$WORK/expat-native.json"

# Bounded Expat probes never prove exploit-complete CVE remediation.
# The multi-gigabyte CVE-2026-118370 path remains deliberately unexercised.
timeout 90s docker run --rm --pull never --network none --read-only \
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --cpus 1 --memory 4g --memory-swap 4g \
  --entrypoint python3 "$NEW_ID" -I -c \
  "$(cat apps/inspector/expat_cve_regression.py)" --probe \
  > "$WORK/expat-bounded.json"
python3 - "$WORK/expat-bounded.json" "$WORK/expat-native.json" <<'PY'
import json
import pathlib
import sys

sys.path.insert(0, "apps/inspector")
from expat_cve_regression import PROBE_STATES

probe = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
native = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if (probe.get("status") != "bounded_probes_passed_not_release"
        or probe.get("release_authorized") is not False
        or probe.get("vex") != "not_issued"
        or probe.get("engine_version") != "expat_2.10.0"
        or probe.get("package_version") != "2.10.0-1+folio1"
        or probe.get("libexpat_sha256") != native.get("library_sha256")
        or probe.get("cve_probes") != PROBE_STATES
        or probe.get("max_input_bytes") != 100000
        or probe.get("max_milliseconds") != 15000):
    raise SystemExit("Bounded Expat probe cannot establish native evidence")
PY

if [[ "$OLD_ID" != "$(docker image inspect "$OLD" --format '{{.Id}}')" ]] \
    || [[ "$NEW_ID" != "$(docker image inspect "$NEW" --format '{{.Id}}')" ]]; then
  printf '{"status":"error","reason":"image_changed_during_expat_delta"}\n'
  exit 3
fi

python3 apps/inspector/expat_delta_r143.py \
  --old-scan "$WORK/old-scan.json" --new-scan "$WORK/new-scan.json" \
  --old-sbom "$WORK/old-sbom.json" --new-sbom "$WORK/new-sbom.json" \
  --old-native "$WORK/old-native.json" --new-native "$WORK/new-native.json" \
  --expat-native "$WORK/expat-native.json" \
  --old-id "$OLD_ID" --new-id "$NEW_ID"
