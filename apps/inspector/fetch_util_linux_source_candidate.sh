#!/usr/bin/env bash
# R1.32: isolated, signed UPSTREAM SOURCE proof, NOT a Debian package build.
# Never installs packages, alters the runtime, waives CVEs or deploys anything.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_signed_source_option","release_authorized":false}\n'
  exit 3
fi
for tool in curl python3 gpg git tar xz mktemp; do
  command -v "$tool" >/dev/null
done
OUT="$(mktemp -d "/tmp/folio-util-linux-signed-r132.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT

# HTTPS transport alone is insufficient; Python verifies two independent
# OpenPGP signatures and the hardcoded SHA256 of source + upstream patch.
fetch() {
  local name="$1" url="$2"
  curl --fail --location --silent --show-error \
    --proto '=https' --connect-timeout 12 --max-time 90 --retry 2 \
    "$url" --output "$OUT/$name"
}
BASE="https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.41"
fetch util-linux-2.41.6.tar.xz "$BASE/util-linux-2.41.6.tar.xz"
fetch util-linux-2.41.6.tar.sign "$BASE/util-linux-2.41.6.tar.sign"
fetch sha256sums.asc "$BASE/sha256sums.asc"
fetch karel-zak.asc \
  "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284"
fetch kernel-autosigner.asc \
  "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"
fetch cve-2026-78408-close-fd.patch \
  "https://github.com/util-linux/util-linux/commit/485dbb67f1b6bb18e08b1b77f4aa2373ff3a705b.patch"

# A valid candidate MUST exit 2: the Debian package has not been rebuilt
# and the release security gate remains blocked. Any flaw must exit 3.
python3 apps/inspector/util_linux_source_candidate.py --artifacts-dir "$OUT"
