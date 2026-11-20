#!/usr/bin/env bash
# R1.33: authenticated Debian Trixie source + upstream 2.41.6 quilt overlay.
# Default is EPHEMERAL; --export-dir creates a private UNSIGNED source handoff.
# Never install, Docker build, push, deploy or issue VEX/waivers. Exit 2=blocked.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
EXPORT=()
if [[ "$#" -eq 2 && "$1" == "--export-dir" && -n "$2" ]]; then
  EXPORT=(--export-dir "$2")
elif [[ "$#" -ne 0 ]]; then
  printf '{"status":"error","reason":"unsupported_debian_overlay_option","release_authorized":false}\n'
  exit 3
fi
for command in python3 curl gpg dpkg-source git tar xz mktemp; do
  command -v "$command" >/dev/null
done
OUT="$(mktemp -d "/tmp/folio-debian-source-r133.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT

fetch() {
  local name="$1" url="$2"
  if ! curl --fail --location --silent --show-error \
    --proto '=https' --connect-timeout 12 --max-time 120 \
    --retry 3 --retry-delay 1 \
    "$url" --output "$OUT/$name"; then
    printf '{"status":"error","reason":"signed_source_fetch_failed","release_authorized":false}\n'
    exit 3
  fi
}

KERNEL="https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.41"
DEBIAN="https://deb.debian.org/debian/pool/main/u/util-linux"

# Signed upstream release, independent kernel.org checksum autosigner,
# SHA-pinned CVE-2026-78408 follow-up patch (no OpenPGP signature on patch).
fetch util-linux-2.41.6.tar.xz "$KERNEL/util-linux-2.41.6.tar.xz"
fetch util-linux-2.41.6.tar.sign "$KERNEL/util-linux-2.41.6.tar.sign"
fetch sha256sums.asc "$KERNEL/sha256sums.asc"
fetch karel-zak.asc \
  "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284"
fetch kernel-autosigner.asc \
  "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1"
fetch cve-2026-78408-close-fd.patch \
  "https://github.com/util-linux/util-linux/commit/485dbb67f1b6bb18e08b1b77f4aa2373ff3a705b.patch"

# Debian Trixie source 2.41.5-0+deb13u1 with the detached maintainer key.
# The .dsc has a clearsigned SHA256 manifest for the two source tarballs.
fetch "util-linux_2.41.5-0+deb13u1.dsc" \
  "$DEBIAN/util-linux_2.41.5-0%2Bdeb13u1.dsc"
fetch "util-linux_2.41.5.orig.tar.xz" \
  "$DEBIAN/util-linux_2.41.5.orig.tar.xz"
fetch "util-linux_2.41.5-0+deb13u1.debian.tar.xz" \
  "$DEBIAN/util-linux_2.41.5-0%2Bdeb13u1.debian.tar.xz"
fetch debian-maintainer.asc \
  "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x7D1ACFFAD9E0806C9C4CD3925C13D6DB93052E03"

# An authenticated and rebuilt *SOURCE* overlay must exit 2 because
# no Debian binary package/ABI test/release exists. Any failure exits 3.
python3 apps/inspector/util_linux_debian_source_overlay.py \
  --artifacts-dir "$OUT" "${EXPORT[@]}"
