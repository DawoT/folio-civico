#!/usr/bin/env bash
# R1.32: non-root LOCAL source-only compile smoke; NEVER deploy/install/run nsenter.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 2 || "$1" != "--artifacts-dir" ]]; then
  printf '{"status":"error","reason":"source_build_usage","release_authorized":false}\n'
  exit 3
fi
SRC_DIR="$2"
for tool in python3 xz tar gpg git cc make timeout sha256sum; do
  command -v "$tool" >/dev/null
done
if [[ "$(id -u)" -eq 0 ]]; then
  printf '{"status":"error","reason":"root_source_build_forbidden","release_authorized":false}\n'
  exit 3
fi
OUT="$(mktemp -d "/tmp/folio-ul-native-build-r132.XXXXXX")"
chmod 700 "$OUT"
trap 'rm -rf -- "$OUT"' EXIT

# A successful source proof returns exit 2 on purpose: no package/release.
set +e
python3 apps/inspector/util_linux_source_candidate.py \
  --artifacts-dir "$SRC_DIR" > "$OUT/verified-source.json"
status="$?"
set -e
if [[ "$status" -ne 2 ]]; then
  printf '{"status":"error","reason":"signed_source_proof_failed","release_authorized":false}\n'
  exit 3
fi

mkdir "$OUT/source" "$OUT/build"
timeout 60s tar --extract --xz \
  --file "$SRC_DIR/util-linux-2.41.6.tar.xz" \
  --directory "$OUT/source" --strip-components=1 \
  --no-same-owner --no-same-permissions
(
  cd "$OUT/source"
  timeout 15s git apply --check --verbose \
    "$SRC_DIR/cve-2026-78408-close-fd.patch"
  timeout 15s git apply --whitespace=error \
    "$SRC_DIR/cve-2026-78408-close-fd.patch"
)
(
  cd "$OUT/build"
  # Disable every unrelated util-linux program and DSO. This is a native host
  # compile smoke of one binary, not Debian Trixie package validation.
  timeout 180s "$OUT/source/configure" \
    --disable-all-programs --enable-nsenter \
    --disable-libuuid --disable-libblkid \
    --disable-libsmartcols --disable-libmount \
    --without-python --without-systemd \
    --without-selinux --disable-shared --disable-static \
    --disable-nls > "$OUT/configure.log" 2>&1
  timeout 180s make --jobs=4 nsenter > "$OUT/build.log" 2>&1
  test -x "$OUT/build/nsenter"
  # Never run this utility with target PID, credentials or namespace options.
  version="$(timeout 10s "$OUT/build/nsenter" --version)"
  test "$version" = "nsenter from util-linux 2.41.6"
  timeout 10s "$OUT/build/nsenter" --help \
    > "$OUT/help.log" 2>&1
)
binary_sha="$(sha256sum "$OUT/build/nsenter" | cut -d ' ' -f 1)"
printf '{"status":"patched_nsenter_native_host_smoke_passed_release_blocked","version":"2.41.6","source_signed":true,"supplemental_cve_78408_backport":true,"native_host_binary_sha256":"%s","unprivileged_build":true,"only_version_help_invoked":true,"installed":false,"debian_package_built":false,"runtime_image_replaced":false,"security_gate":"blocked","release_authorized":false}\n' "$binary_sha"
exit 2
