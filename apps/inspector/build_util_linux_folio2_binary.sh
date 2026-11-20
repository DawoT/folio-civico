#!/usr/bin/env bash
# R1.37 — non-deployable Debian 13.7 folio2 source-to-binary laboratory.
# All .deb are UNRELEASED, UNSIGNED and must never be installed on host/runtime.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 4 || "$1" != "--source-dir" || "$3" != "--output-dir" ]]; then
  printf '{"status":"error","reason":"requires_source_and_output_dir","release_authorized":false}\n'
  exit 3
fi
SRC="$2"
OUT="$4"
# Prevent Docker --mount option injection by path punctuation; never overlap.
if [[ ! "$SRC" =~ ^/[a-zA-Z0-9_./-]+$ || ! "$OUT" =~ ^/[a-zA-Z0-9_./-]+$ ]]; then
  printf '{"status":"error","reason":"unsafe_docker_bind_path","release_authorized":false}\n'
  exit 3
fi
for tool in docker python3 timeout; do command -v "$tool" >/dev/null; done

set +e
REPORT="$(python3 apps/inspector/util_linux_folio2_binary.py --source-dir "$SRC")"
STATUS=$?
set -e
printf '%s\n' "$REPORT"
[[ "$STATUS" == 2 ]] || exit 3

# Required fresh capacity and explicitly local Docker endpoint.
python3 apps/inspector/preflight.py --mode build
IMAGE="docker.io/library/debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}')" == unix://* ]]
docker image inspect "$IMAGE" >/dev/null

python3 - "$SRC" "$OUT" <<'PY'
from pathlib import Path
import sys
src, dest = (Path(p) for p in sys.argv[1:])
if (not src.is_absolute() or not dest.is_absolute() or
        '..' in dest.parts or dest in (Path('/'), Path('/tmp')) or
        dest.is_symlink() or dest.exists() or not dest.parent.is_dir() or
        dest.parent.is_symlink() or dest.parent.resolve(strict=True) != dest.parent or
        src == dest or src in dest.parents or dest in src.parents):
    raise SystemExit(3)
PY

mkdir -m 700 -- "$OUT"
printf '%s\n' 'UNSIGNED, UNRELEASED experimental util-linux folio2 only; release BLOCKED.' \
  > "$OUT/NOT_FOR_RELEASE.txt"
chmod 600 "$OUT/NOT_FOR_RELEASE.txt"

# APT access is required for signed Debian 13 build dependencies. Docker bridge
# networking is NOT egress filtered. No host apt installation or registry push.
# The only host writable bind is the private new output; input is read-only.
timeout 900s docker run --rm --pull never \
  --network bridge --cap-drop ALL \
  --cap-add CHOWN --cap-add SETGID --cap-add SETUID \
  --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --security-opt no-new-privileges --pids-limit 512 \
  --cpus 2 --memory 6g --memory-swap 6g \
  --mount "type=bind,src=$SRC,dst=/source,readonly" \
  --mount "type=bind,src=$OUT,dst=/out" \
  -e DEBIAN_FRONTEND=noninteractive -e SOURCE_DATE_EPOCH=1795190400 \
  -e OUTPUT_UID="$(id -u)" -e OUTPUT_GID="$(id -g)" \
  "$IMAGE" bash -euc '
    test "$(cat /etc/debian_version)" = 13.7
    test "$(dpkg --print-architecture)" = amd64
    sed -i "s/^Types: deb$/Types: deb deb-src/" \
      /etc/apt/sources.list.d/debian.sources
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      build-essential dpkg-dev fakeroot ca-certificates
    apt-get build-dep -y -qq --no-install-recommends util-linux

    # Recheck mounted source bytes in the container (TOCTOU defense).
    printf "%s  %s\n" \
      "e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed" \
      "/source/util-linux_2.41.6.orig.tar.xz" \
      "204326e759e7b81b03b23eae8b43a65567512eccaf862dcf2426212c05145288" \
      "/source/util-linux_2.41.6-0+folio2~deb13u1.debian.tar.xz" \
      "a0301270ca8ca6f9000bf48097f0b51a29aa07b9d7dc0182f486f59fe85439b6" \
      "/source/util-linux_2.41.6-0+folio2~deb13u1.dsc" \
      | sha256sum --check -
    mkdir /build
    dpkg-source --no-check -x \
      /source/util-linux_2.41.6-0+folio2~deb13u1.dsc /build/util-linux
    cd /build/util-linux
    # All security/portability changes must already be in the 11 quilt patches.
    test "$(wc -l < debian/patches/series)" -eq 11
    test "$(tail -n 1 debian/patches/series)" = \
      "upstream/folio-r136-openat2-header.patch"
    grep -q "^# include <linux/openat2.h>$" libmount/src/hook_idmap.c
    printf "%s  %s\n" \
      "e12678246515279507185598710821dc23387b08b84b4eeb9b4977e733e391c1" \
      "libmount/src/hook_idmap.c" | sha256sum --check -
    sha256sum libmount/src/hook_idmap.c > /out/QUILT_SOURCE_SHA256.txt
    dpkg-checkbuilddeps
    dpkg-buildpackage --build=binary --no-sign --jobs=2
    test -n "$(find /build -maxdepth 1 -name "*.deb" -print -quit)"
    cp /build/*.deb /out/
    for f in /build/*.buildinfo /build/*.changes; do
      test -f "$f" && cp "$f" /out/ || :
    done
    {
      printf "debian_version=%s\n" "$(cat /etc/debian_version)"
      printf "architecture=%s\n" "$(dpkg --print-architecture)"
      printf "source_version=2.41.6-0+folio2~deb13u1\n"
      printf "binary_artifacts=%s\n" "$(find /build -maxdepth 1 -name "*.deb" | wc -l)"
      printf "release_authorized=false\n"
    } > /out/BINARY_RESEARCH_ONLY.txt
    chown "$OUTPUT_UID:$OUTPUT_GID" /out/*
    chmod 600 /out/*
  '

# Independent Debian 13 offline metadata gate: no network, no caps,
# no root filesystem writes, nonprivileged UID, private read-only artifacts.
timeout 120s docker run --rm --pull never --read-only \
  --network none --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
  --pids-limit 64 --cpus 1 --memory 1g \
  --mount "type=bind,src=$OUT,dst=/out,readonly" \
  "$IMAGE" sh -euc '
    test "$(cat /etc/debian_version)" = 13.7
    test "$(dpkg --print-architecture)" = amd64
    count=0
    for f in /out/*.deb; do
      test -f "$f"
      package="$(dpkg-deb --field "$f" Package)"
      case "$package" in
        login|login-dbgsym) expected="1:4.16.0-2+really2.41.6-0+folio2~deb13u1" ;;
        bsdutils|bsdutils-dbgsym) expected="1:2.41.6-0+folio2~deb13u1" ;;
        *) expected="2.41.6-0+folio2~deb13u1" ;;
      esac
      test "$(dpkg-deb --field "$f" Version)" = "$expected"
      count=$((count + 1))
    done
    test "$count" -eq 43
    echo "offline_debian13_metadata_packages=$count"
  '

python3 apps/inspector/util_linux_folio2_binary.py \
  --source-dir "$SRC" --binary-dir "$OUT"
# A complete experimental build still fails the security/release gate.
exit 2
