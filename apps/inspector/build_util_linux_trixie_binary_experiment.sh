#!/usr/bin/env bash
# R1.35: Debian 13 source-to-binary research; no package install on host.
# No publishing, no image changes to the inspector, no VEX or release.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$ROOT"
if [[ "$#" -ne 4 || "$1" != "--source-dir" || "$3" != "--output-dir" ]]; then
  printf '{"status":"error","reason":"expected_source_and_output_dir","release_authorized":false}\n'
  exit 3
fi
SRC="$2"
OUT="$4"
if [[ "$SRC" != /* || "$OUT" != /* || "$SRC" == "$OUT" ]]; then
  printf '{"status":"error","reason":"non_absolute_or_overlapping_paths","release_authorized":false}\n'
  exit 3
fi
for cmd in python3 docker timeout; do command -v "$cmd" >/dev/null; done

# The R1.34 manifest itself is unsigned; compare all THREE file hashes with
# immutable R1.33 pins before a container is allowed to read any input.
set +e
REPORT="$(python3 apps/inspector/util_linux_trixie_binary_experiment.py --source-dir "$SRC")"
CODE=$?
set -e
printf '%s\n' "$REPORT"
if [[ "$CODE" -ne 2 ]]; then exit 3; fi

# Read-only check: local Docker daemon, capacity >=8 GiB, RAM >=4 GiB.
python3 apps/inspector/preflight.py --mode build
IMAGE="docker.io/library/debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
PATCH="$ROOT/apps/inspector/research_patches/util-linux-2.41.6-r135-openat2-include.patch"
if [[ -n "${DOCKER_HOST:-}" && "${DOCKER_HOST}" != unix://* ]]; then exit 3; fi
[[ "$(docker context inspect --format '{{.Endpoints.docker.Host}}')" == unix://* ]]
docker image inspect "$IMAGE" >/dev/null

# Never overwrite a previous experiment, a foreign path or a symlinked parent.
python3 - "$OUT" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
if (not p.is_absolute() or '..' in p.parts or p.exists() or p.is_symlink()
        or not p.parent.is_dir() or p.parent.is_symlink()
        or p.parent.resolve(strict=True) != p.parent
        or p == Path('/') or p == Path('/tmp')):
    raise SystemExit(3)
PY
mkdir -m 700 -- "$OUT"
printf '%s\n' 'UNSIGNED, UNAPPROVED Debian 13 experimental binaries only.' > "$OUT/NOT_FOR_RELEASE.txt"
chmod 600 "$OUT/NOT_FOR_RELEASE.txt"

# The builder may reach only Debian's signed APT repositories; it sees the
# signed-source handoff read-only, and writes only to its own new output folder.
# CAP_CHOWN/SETUID/SETGID/DAC_OVERRIDE are needed by apt's _apt sandbox;
# CAP_SYS_ADMIN/NET_ADMIN and all other capabilities remain absent.
# The container's own filesystem is ephemeral; no host apt or dpkg install.
timeout 900s docker run --rm --pull never \
  --network bridge --cap-drop ALL \
  --cap-add CHOWN --cap-add SETGID --cap-add SETUID --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges --pids-limit 512 \
  --cpus 2 --memory 6g --memory-swap 6g \
  --mount "type=bind,src=$SRC,dst=/source,readonly" \
  --mount "type=bind,src=$PATCH,dst=/research/patch,readonly" \
  --mount "type=bind,src=$OUT,dst=/out" \
  -e DEBIAN_FRONTEND=noninteractive -e SOURCE_DATE_EPOCH=1795190400 \
  -e OUTPUT_UID="$(id -u)" -e OUTPUT_GID="$(id -g)" \
  "$IMAGE" bash -euc '
    test "$(dpkg --print-architecture)" = amd64
    test "$(cat /etc/debian_version)" = 13.7
    sed -i "s/^Types: deb$/Types: deb deb-src/" /etc/apt/sources.list.d/debian.sources
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      build-essential dpkg-dev fakeroot ca-certificates git
    apt-get build-dep -y -qq --no-install-recommends util-linux
    mkdir /build
    dpkg-source --no-check -x \
      /source/util-linux_2.41.6-0+folio1~deb13u1.dsc /build/util-linux
    cd /build/util-linux
    # R1.35 research-only missing header include; never patch the signed tar.
    # Forward-only check: a pre-applied or different patch must fail closed.
    git apply --check /research/patch
    git apply /research/patch
    grep -q "^# include <linux/openat2.h>$" libmount/src/hook_idmap.c
    sha256sum libmount/src/hook_idmap.c > /out/BUILD_ONLY_OPENAT2_SOURCE_SHA256.txt
    dpkg-checkbuilddeps
    dpkg-buildpackage --build=binary --no-sign --jobs=2
    test -n "$(find /build -maxdepth 1 -name "*.deb" -print -quit)"
    # Copy unapproved research artifacts first, so a failing gate leaves
    # inspectable evidence instead of forcing an unnecessary repeat build.
    cp /build/*.deb /out/
    for f in /out/*.deb; do
      pkg="$(dpkg-deb --field "$f" Package)"
      version="$(dpkg-deb --field "$f" Version)"
      case "$pkg" in
        login|login-dbgsym) expected="1:4.16.0-2+really2.41.6-0+folio1~deb13u1" ;;
        bsdutils|bsdutils-dbgsym) expected="1:2.41.6-0+folio1~deb13u1" ;;
        *) expected="2.41.6-0+folio1~deb13u1" ;;
      esac
      if [ "$version" != "$expected" ]; then
        printf "RESEARCH GATE REJECTED: package=%s actual=%s expected=%s\\n" "$pkg" "$version" "$expected" >&2
        exit 3
      fi
    done
    for f in /build/*.buildinfo /build/*.changes; do
      test -f "$f" || continue
      cp "$f" /out/
    done
    {
      printf "debian_version=%s\n" "$(cat /etc/debian_version)"
      printf "architecture=%s\n" "$(dpkg --print-architecture)"
      printf "source_version=2.41.6-0+folio1~deb13u1\n"
      printf "binary_artifacts=%s\n" "$(find /build -maxdepth 1 -name "*.deb" | wc -l)"
    } > /out/BINARY_RESEARCH_ONLY.txt
    chown "$OUTPUT_UID:$OUTPUT_GID" /out/*
    chmod 600 /out/*
  '

# Second, read-only offline admission of the produced packages. No builder
# network, process capability, runtime installation or executable invocation.
timeout 120s docker run --rm --pull never --read-only \
  --network none --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
  --pids-limit 64 --cpus 1 --memory 1g \
  --mount "type=bind,src=$OUT,dst=/out,readonly" \
  "$IMAGE" sh -euc '
    test "$(cat /etc/debian_version)" = "13.7"
    test "$(dpkg --print-architecture)" = amd64
    found=0
    for f in /out/*.deb; do
      test -f "$f"
      case "$(dpkg-deb --field "$f" Package)" in
        login|login-dbgsym) expected="1:4.16.0-2+really2.41.6-0+folio1~deb13u1" ;;
        bsdutils|bsdutils-dbgsym) expected="1:2.41.6-0+folio1~deb13u1" ;;
        *) expected="2.41.6-0+folio1~deb13u1" ;;
      esac
      test "$(dpkg-deb --field "$f" Version)" = "$expected"
      found=$((found + 1))
    done
    test "$found" -gt 0
  '

# Post-build evidence is never a deployable security approval.
python3 apps/inspector/util_linux_trixie_binary_experiment.py \
  --source-dir "$SRC" --binary-dir "$OUT"
exit 2
