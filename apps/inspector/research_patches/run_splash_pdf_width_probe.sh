#!/usr/bin/env bash
# R1.31: isolate an exact-source Debian Poppler PDF-to-Splash width experiment.
# Research-only, bounded synthetic PDF files. No operational images or network.
set -euo pipefail
umask 022
test "$(dpkg-parsechangelog -l /src/poppler-25.03.0/debian/changelog -S Version)" = "25.03.0-5+deb13u4"
test -d /fixtures && test -d /results && test -d /prototypes
echo 'dbf3dcafa042348499ccefba4dd586979b7080ffa7064901a7ecebfc4c9fe27c  /src/poppler-25.03.0/splash/Splash.cc' | sha256sum --check -
echo 'f551d09a1dce5dda5787cc66305714259a0ba24766a765cbbcd9af27cc0cd741  /src/poppler-25.03.0/poppler/SplashOutputDev.cc' | sha256sum --check -
echo '206d9f4a6e5bb9054e7ef769d3b0fa3e9332b0f2c65ba062fe40f922d80ef7f0  /src/poppler-25.03.0/splash/SplashBitmap.cc' | sha256sum --check -
(cd /fixtures && sha256sum --check /fixtures/r131-corpus.sha256)
export HOME=/work XDG_CACHE_HOME=/work/.cache TMPDIR=/work
SANITIZERS="-fsanitize=address,undefined -fno-sanitize=vptr -fno-sanitize-recover=all -fno-omit-frame-pointer"
cmake -S /src/poppler-25.03.0 -B /work/build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$SANITIZERS" -DCMAKE_CXX_FLAGS="$SANITIZERS" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DBUILD_SHARED_LIBS=OFF -DFONT_CONFIGURATION=fontconfig \
  -DENABLE_LIBCURL=OFF -DENABLE_GPGME=OFF -DENABLE_NSS3=OFF \
  -DENABLE_CPP=OFF -DENABLE_GLIB=OFF -DENABLE_QT5=OFF -DENABLE_QT6=OFF \
  -DENABLE_CAIRO=OFF -DENABLE_LIBTIFF=OFF -DENABLE_BOOST=OFF \
  -DENABLE_UTILS=ON > /work/cmake-report.log
cmake --build /work/build --parallel 2 --target pdftoppm pdfinfo
for tool in pdftoppm pdfinfo; do
  test -x "/work/build/utils/$tool"
  ldd "/work/build/utils/$tool" | grep -q 'libasan.so'
  ldd "/work/build/utils/$tool" | grep -q 'libubsan.so'
done

record() {
  local name="$1"
  shift
  local prefix="/results/$name"
  local rc
  local output="$prefix.stdout"
  if [[ "$name" == "wide_noaa" || "$name" == "wide_aa" || "$name" == "wide_gray_aa" ]]; then
    : > "$prefix.stdout"
    output=/dev/null
  fi
  set +e
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
    timeout --signal=TERM --kill-after=2s 12s \
    "$@" > "$output" 2> "$prefix.stderr"
  rc="$?"
  set -e
  printf '%s\n' "$rc" > "$prefix.exit"
  test "$(wc -c < "$prefix.stdout")" -lt 8192
  test "$(wc -c < "$prefix.stderr")" -lt 16384
}

# Read page metadata without allocating a huge raster.
record wide_metadata /work/build/utils/pdfinfo /fixtures/wide.pdf
# Small real PDF path, positive and negative AA controls.
record normal_noaa /work/build/utils/pdftoppm \
  -f 1 -l 1 -singlefile -mono -r 72 -aa no -aaVector no \
  /fixtures/normal.pdf /results/normal_noaa
record normal_aa /work/build/utils/pdftoppm \
  -f 1 -l 1 -singlefile -mono -r 72 -aa yes -aaVector yes \
  /fixtures/normal.pdf /results/normal_aa
# Scaled extreme MediaBox, strictly tiny rendered pixel dimensions.
record scaled_wide_aa /work/build/utils/pdftoppm \
  -f 1 -l 1 -singlefile -mono -scale-to-x 32 -scale-to-y 1 \
  -aa yes -aaVector yes \
  /fixtures/wide.pdf /results/scaled_wide_aa
# Unscaled 536870919-wide bitmap experiment: isolate process, never save PBM.
# Output goes to /dev/null because a valid result would be ~64MiB.
record wide_noaa /work/build/utils/pdftoppm \
  -f 1 -l 1 -singlefile -mono -r 72 -aa no -aaVector no \
  /fixtures/wide.pdf
record wide_aa /work/build/utils/pdftoppm \
  -f 1 -l 1 -singlefile -mono -r 72 -aa yes -aaVector yes \
  /fixtures/wide.pdf
# Actual AA-enabled image mode: Mono1 is forced to no-AA by SplashOutputDev.
# Gray (Mono8) requires an unusually large allocation; cgroup and 12s timeout apply.
record wide_gray_aa /work/build/utils/pdftoppm \
  -f 1 -l 1 -singlefile -gray -r 72 -aa yes -aaVector yes \
  /fixtures/wide.pdf

echo 'dbf3dcafa042348499ccefba4dd586979b7080ffa7064901a7ecebfc4c9fe27c  /src/poppler-25.03.0/splash/Splash.cc' | sha256sum --check -
echo 'f551d09a1dce5dda5787cc66305714259a0ba24766a765cbbcd9af27cc0cd741  /src/poppler-25.03.0/poppler/SplashOutputDev.cc' | sha256sum --check -
(cd /fixtures && sha256sum --check /fixtures/r131-corpus.sha256)
printf 'r131-synthetic-pdf-width-research-complete\n'
