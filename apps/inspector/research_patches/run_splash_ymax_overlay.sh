#!/usr/bin/env bash
# R1.19: SOURCE-ONLY guard overlay after five SHA-pinned research changes.
# Invoked solely inside the isolated builder by poppler_splash_ymax_probe.py.
set -euo pipefail
umask 022

test "$(dpkg-parsechangelog -l /src/poppler-25.03.0/debian/changelog -S Version)" = "25.03.0-5+deb13u4"
test -d /fixes && test -d /prototypes && test -d /fixtures && test -d /results
test "$(pkg-config --exists freetype2 && printf yes)" = yes
mkdir -p /work
cp -r /src/poppler-25.03.0 /work/original
cd /work/original
sha256sum --check /fixtures/baseline.sha256
cp -r /work/original /work/patched

(cd /fixes && sha256sum --check /fixtures/direct-patches.sha256)
(cd /prototypes && sha256sum --check /fixtures/research-patches.sha256)
cd /work/patched
patch --batch --forward --fuzz=0 -p1 -i /fixes/CVE-2026-102620.patch
patch --batch --forward --fuzz=0 -p1 -i /fixes/CVE-2026-93311.patch
patch --batch --forward --fuzz=0 -p1 -i /prototypes/CVE-2026-102621-trixie-prototype.patch
patch --batch --forward --fuzz=0 -p1 -i /prototypes/CVE-2026-93312-trixie-prototype.patch
patch --batch --forward --fuzz=0 -p1 -i /prototypes/CVE-2026-93313-trixie-prototype.patch
sha256sum --check /fixtures/patched.sha256

# Copy only after verifying all five research patches. The sixth amendment
# is deliberately NOT included in the pinned CVE-prototype set of R1.13.
cp -r /work/patched /work/extended
(cd /prototypes && sha256sum --check /fixtures/overlay.sha256)
cd /work/extended
patch --batch --forward --fuzz=0 -p1 -i /prototypes/SplashClip-ymax-checked-research-overlay.patch
sha256sum --check /fixtures/extended.sha256

# Configure Poppler solely for generated config.h and poppler-config.h
# (method harness, no full PDF parser/renderer binary built here).
export HOME=/work XDG_CACHE_HOME=/work/.cache
cmake -S /work/patched -B /work/build-method -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=ON \
    -DFONT_CONFIGURATION=fontconfig \
    -DENABLE_LIBCURL=OFF -DENABLE_GPGME=OFF -DENABLE_NSS3=OFF \
    -DENABLE_CPP=OFF -DENABLE_GLIB=OFF -DENABLE_QT5=OFF -DENABLE_QT6=OFF \
    -DENABLE_CAIRO=OFF -DENABLE_LIBTIFF=OFF -DENABLE_BOOST=OFF \
    -DENABLE_UTILS=OFF >/work/cmake-report.log
test -f /work/build-method/config.h
test -f /work/build-method/poppler/poppler-config.h

cd /work
for variant in original patched extended; do
  source="/work/$variant"
  g++ -std=c++20 -O1 -g -fsanitize=address,undefined \
      -fno-sanitize-recover=all -fno-omit-frame-pointer \
      -I /work/build-method -I /work/build-method/poppler \
      -I "$source" -I "$source/splash" \
      /prototypes/splash_ymax_method_probe.cc \
      "$source/splash/SplashClip.cc" \
      "$source/splash/SplashXPath.cc" \
      "$source/splash/SplashXPathScanner.cc" \
      "$source/splash/SplashPath.cc" \
      -o "/work/splash-$variant"
  test -x "/work/splash-$variant"
  for condition in normal ymin_overflow ymax_overflow; do
    prefix="/results/$variant-$condition"
    set +e
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
      UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
      timeout --signal=TERM --kill-after=2s 6s \
      "/work/splash-$variant" "$condition" \
      > "$prefix.stdout" 2> "$prefix.stderr"
    code="$?"
    set -e
    printf '%s\n' "$code" > "$prefix.exit"
    test "$(wc -c < "$prefix.stderr")" -lt 16384
    test "$(wc -c < "$prefix.stdout")" -lt 2048
  done
done
printf 'r119-source-only-splash-ymax-experiment-complete\n'
