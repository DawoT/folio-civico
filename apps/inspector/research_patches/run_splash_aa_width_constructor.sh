#!/usr/bin/env bash
# R1.27: compile the real Debian Poppler static library in isolated tmpfs.
# Test Splash constructors with a real one-row Mono1 bitmap (~64 MiB).
# No PDF parser, OCI changes, runtime images, CVE waiver, or remote services.
set -euo pipefail
umask 022
test "$(dpkg-parsechangelog -l /src/poppler-25.03.0/debian/changelog -S Version)" = "25.03.0-5+deb13u4"
test -d /fixtures && test -d /results && test -f /prototypes/splash_aa_width_constructor_probe.cc
echo 'dbf3dcafa042348499ccefba4dd586979b7080ffa7064901a7ecebfc4c9fe27c  /src/poppler-25.03.0/splash/Splash.cc' | sha256sum --check -
test "$(grep -Fc 'aaBuf = new SplashBitmap(splashAASize * bitmap->width' /src/poppler-25.03.0/splash/Splash.cc)" -eq 2
(cd /prototypes && sha256sum --check /fixtures/probe-source.sha256)
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
    -DENABLE_UTILS=OFF > /work/cmake-report.log
cmake --build /work/build --parallel 2 --target poppler
test -s /work/build/libpoppler.a
g++ -std=c++20 -O1 -g \
    $SANITIZERS \
    -I/work/build -I/work/build/poppler \
    -I/src/poppler-25.03.0 -I/src/poppler-25.03.0/splash \
    /prototypes/splash_aa_width_constructor_probe.cc \
    /work/build/libpoppler.a \
    -Wl,--start-group -lfontconfig -lfreetype -lpng -ljpeg \
    -lopenjp2 -llcms2 -lz -Wl,--end-group \
    -o /work/splash-ctor-probe
test -x /work/splash-ctor-probe
ldd /work/splash-ctor-probe | grep -q 'libasan.so'
ldd /work/splash-ctor-probe | grep -q 'libubsan.so'
for constructor in params screen; do
  for scenario in normal_aa normal_noaa wide_noaa wide_aa; do
    condition="$constructor-$scenario"
    stem="/results/$condition"
    set +e
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
      UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
      timeout --signal=TERM --kill-after=2s 8s \
      /work/splash-ctor-probe "$constructor""_""$scenario" \
      > "$stem.stdout" 2> "$stem.stderr"
    rc="$?"
    set -e
    printf '%s\n' "$rc" > "$stem.exit"
    test "$(wc -c < "$stem.stdout")" -lt 2048
    test "$(wc -c < "$stem.stderr")" -lt 16384
  done
done
echo 'dbf3dcafa042348499ccefba4dd586979b7080ffa7064901a7ecebfc4c9fe27c  /src/poppler-25.03.0/splash/Splash.cc' | sha256sum --check -
(cd /prototypes && sha256sum --check /fixtures/probe-source.sha256)
printf 'r127-real-splash-constructors-ubsan-complete\n'
