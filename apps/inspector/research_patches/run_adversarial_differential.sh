#!/usr/bin/env bash
# R1.16: strictly isolated *source-only* baseline-vs-prototypes build.
# Must be invoked only by poppler_adversarial_differential.py inside Docker.
set -euo pipefail
umask 022
test "$(dpkg-parsechangelog -l /src/poppler-25.03.0/debian/changelog -S Version)" = "25.03.0-5+deb13u4"
test -d /fixes && test -d /prototypes && test -d /fixtures && test -d /results
test "$(pkg-config --exists freetype2 && printf yes)" = "yes"
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

export HOME=/work XDG_CACHE_HOME=/work/.cache
SANITIZERS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
for state in original patched; do
  cmake -S "/work/$state" -B "/work/build-$state" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="$SANITIZERS" -DCMAKE_CXX_FLAGS="$SANITIZERS" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DBUILD_SHARED_LIBS=ON \
    -DFONT_CONFIGURATION=fontconfig \
    -DENABLE_LIBCURL=OFF -DENABLE_GPGME=OFF -DENABLE_NSS3=OFF \
    -DENABLE_CPP=OFF -DENABLE_GLIB=OFF -DENABLE_QT5=OFF -DENABLE_QT6=OFF \
    -DENABLE_CAIRO=OFF -DENABLE_LIBTIFF=OFF -DENABLE_BOOST=OFF \
    -DENABLE_UTILS=ON
  cmake --build "/work/build-$state" --parallel 2 --target pdftoppm
  test -x "/work/build-$state/utils/pdftoppm"
  test -f "/work/build-$state/libpoppler.so.147"
  LD_LIBRARY_PATH="/work/build-$state" ldd "/work/build-$state/utils/pdftoppm" |
    grep -F "/work/build-$state/libpoppler.so.147"
  ldd "/work/build-$state/utils/pdftoppm" | grep -F "libasan.so"
  ldd "/work/build-$state/utils/pdftoppm" | grep -F "libubsan.so"
done
bash /prototypes/run_adversarial_cases.sh
