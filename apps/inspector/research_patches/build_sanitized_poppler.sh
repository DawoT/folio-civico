#!/usr/bin/env bash
# R1.14 research ONLY. Runs inside the immutable, isolated Poppler builder.
# No runtime image, OCI tag, release gate, user PDF or network access.
set -euo pipefail
umask 022
test -d /src/poppler-25.03.0
test -d /fixes
test -d /prototypes
test -d /fixtures
test -d /results
test "$(dpkg-parsechangelog -l /src/poppler-25.03.0/debian/changelog -S Version)" = "25.03.0-5+deb13u4"
test "$(pkg-config --exists freetype2 && printf yes)" = "yes"

mkdir -p /work
# Never patch the builder's original source; keep everything in tmpfs.
cp -r /src/poppler-25.03.0 /work/source
cd /work/source
sha256sum --check /fixtures/baseline.sha256

(cd /fixes && sha256sum --check /fixtures/direct-patches.sha256)
(cd /prototypes && sha256sum --check /fixtures/research-patches.sha256)

patch --batch --forward --fuzz=0 -p1 -i /fixes/CVE-2026-102620.patch
patch --batch --forward --fuzz=0 -p1 -i /fixes/CVE-2026-93311.patch
patch --batch --forward --fuzz=0 -p1 -i /prototypes/CVE-2026-102621-trixie-prototype.patch
patch --batch --forward --fuzz=0 -p1 -i /prototypes/CVE-2026-93312-trixie-prototype.patch
patch --batch --forward --fuzz=0 -p1 -i /prototypes/CVE-2026-93313-trixie-prototype.patch
sha256sum --check /fixtures/patched.sha256

# R1.15: typeinfo for AnnotLink has hidden visibility in Debian's libpoppler.
# UBSan's vptr instrumentation in pdfinfo would require that non-exported RTTI.
# Scope the exemption to pdfinfo's *compiler* target, not Poppler or other utils.
# Only the isolated /work copy's CMakeLists.txt changes, after SHA validation.
CMAKE_UTILS=/work/source/utils/CMakeLists.txt
test "$(grep -Fxc 'add_executable(pdfinfo ${pdfinfo_SOURCES})' "$CMAKE_UTILS")" -eq 1
! grep -Fq 'target_compile_options(pdfinfo PRIVATE -fno-sanitize=vptr)' "$CMAKE_UTILS"
printf '\n# R1.15 isolated sanitizer test only: hidden AnnotLink RTTI.\ntarget_compile_options(pdfinfo PRIVATE -fno-sanitize=vptr)\n' >> "$CMAKE_UTILS"
test "$(grep -Fxc 'target_compile_options(pdfinfo PRIVATE -fno-sanitize=vptr)' "$CMAKE_UTILS")" -eq 1

export HOME=/work
export XDG_CACHE_HOME=/work/.cache
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:allocator_may_return_null=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
SANITIZERS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
cmake -S /work/source -B /work/build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$SANITIZERS" \
  -DCMAKE_CXX_FLAGS="$SANITIZERS" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DBUILD_SHARED_LIBS=ON \
  -DFONT_CONFIGURATION=fontconfig \
  -DENABLE_LIBCURL=OFF -DENABLE_GPGME=OFF -DENABLE_NSS3=OFF \
  -DENABLE_CPP=OFF -DENABLE_GLIB=OFF -DENABLE_QT5=OFF -DENABLE_QT6=OFF \
  -DENABLE_CAIRO=OFF -DENABLE_LIBTIFF=OFF -DENABLE_BOOST=OFF \
  -DENABLE_UTILS=ON

cmake --build /work/build --parallel 2 --target pdftotext pdftoppm pdfinfo
bash /prototypes/check_sanitized_poppler.sh
