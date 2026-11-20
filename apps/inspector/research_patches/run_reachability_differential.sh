#!/usr/bin/env bash
# R1.17 source-method + synthetic PDF reachability, never a runtime build.
set -euo pipefail
umask 022

# Reuse R1.16's single, strict source/patch preparation and two independently
# instrumented Poppler libraries; no duplicated acquisition or bypass.
bash /prototypes/run_adversarial_differential.sh

for variant in original patched; do
  source="/work/$variant"
  build="/work/build-$variant"
  test -d "$source" && test -d "$build"
  test -f "$build/config.h" && test -f "$build/poppler/poppler-config.h"
  cmake --build "$build" --parallel 2 --target pdftops
  test -x "$build/utils/pdftops"
  LD_LIBRARY_PATH="$build" ldd "$build/utils/pdftops" |
    grep -F "$build/libpoppler.so.147"
  ldd "$build/utils/pdftops" | grep -F 'libasan.so'
  ldd "$build/utils/pdftops" | grep -F 'libubsan.so'

  # Compile the ACTUAL SplashClip::clipToPath and local collaborators from
  # each SHA-verified tree. Direct method tests are NOT PDF parser tests.
  cd /work
  g++ -std=c++20 -O1 -g -fsanitize=address,undefined \
    -fno-sanitize-recover=all -fno-omit-frame-pointer \
    -I "$build" -I "$build/poppler" -I "$source" -I "$source/splash" \
    /prototypes/splash_clip_method_probe.cc \
    "$source/splash/SplashClip.cc" \
    "$source/splash/SplashXPath.cc" \
    "$source/splash/SplashXPathScanner.cc" \
    "$source/splash/SplashPath.cc" \
    -o "/work/splash-method-$variant"
  test -x "/work/splash-method-$variant"

  # The existing Trixie invalid-page guard deletes a failed allocation
  # before reset(). It does not prove all JBIG2 invalid states unreachable.
  grep -Fq 'pageBitmap = new JBIG2Bitmap(0, pageW, curPageH);' \
    "$source/poppler/JBIG2Stream.cc"
  grep -Fq 'if (!pageBitmap->isOk()) {' "$source/poppler/JBIG2Stream.cc"
done

cd /fixtures
sha256sum --check /fixtures/r117-corpus.sha256
bash /prototypes/run_reachability_cases.sh
