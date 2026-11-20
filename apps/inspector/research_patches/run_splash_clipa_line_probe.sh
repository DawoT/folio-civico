#!/usr/bin/env bash
# R1.26: actual SplashClip::clipAALine with a tiny real SplashBitmap.
# Invoked only in the offline research builder. NO runtime image changes.
set -euo pipefail
umask 022

# Re-run the three SHA-pinned source variants, the 9 R1.19 + 6 R1.21
# + 12 R1.24 checks and their source/patch SHA attestations first.
bash /prototypes/run_splash_span_probe.sh

# Real SplashBitmap constructor/destructor supplied by a separate,
# SHA-pinned, R1.14 *research-only* libpoppler.so helper. This helper
# is NOT compared to production binary and is never installed.
test -f /libhelper/libpoppler.so.147
(cd /libhelper && sha256sum --check /fixtures/helper-lib.sha256)

cd /work
export HOME=/work XDG_CACHE_HOME=/work/.cache
for variant in original patched extended; do
  source="/work/$variant"
  test -d "$source"
  g++ -std=c++20 -O1 -g -fsanitize=address,undefined \
    -fno-sanitize-recover=all -fno-omit-frame-pointer \
    -I /work/build-method -I /work/build-method/poppler \
    -I "$source" -I "$source/splash" \
    /prototypes/splash_clipa_line_method_probe.cc \
    "$source/splash/SplashClip.cc" \
    "$source/splash/SplashXPath.cc" \
    "$source/splash/SplashXPathScanner.cc" \
    "$source/splash/SplashPath.cc" \
    -L/libhelper -Wl,-rpath,/libhelper -l:libpoppler.so.147 \
    -o "/work/splash-clippaaline-$variant"
  test -x "/work/splash-clippaaline-$variant"
  for condition in normal_origin normal_in_bounds invalid_x0 invalid_x1; do
    prefix="/results/$variant-clippaaline_$condition"
    set +e
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
      UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
      timeout --signal=TERM --kill-after=2s 6s \
      "/work/splash-clippaaline-$variant" "$condition" \
      > "$prefix.stdout" 2> "$prefix.stderr"
    rc="$?"
    set -e
    printf '%s\n' "$rc" > "$prefix.exit"
    test "$(wc -c < "$prefix.stdout")" -lt 2048
    test "$(wc -c < "$prefix.stderr")" -lt 16384
  done
done
(cd /libhelper && sha256sum --check /fixtures/helper-lib.sha256)
printf 'r126-source-only-clipaaline-bitmap-ubsan-complete\n'
