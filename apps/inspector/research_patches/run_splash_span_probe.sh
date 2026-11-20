#!/usr/bin/env bash
# R1.24: isolated Poppler method test; NOT a runtime fix or an exploit test.
set -euo pipefail
umask 022

# Attest Debian source, official fixes, 5 prototypes and sixth overlay,
# and rerun 9 clipToPath + 6 public test controls before new scenarios.
bash /prototypes/run_splash_public_test.sh

cd /work
for variant in original patched extended; do
  source="/work/$variant"
  test -d "$source"
  g++ -std=c++20 -O1 -g -fsanitize=address,undefined \
    -fno-sanitize-recover=all -fno-omit-frame-pointer \
    -I /work/build-method -I /work/build-method/poppler \
    -I "$source" -I "$source/splash" \
    /prototypes/splash_span_method_probe.cc \
    "$source/splash/SplashClip.cc" \
    "$source/splash/SplashXPath.cc" \
    "$source/splash/SplashXPathScanner.cc" \
    "$source/splash/SplashPath.cc" \
    -o "/work/splash-span-$variant"
  test -x "/work/splash-span-$variant"
  for condition in normal no_path_extreme outside_guard span_x_aa_overflow; do
    prefix="/results/$variant-span_$condition"
    set +e
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
      UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
      timeout --signal=TERM --kill-after=2s 6s \
      "/work/splash-span-$variant" "$condition" \
      > "$prefix.stdout" 2> "$prefix.stderr"
    rc="$?"
    set -e
    printf '%s\n' "$rc" > "$prefix.exit"
    test "$(wc -c < "$prefix.stdout")" -lt 2048
    test "$(wc -c < "$prefix.stderr")" -lt 16384
  done
done
printf 'r124-source-only-span-method-ubsan-complete\n'
