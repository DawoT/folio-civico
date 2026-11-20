#!/usr/bin/env bash
# R1.21: bounded source-method regression. Must run inside Poppler builder only.
set -euo pipefail
umask 022

# Reuse the exact SHA-pinned Debian source, 7 Debian fixes, 3 prior prototypes
# and sixth research overlay attestations; runs the 9 R1.19 method controls.
bash /prototypes/run_splash_ymax_overlay.sh

cd /work
for variant in original patched extended; do
  source="/work/$variant"
  test -d "$source"
  g++ -std=c++20 -O1 -g -fsanitize=address,undefined \
    -fno-sanitize-recover=all -fno-omit-frame-pointer \
    -I /work/build-method -I /work/build-method/poppler \
    -I "$source" -I "$source/splash" \
    /prototypes/splash_public_test_probe.cc \
    "$source/splash/SplashClip.cc" \
    "$source/splash/SplashXPath.cc" \
    "$source/splash/SplashXPathScanner.cc" \
    "$source/splash/SplashPath.cc" \
    -o "/work/splash-public-test-$variant"
  test -x "/work/splash-public-test-$variant"
  for input in normal x_aa_overflow; do
    prefix="/results/$variant-publictest_$input"
    set +e
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
      UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
      timeout --signal=TERM --kill-after=2s 6s \
      "/work/splash-public-test-$variant" "$input" \
      > "$prefix.stdout" 2> "$prefix.stderr"
    rc="$?"
    set -e
    printf '%s\n' "$rc" > "$prefix.exit"
    test "$(wc -c < "$prefix.stdout")" -lt 2048
    test "$(wc -c < "$prefix.stderr")" -lt 16384
  done
done
printf 'r121-source-only-public-test-ubsan-complete\n'
