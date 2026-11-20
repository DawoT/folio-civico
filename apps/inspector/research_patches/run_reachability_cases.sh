#!/usr/bin/env bash
# R1.17 offline, rootless synthetic cases. No institutional PDFs.
set -euo pipefail
umask 022
test -d /results && test -d /fixtures
cd /fixtures
sha256sum --check /fixtures/r117-corpus.sha256
command -v timeout >/dev/null
for variant in original patched; do
  test -x "/work/splash-method-$variant"
  test -x "/work/build-$variant/utils/pdftops"
  test -x "/work/build-$variant/utils/pdftoppm"

  for mode in normal ymin_overflow ymax_residual; do
    prefix="/results/$variant-splash_$mode"
    set +e
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
      UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
      timeout --signal=TERM --kill-after=2s 5s \
      "/work/splash-method-$variant" "$mode" \
      > "$prefix.stdout" 2> "$prefix.stderr"
    rc="$?"
    set -e
    printf '%s\n' "$rc" > "$prefix.exit"
    test "$(wc -c < "$prefix.stderr")" -lt 16384
    test "$(wc -c < "$prefix.stdout")" -lt 2048
  done

  for case in jbig2_zero_width jbig2_zero_height jbig2_zero_stripe; do
    prefix="/results/$variant-$case"
    set +e
    LD_LIBRARY_PATH="/work/build-$variant" \
      ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
      UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
      timeout --signal=TERM --kill-after=2s 8s \
      "/work/build-$variant/utils/pdftoppm" -f 1 -l 1 \
      -singlefile -gray -scale-to 128 \
      "/fixtures/$case.pdf" "$prefix" \
      > "$prefix.stdout" 2> "$prefix.stderr"
    rc="$?"
    set -e
    printf '%s\n' "$rc" > "$prefix.exit"
    test "$(wc -c < "$prefix.stderr")" -lt 16384
    test "$(wc -c < "$prefix.stdout")" -lt 2048
    test -f "$prefix.pgm"
    test "$(wc -c < "$prefix.pgm")" -lt 1048576
  done

  prefix="/results/$variant-type42_synthetic"
  set +e
  LD_LIBRARY_PATH="/work/build-$variant" \
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=0 \
    timeout --signal=TERM --kill-after=2s 8s \
    "/work/build-$variant/utils/pdftops" -level2 -f 1 -l 1 \
    /fixtures/type42_synthetic.pdf "$prefix.ps" \
    > "$prefix.stdout" 2> "$prefix.stderr"
  rc="$?"
  set -e
  printf '%s\n' "$rc" > "$prefix.exit"
  test "$(wc -c < "$prefix.stderr")" -lt 16384
  test "$(wc -c < "$prefix.stdout")" -lt 2048
  test -f "$prefix.ps"
  test "$(wc -c < "$prefix.ps")" -lt 131072
done
printf 'r117-method-and-parser-reachability-complete\n'
