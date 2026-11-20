#!/usr/bin/env bash
# R1.16 differential execution inside pinned offline Debian builder.
# Deliberately uses only bash, coreutils and Poppler. Builder has no Python.
set -euo pipefail
umask 022
command -v timeout >/dev/null
for variant in original patched; do
  test -x "/work/build-${variant}/utils/pdftoppm"
  test -f "/work/build-${variant}/libpoppler.so.147"
done
mkdir -p /results
cd /fixtures
sha256sum --check /fixtures/differential-corpus.sha256

for case in sampled32 jbig2_intmin jbig2_zero jbig2_large_page splash_triangle splash_far; do
  test -s "/fixtures/${case}.pdf"
  for variant in original patched; do
    output="/results/${variant}-${case}"
    set +e
    LD_LIBRARY_PATH="/work/build-${variant}" \
      ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
      UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
      timeout --signal=TERM --kill-after=2s 8s \
      "/work/build-${variant}/utils/pdftoppm" -f 1 -l 1 \
      -singlefile -gray -scale-to 128 \
      "/fixtures/${case}.pdf" "${output}" \
      >"${output}.stdout" 2>"${output}.stderr"
    exit_status="$?"
    set -e
    printf '%s\n' "$exit_status" > "${output}.exit"
    test -f "${output}.stderr" && test -f "${output}.stdout"
    test "$(wc -c < "${output}.stderr")" -lt 131072
    if test -f "${output}.pgm"; then
      test "$(wc -c < "${output}.pgm")" -lt 1048576
    fi
  done
done
printf 'r116-differential-synthetic-execution-complete\n'
