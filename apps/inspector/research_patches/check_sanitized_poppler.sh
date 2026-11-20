#!/usr/bin/env bash
# R1.14 research-only PDF smoke on already-compiled ASan/UBSan binaries.
# Must run in the same --network none, --read-only, non-root Docker sandbox.
set -euo pipefail
umask 022
export HOME=/work
export XDG_CACHE_HOME=/work/.cache
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:allocator_may_return_null=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
test -x /work/build/utils/pdftotext
test -x /work/build/utils/pdftoppm
test -x /work/build/utils/pdfinfo
test -f /work/build/libpoppler.so.147
# Prevent accidental execution of the unpatched Poppler packaged in the base image.
export LD_LIBRARY_PATH=/work/build
ldd /work/build/utils/pdftotext | grep -F "/work/build/libpoppler.so.147"
ldd /work/build/utils/pdftotext | grep -F "libasan.so"
ldd /work/build/utils/pdftotext | grep -F "libubsan.so"
ldd /work/build/utils/pdfinfo | grep -F "/work/build/libpoppler.so.147"
ldd /work/build/utils/pdfinfo | grep -F "libasan.so"
ldd /work/build/utils/pdfinfo | grep -F "libubsan.so"

mkdir -p /results

# R1.15: enable leak detection for pdfinfo ONLY; previous Poppler renderer
# probes retain detect_leaks=0 pending their separate lifecycle review.
for fixture in native scanned clipped sampled32 linked; do
  ASAN_OPTIONS="detect_leaks=1:abort_on_error=1" \
    /work/build/utils/pdfinfo "/fixtures/${fixture}.pdf" > "/results/pdfinfo-${fixture}.txt"
  grep -Eq '^Pages:[[:space:]]+1$' "/results/pdfinfo-${fixture}.txt"
  grep -Eq '^Encrypted:[[:space:]]+no$' "/results/pdfinfo-${fixture}.txt"
  grep -Eq '^PDF version:[[:space:]]+1\.4$' "/results/pdfinfo-${fixture}.txt"
done
ASAN_OPTIONS="detect_leaks=1:abort_on_error=1" \
  /work/build/utils/pdfinfo -url /fixtures/linked.pdf > /results/linked-urls.txt
test "$(grep -Fc 'https://example.invalid/folio-r115' /results/linked-urls.txt)" -eq 1
/work/build/utils/pdftotext -enc UTF-8 /fixtures/native.pdf /results/native.txt
grep -q "EXPEDIENTE OBRA 2026" /results/native.txt
/work/build/utils/pdftoppm -f 1 -l 1 -singlefile -gray -scale-to 850 \
  /fixtures/native.pdf /results/native > /results/native-render.log 2>&1
test -s /results/native.pgm

/work/build/utils/pdftotext -enc UTF-8 /fixtures/scanned.pdf /results/scanned.txt
test ! -s /results/scanned.txt || test "$(tr -d '[:space:]' < /results/scanned.txt)" = ""
/work/build/utils/pdftoppm -f 1 -l 1 -singlefile -gray -scale-to 850 \
  /fixtures/scanned.pdf /results/scanned > /results/scanned-render.log 2>&1
test -s /results/scanned.pgm

/work/build/utils/pdftoppm -f 1 -l 1 -singlefile -gray -scale-to 850 \
  /fixtures/clipped.pdf /results/clipped > /results/clipped-render.log 2>&1
test -s /results/clipped.pgm

/work/build/utils/pdftoppm -f 1 -l 1 -singlefile -gray -scale-to 850 \
  /fixtures/sampled32.pdf /results/sampled32 > /results/sampled-render.log 2>&1
test -s /results/sampled32.pgm

# A deliberately truncated synthetic PDF must not crash or trigger sanitizer.
set +e
/work/build/utils/pdftotext /fixtures/truncated.pdf /results/truncated.txt \
  > /results/truncated.stdout 2> /results/truncated.stderr
MALFORMED_EXIT="$?"
set -e
if [[ "$MALFORMED_EXIT" -gt 128 ]]; then
  printf 'Malformed sample crashed: %s\n' "$MALFORMED_EXIT" >&2
  exit 15
fi
if grep -Eq 'AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:' /results/truncated.stderr; then
  printf 'Sanitizer reported an error on malformed synthetic PDF\n' >&2
  exit 16
fi
printf '{"build":"asan_ubsan_complete","native_pdf":"parsed","scan_pdf":"parsed","clip_pdf":"rendered","sampled_function_32bit":"rendered","pdfinfo_sanitized_link_verified":true,"pdfinfo_leak_probe_passed":true,"malformed_exit":%s,"release_authorized":false}\n' "$MALFORMED_EXIT"
