# Folio Cívico: vendor-signed ClamAV 1.5.5 and isolated PDF runtime.
# Builds are manual; no Cloudflare resources or institutional PDFs are touched.
#
# Vendor artifact verification is isolated in a disposable build stage.
# curl and GPG never enter the runtime image that processes untrusted PDFs.
FROM debian:trixie-slim AS clamav_verifier

ARG CLAMAV_VERSION=1.5.5
RUN test "$(dpkg --print-architecture)" = "amd64"
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg \
  && rm -rf /var/lib/apt/lists/*

# Independently pinned Talos primary fingerprint. Verify detached signature
# before the package can be copied into the runtime build stage.
RUN set -eux; \
  mkdir -p /tmp/clamav-vendor; \
  curl --fail --silent --show-error --location --proto '=https' \
    --connect-timeout 15 --max-time 45 \
    https://raw.githubusercontent.com/Cisco-Talos/clamav-documentation/main/src/manual/cisco-talos.gpg \
    --output /tmp/clamav-vendor/talos.asc; \
  curl --fail --silent --show-error --location --proto '=https' \
    --connect-timeout 15 --max-time 180 \
    "https://github.com/Cisco-Talos/clamav/releases/download/clamav-${CLAMAV_VERSION}/clamav-${CLAMAV_VERSION}.linux.x86_64.deb" \
    --output /tmp/clamav-vendor/clamav.deb; \
  curl --fail --silent --show-error --location --proto '=https' \
    --connect-timeout 15 --max-time 45 \
    "https://github.com/Cisco-Talos/clamav/releases/download/clamav-${CLAMAV_VERSION}/clamav-${CLAMAV_VERSION}.linux.x86_64.deb.sig" \
    --output /tmp/clamav-vendor/clamav.deb.sig; \
  gpg --batch --no-default-keyring --keyring /tmp/clamav-vendor/talos-keyring.gpg \
    --import /tmp/clamav-vendor/talos.asc; \
  actual_fingerprint="$(gpg --batch --no-default-keyring \
    --keyring /tmp/clamav-vendor/talos-keyring.gpg --with-colons --list-keys \
    | awk -F: '$1 == "fpr" {print $10; exit}')"; \
  test "$actual_fingerprint" = "5BADCA2665EF59DCF8A23D8B707F0DB480836771"; \
  gpg --batch --no-default-keyring \
    --keyring /tmp/clamav-vendor/talos-keyring.gpg --verify \
    /tmp/clamav-vendor/clamav.deb.sig /tmp/clamav-vendor/clamav.deb

# Tesseract is built separately, not installed as an opaque binary package.
# Only the official English/Spanish models are retained in the runtime.
# The source tarball digest was independently matched with upstream 5.5.4.
FROM debian:trixie-slim AS ocr_builder
ARG TESSERACT_VERSION=5.5.4
ARG TESSERACT_SOURCE_SHA256=a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4
RUN test "$(dpkg --print-architecture)" = "amd64"
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl cmake build-essential pkg-config libleptonica-dev \
  && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /src \
  && curl --fail --silent --show-error --location --proto '=https' \
    "https://deb.debian.org/debian/pool/main/t/tesseract/tesseract_${TESSERACT_VERSION}.orig.tar.gz" \
    --output /tmp/tesseract.tar.gz \
  && echo "${TESSERACT_SOURCE_SHA256}  /tmp/tesseract.tar.gz" | sha256sum --check - \
  && tar --extract --file /tmp/tesseract.tar.gz --directory /src --strip-components=1 \
  && rm /tmp/tesseract.tar.gz
RUN cmake -S /src -B /tmp/ocr-build \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/folio-ocr \
    -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=ON \
    -DBUILD_TRAINING_TOOLS=OFF -DBUILD_TESTS=OFF \
    -DDISABLE_ARCHIVE=ON -DDISABLE_CURL=ON \
    -DGRAPHICS_DISABLED=ON -DDISABLED_LEGACY_ENGINE=ON \
  && cmake --build /tmp/ocr-build --parallel 4 \
  && cmake --install /tmp/ocr-build \
  && printf '{"name":"tesseract","version":"%s","source_sha256":"%s","archive":false,"curl":false}\n' \
    "${TESSERACT_VERSION}" "${TESSERACT_SOURCE_SHA256}" \
    > /opt/folio-ocr/source-provenance.json

FROM python:3.12-slim-trixie
RUN test "$(dpkg --print-architecture)" = "amd64"

# Runtime dependencies, without curl or an unverified Debian ClamAV binary.
# Poppler on Trixie depends on GPG-related packages; purging GPG removes
# poppler-utils as well. Do not break the PDF scanner to remove a dependency.
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates qpdf poppler-utils libleptonica6 tesseract-ocr-spa tesseract-ocr-eng zlib1g \
  && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge "1:1.3.dfsg+really1.3.1-1+deb13u1" \
  && test -r /etc/fonts/fonts.conf \
  && test ! -L /etc/fonts/fonts.conf \
  && test -d /etc/fonts/conf.d \
  && rm -rf /var/lib/apt/lists/*

# The source-verified OCR executable and shared library do not depend on
# libarchive/libcurl, removing libxml2 from the Tesseract dependency chain.
COPY --from=ocr_builder /opt/folio-ocr /opt/folio-ocr
RUN set -eux; \
  printf '%s\n' /opt/folio-ocr/lib > /etc/ld.so.conf.d/folio-ocr.conf; \
  ldconfig; \
  echo 'gate: OCR version'; \
  timeout 15s /opt/folio-ocr/bin/tesseract --version; \
  echo 'gate: dynamic executable libraries'; \
  linked_bin="$(timeout 15s ldd /opt/folio-ocr/bin/tesseract)"; \
  printf '%s\n' "$linked_bin"; \
  ! printf '%s\n' "$linked_bin" | grep -E '(libarchive|libcurl|libxml2)'; \
  echo 'gate: dynamic shared library dependencies'; \
  linked_lib="$(timeout 15s ldd /opt/folio-ocr/lib/libtesseract.so.5.5.4)"; \
  printf '%s\n' "$linked_lib"; \
  ! printf '%s\n' "$linked_lib" | grep -E '(libarchive|libcurl|libxml2)'; \
  echo 'gate: forbidden Debian packages'; \
  for package in libxml2 libarchive13t64 libtesseract5 tesseract-ocr; do \
    status="$(timeout 5s dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" \
      || { code="$?"; test "$code" -eq 1; status=''; }; \
    test "$status" != 'install ok installed'; \
  done; \
  echo 'gate: forbidden library files'; \
  test ! -e /lib/x86_64-linux-gnu/libxml2.so.2; \
  test ! -e /lib/x86_64-linux-gnu/libarchive.so.13; \
  echo 'gate: OCR language model files'; \
  test -s /usr/share/tesseract-ocr/5/tessdata/spa.traineddata; \
  test -s /usr/share/tesseract-ocr/5/tessdata/eng.traineddata; \
  echo 'gate: OCR language discovery'; \
  languages="$(TESSDATA_PREFIX=/usr/share/tesseract-ocr/5/tessdata timeout 15s /opt/folio-ocr/bin/tesseract --list-langs)"; \
  printf '%s\n' "$languages" | grep -q 'spa'; \
  printf '%s\n' "$languages" | grep -q 'eng'
ENV PATH="/opt/folio-ocr/bin:${PATH}" \
    TESSDATA_PREFIX=/usr/share/tesseract-ocr/5/tessdata

# The only artifact copied out of the verification stage is the signed .deb.
COPY --from=clamav_verifier /tmp/clamav-vendor/clamav.deb /tmp/clamav.deb
RUN dpkg -i /tmp/clamav.deb && rm /tmp/clamav.deb

# Signatures must be downloaded anew on each explicit build. A time-varying
# build argument invalidates ONLY this layer and the layers after it; Tesseract
# and Talos GPG verification can remain cached. Omitted tokens fail closed.
# Runtime still independently rejects stale signatures (72-hour cap).
ARG CLAMAV_SIGNATURE_REFRESH_EPOCH
RUN set -eux; \
  test -n "$CLAMAV_SIGNATURE_REFRESH_EPOCH"; \
  case "$CLAMAV_SIGNATURE_REFRESH_EPOCH" in *[!0-9]* ) exit 1 ;; esac; \
  current_epoch="$(date -u +%s)"; \
  test "$CLAMAV_SIGNATURE_REFRESH_EPOCH" -le "$current_epoch"; \
  test "$CLAMAV_SIGNATURE_REFRESH_EPOCH" -ge "$((current_epoch - 3600))"; \
  groupadd --system clamav; \
  useradd --system --gid clamav --no-create-home clamav; \
  mkdir -p /opt/clamdb; \
  chown clamav:clamav /opt/clamdb; \
  printf 'DatabaseMirror database.clamav.net\nDatabaseDirectory /opt/clamdb\nDatabaseOwner clamav\n' \
    > /etc/folio-freshclam.conf; \
  freshclam --config-file=/etc/folio-freshclam.conf --datadir=/opt/clamdb; \
  find /opt/clamdb -type f \( -name '*.cvd' -o -name '*.cld' \) -print -quit | grep -q .; \
  chmod -R a+rX /opt/clamdb

WORKDIR /srv/folio-inspector
COPY --chown=65534:65534 inspector.py qpdf_paint_triage_r154.py qpdf_scoped_gate_r155.py fixtures.py preflight.py smoke_real_engines.py smoke_http_real.py /srv/folio-inspector/

# Harden both build and runtime admission against an outdated scanner.
RUN python3 -c "from inspector import verify_clamav_version; import subprocess; verify_clamav_version(subprocess.check_output(['clamscan','--version'], text=True))"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CLAMAV_DB_DIR=/opt/clamdb FOLIO_INSPECTOR_BIND=0.0.0.0

USER 65534:65534
EXPOSE 8789
CMD ["python3", "-I", "/srv/folio-inspector/inspector.py"]
