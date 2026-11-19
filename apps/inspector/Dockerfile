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
    https://raw.githubusercontent.com/Cisco-Talos/clamav-documentation/main/src/manual/cisco-talos.gpg \
    --output /tmp/clamav-vendor/talos.asc; \
  curl --fail --silent --show-error --location --proto '=https' \
    "https://github.com/Cisco-Talos/clamav/releases/download/clamav-${CLAMAV_VERSION}/clamav-${CLAMAV_VERSION}.linux.x86_64.deb" \
    --output /tmp/clamav-vendor/clamav.deb; \
  curl --fail --silent --show-error --location --proto '=https' \
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

FROM python:3.12-slim-trixie
RUN test "$(dpkg --print-architecture)" = "amd64"

# Runtime dependencies, without curl or an unverified Debian ClamAV binary.
# Poppler on Trixie depends on GPG-related packages; purging GPG removes
# poppler-utils as well. Do not break the PDF scanner to remove a dependency.
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates qpdf poppler-utils tesseract-ocr tesseract-ocr-spa tesseract-ocr-eng zlib1g \
  && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge "1:1.3.dfsg+really1.3.1-1+deb13u1" \
  && rm -rf /var/lib/apt/lists/*

# The only artifact copied out of the verification stage is the signed .deb.
COPY --from=clamav_verifier /tmp/clamav-vendor/clamav.deb /tmp/clamav.deb
RUN dpkg -i /tmp/clamav.deb && rm /tmp/clamav.deb

# Official signatures fetched and validated only at build time.
# The runtime has no egress, so rebuild before the 72-hour freshness cap.
RUN set -eux; \
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
COPY --chown=65534:65534 inspector.py fixtures.py preflight.py smoke_real_engines.py smoke_http_real.py /srv/folio-inspector/

# Harden both build and runtime admission against an outdated scanner.
RUN python3 -c "from inspector import verify_clamav_version; import subprocess; verify_clamav_version(subprocess.check_output(['clamscan','--version'], text=True))"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CLAMAV_DB_DIR=/opt/clamdb FOLIO_INSPECTOR_BIND=0.0.0.0

USER 65534:65534
EXPOSE 8789
CMD ["python3", "-I", "/srv/folio-inspector/inspector.py"]
