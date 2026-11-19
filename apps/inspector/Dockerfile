# Folio Cívico inspector: fail-closed build against November 2026
# ClamAV security vulnerabilities. Never deploy automatically.
# The vendor-signed release is used because Debian Bookworm currently ships
# 1.4.6 and the official Docker feature tags still point to 1.5.4.
FROM python:3.12-slim-bookworm

ARG CLAMAV_VERSION=1.5.5
RUN test "$(dpkg --print-architecture)" = "amd64"

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg qpdf poppler-utils tesseract-ocr tesseract-ocr-spa tesseract-ocr-eng \
  && rm -rf /var/lib/apt/lists/*

# Obtain the Talos key from its official documentation. Pin the full primary
# fingerprint independently of the download; neither HTTPS alone nor an
# unverified key fetched beside the .deb is sufficient supply-chain checking.
# Verify the detached release signature BEFORE installing the binaries.
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
    /tmp/clamav-vendor/clamav.deb.sig /tmp/clamav-vendor/clamav.deb; \
  dpkg -i /tmp/clamav-vendor/clamav.deb; \
  rm -rf /tmp/clamav-vendor

# Offline runtime: freshly downloaded official signatures are baked into the
# image, not requested by the parser container. Rotate image before 72h.
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

# Build-level version assertion reuses the same fail-closed policy as health
# and document admission. If the upstream package is not 1.5.5+, stop here.
RUN python3 -c "from inspector import verify_clamav_version; import subprocess; verify_clamav_version(subprocess.check_output(['clamscan','--version'], text=True))"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CLAMAV_DB_DIR=/opt/clamdb FOLIO_INSPECTOR_BIND=0.0.0.0

USER 65534:65534
EXPOSE 8789
CMD ["python3", "-I", "/srv/folio-inspector/inspector.py"]
