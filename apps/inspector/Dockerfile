# This image is NOT deployed automatically. The operator must supply up-to-date
# ClamAV signatures as a read-only mount and run with private networking,
# read-only filesystem, unprivileged user, tmpfs and resource limits.
FROM python:3.12-slim-bookworm

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clamav clamav-freshclam qpdf poppler-utils tesseract-ocr tesseract-ocr-spa tesseract-ocr-eng \
  && rm -rf /var/lib/apt/lists/*

# Fetch trusted AV definitions during image build. A failed download fails
# the build. With enableInternet=false, runtime cannot silently refresh them:
# rebuild and replace the image before the 72-hour freshness gate expires.
# Do not put signatures or credentials in the git repository.
RUN mkdir -p /opt/clamdb \
  && chown clamav:clamav /opt/clamdb \
  && freshclam --datadir=/opt/clamdb \
  && find /opt/clamdb -type f \( -name '*.cvd' -o -name '*.cld' \) -print -quit | grep -q . \
  && chmod -R a+rX /opt/clamdb

WORKDIR /srv/folio-inspector
COPY --chown=65534:65534 inspector.py /srv/folio-inspector/inspector.py

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CLAMAV_DB_DIR=/opt/clamdb FOLIO_INSPECTOR_BIND=0.0.0.0

USER 65534:65534
EXPOSE 8789
CMD ["python3", "-I", "/srv/folio-inspector/inspector.py"]
