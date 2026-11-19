# This image is NOT deployed automatically. The operator must supply up-to-date
# ClamAV signatures as a read-only mount and run with private networking,
# read-only filesystem, unprivileged user, tmpfs and resource limits.
FROM python:3.12-slim-bookworm

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clamav qpdf poppler-utils tesseract-ocr tesseract-ocr-spa tesseract-ocr-eng \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/folio-inspector
COPY --chown=65534:65534 inspector.py /srv/folio-inspector/inspector.py

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CLAMAV_DB_DIR=/opt/clamdb FOLIO_INSPECTOR_BIND=0.0.0.0

USER 65534:65534
EXPOSE 8789
CMD ["python3", "-I", "/srv/folio-inspector/inspector.py"]
