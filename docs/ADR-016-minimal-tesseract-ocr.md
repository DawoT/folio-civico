# ADR-016 · Tesseract 5.5.4 mínimo sin libarchive/libxml2

**Fecha:** 2026-11-19 (America/Lima)  
**Estado:** remediación acotada en evaluación local. **No equivale a aprobar el inspector ni habilitar Preview**.

## Problema y decisión

La imagen histórica del inspector incluía `tesseract-ocr` y `libtesseract5` de Debian Trixie. El inventario dinámico mostró la cadena de Tesseract hacia `libarchive` y `libxml2`, con **CVE-2026-6653** aún registrado por [Debian](https://security-tracker.debian.org/tracker/CVE-2026-6653) como vulnerable en Trixie. Para reconocer las imágenes PNG rasterizadas por Poppler no se necesita abrir archivos archivados ni descargar datos desde Tesseract.

Se conserva la arquitectura ClamAV + qpdf + Poppler + Tesseract. El Dockerfile principal incorpora un *builder* separado con Tesseract **5.5.4** y `DISABLE_ARCHIVE=ON`, `DISABLE_CURL=ON`, `DISABLED_LEGACY_ENGINE=ON`; desactiva herramientas de entrenamiento y GUI. Su fuente `tesseract_5.5.4.orig.tar.gz` se descarga por HTTPS desde Debian y se comprueba contra SHA-256 **`a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4`**, previamente contrastado con el tarball de upstream. No se usa `sid` ni se suprime ninguna alerta CVE.

La imagen final incorpora el binario y biblioteca compilados, `libleptonica6` como dependencia explícita y los paquetes de idiomas de Debian `tesseract-ocr-spa` y `tesseract-ocr-eng` **sin instalar el Tesseract de Debian**. El stage de construcción, `curl` y `cmake` no pasan al runtime. Se preserva el ClamAV 1.5.5 firmado por Cisco Talos, su verificación GPG y las tres bases de firmas obligatorias.

## Verificación y política de aceptación

1. `sh scripts/ci.sh`: tests locales (incluido Red→Green de la política de Dockerfile), typecheck, build, workerd y migraciones D1 locales. **No sustituye los gates de imagen**.
2. `bash apps/inspector/validate_real_engines.sh`: reconstrucción aislada y comprobación de versión, procedencia, ausencia de paquetes `libxml2`, `libarchive`, `libtesseract5`, `tesseract-ocr`, archivos de biblioteca y enlaces dinámicos no deseados, seguido de seis pruebas reales y cuatro HTTP; todos los casos con datos sintéticos.
3. `bash apps/inspector/audit_image.sh --candidate`: Trivy JSON + SBOM CycloneDX sobre **`folio-civico-inspector:ocr-integrated`**, sin alterar la etiqueta `validation`. El mismo `audit_image.py` bloquea hallazgos CRITICAL/HIGH/UNKNOWN. `pnpm audit:inspector:image` sigue siendo el gate de la etiqueta aprobable.
4. Comparar el texto normalizado de una muestra sintética escaneada con la imagen histórica. Esta comparación demuestra compatibilidad para el fixture, **no paridad estadística de precisión sobre documentos institucionales**.
5. No actualizar imagen desplegada, contenedor Cloudflare, Queues, cron, firmas, datos ni rutas hasta que el gate global esté limpio o exista VEX granular aprobado.

## Limitaciones de cadena de suministro y seguridad

- Un binario compilado desde código fuente **no necesariamente aparece como componente vulnerable de Tesseract** en la detección automática de Trivy. Una caída de hallazgos es evidencia de menor inventario Debian, no prueba de ausencia de CVE de Tesseract. Se conserva `/opt/folio-ocr/source-provenance.json` con versión, checksum y flags de las funciones omitidas, sujeto a validación en el smoke. Es necesaria vigilancia específica de los [advisories upstream](https://github.com/tesseract-ocr/tesseract/security/advisories), incluidos los posteriores a 5.5.4.
- Tesseract 5.5.4 incluye correcciones de **17 advisories** según [las notas oficiales](https://github.com/tesseract-ocr/tesseract/releases/tag/5.5.4), pero esto no certifica las demás bibliotecas del contenedor.
- El SHA-256 fija el tarball; no es, por sí solo, una firma criptográfica de publicación del proyecto. Las imágenes base por etiqueta y paquetes APT continúan evolucionando; registrar digest de la imagen final y reconstruir para seguridad actualizada.
- La presencia/ausencia de enlace `ldd` no cubre `dlopen`, estático, plugins ni todos los procesos. La verificación usa además paquete instalado y archivos físicos en el contenedor. Aun sin `libxml2`, **los CVE restantes de Poppler, ClamAV, librerías criptográficas u otras dependencias mantienen bloqueada la publicación**.

## Referencias

[ADR-012](ADR-012-patched-clamav-supply-chain.md) · [ADR-013](ADR-013-inspector-sbom-cve-gate.md) · [ADR-014](ADR-014-native-zlib-signature-lifecycle.md) · [ADR-015](ADR-015-runtime-cve-triage.md) · [EXECUTION_PLAN](EXECUTION_PLAN.md).
