# ADR-025 · Rechazo de PDFs cifrados antes de invocar Poppler

**Fecha:** 2026-11-19 (America/Lima)
**Estado:** implementado y validado en código y motores reales; **no constituye remediación CVE ni autorización de despliegue**.

## Riesgo investigado

Poppler de Debian Trixie 25.03.0-5+deb13u4 permanece afectado según Debian por `CVE-2026-107705`, un desbordamiento de pila en `Decrypt::revision6Hash()` al procesar PDFs cifrados AESV3/R6 con contraseña controlada. El inspector **ya rechazaba PDFs cifrados**, pero consultaba `pdfdetach` (Poppler) antes de inspeccionar `Encrypted: yes` con `pdfinfo` (también Poppler). Un rechazo posterior no evita exponer primero un analizador vulnerable al documento.

**Alcance real:** esta evaluación demuestra una ruta previa a Poppler y elimina ese procesamiento para PDFs cifrados dentro del flujo actual. No demuestra explotabilidad del CVE en la versión exacta, ni acredita la corrección de su código. QPDF sigue analizando el PDF bajo límites de ejecución y el CVE queda abierto.

## Decisión implementada

Antes del cambio, la secuencia era `ClamAV → qpdf --check → pdfdetach → pdfinfo/Encrypted → extracción`.

La secuencia actual queda:

`ClamAV → qpdf --is-encrypted → qpdf --check → pdfdetach → pdfinfo → extracción por página`.

El análisis antivirus sigue siendo obligatorio **antes de cualquier parser PDF**. QPDF utiliza el contrato documentado de `--is-encrypted`:

| Código de salida QPDF | Significado | Acción |
| --- | --- | --- |
| `0` | PDF cifrado | `ReviewRequired`, rechazo del documento |
| `2` | PDF no cifrado | Emitir una señal interna exacta `not_encrypted` y continuar |
| `1`, `3`, señal o error | Estado indeterminado, fallo de QPDF o invocación | `ScannerUnavailable`, nunca tratar como limpio |

`inspect_pdf()` comprueba que el veredicto devuelto por `command()` coincida exactamente con `not_encrypted`. Un fallo por falta de herramienta, timeout, salida inesperada o ejecución simulada incompleta **impide invocar Poppler**. No se expone el texto ni el PDF original en logs.

## Evidencia reproducible

1. **Contrato del ejecutable real:** dentro de la imagen local `folio-civico-inspector:poppler-experiment`, en red deshabilitada, filesystem de solo lectura y sin capacidades, QPDF devolvió `2` con el fixture PDF nativo y `0` con el mismo PDF cifrado mediante `qpdf --encrypt ... 256`. El fixture cifrado fue generado para la prueba en almacenamiento temporal; no se procesaron documentos institucionales.
2. **TDD:** las pruebas unitarias fallaron antes de implementar el guard y después pasaron. Cubren el tratamiento específico de `0/2/1/3/señal`, orden exacto antivirus → preflight → Poppler, rechazo temprano del caso cifrado y fallo cerrado ante veredictos faltantes o alterados.
3. **Smoke con ejecutables reales:** `bash apps/inspector/verify_raster_guard.sh` ejecuta `inspector.py` y `smoke_real_engines.py` **de la versión del repositorio** en memoria dentro de la imagen previa por ID inmutable. Verifica siete controles: extracción PDF nativa, OCR, PDF dañado, PDF cifrado, rechazo cifrado **antes de Poppler**, adjuntos y detección antivirus EICAR. La política de contenedor es offline, solo lectura, sin puertos ni montajes de archivos de usuario.
4. La prueba de invariantes en `smoke_real_engines.py` intercepta todas las invocaciones de la ruta cifrada y **falla** si se llama a `pdfdetach`, `pdfinfo`, `pdftotext`, `pdftoppm` o a `qpdf --check` antes de que `qpdf --is-encrypted` rechace.
5. La imagen local que sirvió la prueba no fue reconstruida: esta ejecución **no demuestra** que exista una imagen de producción reconstruida, firmada o aprobada. El gate de vulnerabilidades del contenedor se sigue ejecutando por separado y no se debilita.

Referencias oficiales: [QPDF, comportamiento y códigos de salida de `--is-encrypted`](https://qpdf.readthedocs.io/en/latest/cli.html); [Debian Security Tracker, `CVE-2026-107705`](https://security-tracker.debian.org/tracker/CVE-2026-107705); [investigación R1.6 sobre fidelidad PDF](RESEARCH-poppler-fontconfig-regression.md).

## Lo que sigue bloqueado

- Poppler 25.03.0-5+deb13u4 **no ha sido declarado corregido** para `CVE-2026-107705`, `CVE-2026-93653` ni el resto de sus avisos.
- `libexpat1` conserva 4 HIGH y 2 UNKNOWN; la ruta de Fontconfig se mantiene porque eliminarla destruyó texto PDF sintético.
- Las alertas históricas de ClamAV y la cobertura de Tesseract/Poppler compilados desde fuente siguen pendientes de análisis formal.
- Los límites, el aislamiento y el filtro temprano **reducen superficie**, pero no reemplazan un parche del fabricante, un VEX granular aprobado, un SBOM completo ni el gate CVE.
- La integración de código en `main` se rige por [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md). Sin Preview, despliegue Cloudflare, sustitución de `validation`, publicación de imágenes ni procesamiento de documentación real.
