# R1.10 · Evidencia de parches Tesseract 5.5.4 y modelos OCR del runtime

**Corte:** 2026-11-19 (America/Lima)
**Alcance:** solo código, evidencias y pruebas offline. **No** hay una imagen aprobada, VEX ni autorización de Preview.

## Hallazgo verificable

El registro R1.9 seleccionó 14 CVE de Tesseract publicados en el tracker de Debian. Debian Trixie distribuye el paquete fuente **5.5.0-1**, catalogado como vulnerable a esos 14 casos, mientras que **Forky/Sid 5.5.4-1** aparece como corregido para todos ellos. La publicación upstream **5.5.4** anuncia la corrección de 17 avisos de seguridad.

La imagen local de Folio Cívico no usa el paquete Debian Trixie 5.5.0: compila **el tarball original 5.5.4**, descargado del archivo Debian y verificado con el SHA-256 que exige el Dockerfile:

`a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4`

**Distinciones obligatorias:** que Debian considere reparada la versión 5.5.4 no demuestra que cada función del binario local coincida con esa fuente ni cubre todos los avisos actuales y futuros. La comprobación de cuatro marcadores de fuente es evidencia adicional; **ningún CVE se declaró automáticamente `not_affected`** y no se redujo el gate.

Fuentes:
- [Debian Tesseract: estado por suite](https://security-tracker.debian.org/tracker/source-package/tesseract)
- [Tesseract: publicación 5.5.4](https://github.com/tesseract-ocr/tesseract/releases/tag/5.5.4)
- [CVE-2026-119338](https://security-tracker.debian.org/tracker/CVE-2026-119338), [119339](https://security-tracker.debian.org/tracker/CVE-2026-119339), [119340](https://security-tracker.debian.org/tracker/CVE-2026-119340), [119341](https://security-tracker.debian.org/tracker/CVE-2026-119341)
- [Registro R1.9 de CVE nativos](SECURITY_NATIVE_ADVISORY_LEDGER_2026-11-19.md)

## Verificación de cuatro reparaciones en el archivo fuente fijado

`apps/inspector/tesseract_source_patch_probe.py` es una utilidad **offline**; recibe una copia local del `tesseract_5.5.4.orig.tar.gz` e impone exactamente la huella oficial ya fijada en `source_inventory.py`. Sin coincidencia de SHA-256, con tarball malformado, archivo repetido, enlace simbólico o marcadores ausentes, aborta con **exit 3**.

| CVE | Símbolo/archivo fuente comprobado | Evidencia observada en el tarball fijado |
| --- | --- | --- |
| `CVE-2026-119338` | `AppendLinePolygon`, `src/api/pagerenderer.cpp` | acumulador RTL por referencia (`Pta **`), destrucción y reinicialización segura del puntero |
| `CVE-2026-119339` | `WeightMatrix::DeSerializeOld`, `src/lstm/weightmatrix.cpp` | ruta `FAST_FLOAT` devuelve `false` para matrices antiguas, sin abortar |
| `CVE-2026-119340` | `DeSerializeSize`, `src/ccstruct/matrix.h` | dimensiones sin signo y comprobación de bytes de entrada antes de reservar |
| `CVE-2026-119341` | `ReadAdaptedClass`, `src/classify/adaptive.cpp` | neutralización de punteros leídos de archivo antes de posibles destructores |

**Ejecución real:** descargado en memoria desde `https://deb.debian.org/debian/pool/main/t/tesseract/tesseract_5.5.4.orig.tar.gz` (1.969.431 bytes), SHA-256 verificado contra el Dockerfile, **4/4 marcadores presentes**, respuesta `source_markers_verified`. La herramienta no descarga nada: la descarga manual de verificación se efectuó separadamente. No hay modificación de archivos del repositorio por el proceso de inspección.

Estos marcadores están vinculados al contenido íntegro por SHA-256, pero no sustituyen una revisión de parches con instrumentación dinámica, pruebas de explotación no destructivas, verificación de toolchain/build reproducible o revisión independiente. La respuesta señala `binary_patch_verified=false`, `complete_source_advisory_coverage=false` y `release_authorized=false`.

## Identidad de los modelos entrenados utilizados por OCR

Los 14 CVE incluyen errores en la carga y deserialización de `.traineddata`, por lo que comprobar únicamente el ejecutable `tesseract` y `libtesseract.so` es insuficiente. Antes, el inventario nativo no incluía los modelos.

`source_inventory.py` ahora mide los modelos desde **el ID exacto de la imagen local** en `/usr/share/tesseract-ocr/5/tessdata`. Rechaza una carpeta ausente, enlazada o modificable por grupo/otros; exige **exactamente** dos archivos regulares `eng.traineddata` y `spa.traineddata`, sin symlinks, nombres adicionales `.traineddata`, archivos vacíos, modificables por grupo/otros o superiores a 32 MiB. Calcula SHA-256 en lectura por bloques, sin volcar contenido.

| Modelo en ambas imágenes locales | Tamaño verificado | SHA-256 medido |
| --- | ---: | --- |
| `eng.traineddata` | 4.113.088 B | `7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2` |
| `spa.traineddata` | 2.294.433 B | `6f2e04d02774a18f01bed44b1111f2cd7f3ba7ac9dc4373cd3f898a40ea6b464` |

Los archivos se comprobaron **regulares, no symlinks, UID 0 y modo 0644** en la imagen local experimental; la carpeta es UID 0 y modo 0755. El inspector usa `TESSDATA_PREFIX` estático y explícitamente `-l spa+eng`, con filesystem del contenedor de solo lectura y proceso UID 65534. **El SHA medido es identidad, no autenticación del origen de los modelos por sí solo**. La autenticidad de paquetes Debian depende de la firma y política APT del proceso de build, objeto de revisión independiente.

`audit_image.py` ahora exige `model_sha256` con exactamente estas dos claves para Tesseract y un diccionario vacío para Poppler. Valores vacíos, ausentes, adicionales o inválidos causan **error del gate**, no un falso `passed`. La misma identidad aparece en el reporte de advisories nativos por CVE.

## Evidencia de pruebas y bloqueos

```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_source_inventory.py' -v
python3 -m unittest discover -s apps/inspector/tests -p 'test_tesseract_source_patch_probe.py' -v

# Requiere el tarball oficial ya disponible localmente; no hay descarga:
python3 apps/inspector/tesseract_source_patch_probe.py \
  --archive /ruta/local/tesseract_5.5.4.orig.tar.gz

# Controles separados y deliberadamente bloqueantes de release:
bash apps/inspector/audit_image.sh --candidate --advisories
bash apps/inspector/audit_image.sh --experiment --advisories
sh scripts/ci.sh
```

**Validación sobre imágenes originales sin rebuild ni cambio de tags:**

- `ocr-integrated`: Trivy **0 CRITICAL / 128 HIGH / 19 UNKNOWN**, modelos `spa/eng` identificados; **exit 2, bloqueado**.
- `poppler-experiment`: Trivy **0 CRITICAL / 70 HIGH / 19 UNKNOWN**, modelos idénticos; **exit 2, bloqueado**.
- Ambos informes conservan los CVE priorizados, la revisión de Poppler y la obligación de evaluar componentes compilados. No se han creado VEX ni excepciones.

## Pendientes y decisión

El siguiente trabajo sustantivo es verificar los **10 avisos abiertos de Poppler** contra la fuente Debian parcheada concreta y sus rutas utilizadas (en especial Splash y JBIG2), así como los restantes problemas de runtime en Expat/ClamAV. Aunque se acreditasen las reparaciones upstream de los 14 CVE seleccionados de Tesseract, todavía faltarían reproducibilidad de binarios, actualización exhaustiva de advisories, evaluación de modelos, SBOM completo y revisión de los restantes **HIGH/UNKNOWN** de la imagen.

Conforme a [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md), esta evidencia y los controles de código pueden integrarse en `main` tras CI. No habilitar procesamiento real, despliegues Cloudflare, Preview, migraciones remotas o publicación de imágenes.
