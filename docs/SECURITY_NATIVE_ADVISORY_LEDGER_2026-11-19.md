# R1.9 · Registro CVE de motores compilados desde fuente

**Corte de fuentes:** 2026-11-19 (America/Lima). **Estado:** evidencia parcial y verificable de revisión; **NO** es VEX, aprobación de imagen ni clasificación de afectación.

## Problema y decisión

Trivy y CycloneDX identifican paquetes Debian, pero al compilar e instalar Tesseract y Poppler bajo `/opt/folio-ocr` y `/opt/folio-poppler`, sus paquetes binarios de Debian desaparecen del informe de vulnerabilidades del sistema. Una disminución de hallazgos Trivy **no** demuestra que el código compilado esté libre de CVE. La puerta de seguridad ya bloquea esas imágenes por cobertura desconocida, pero hasta ahora el reporte de advisories solo enumeraba ClamAV/Expat.

La investigación verificó en los **rastreadores oficiales de paquetes fuente de Debian Trixie** los siguientes asuntos abiertos. Se registran como **seleccionados, no exhaustivos y pendientes de evaluación de aplicabilidad al binario concreto**:

| Fuente | Versión de código / imagen local | CVE abiertos seleccionados en Debian Trixie | Situación |
| --- | --- | ---: | --- |
| Tesseract | fuente upstream 5.5.4, ejecutable ELF con checksum | **14** | Varios avisos se corrigieron en upstream 5.5.3 o 5.5.4; hay que demostrar qué patches contiene el tarball exacto y qué rutas se ejecutan. No asumir que el estado `vulnerable` del paquete estable Trixie 5.5.0 equivale a un fallo del binario 5.5.4 |
| Poppler | fuente Debian `25.03.0-5+deb13u4` | **10** | Hay avisos recientes corregidos únicamente en suites posteriores o aplazados por Debian, más dos avisos históricos `no-dsa/ignored`. Se necesita triage de funciones y patches realmente incorporados; no equiparar todos con HIGH |

Fuentes oficiales consultadas: [Debian Tesseract](https://security-tracker.debian.org/tracker/source-package/tesseract), [Debian Poppler](https://security-tracker.debian.org/tracker/source-package/poppler). Son **fotografías del 19-11-2026**, no feed automático; pueden aparecer nuevos CVE, correcciones y cambios de prioridad.

### Tesseract (14)

`CVE-2026-119341`, `CVE-2026-119340`, `CVE-2026-119339`, `CVE-2026-119338`, `CVE-2026-88054`, `CVE-2026-88053`, `CVE-2026-88052`, `CVE-2026-88051`, `CVE-2026-88050`, `CVE-2026-88049`, `CVE-2026-88048`, `CVE-2026-88047`, `CVE-2026-73067`, `CVE-2026-73066`.

Se investigarán especialmente la carga de `.traineddata` y `CVE-2026-119338` (rutas de salida PAGE XML y texto de derecha a izquierda). El inspector recibe PDFs, pero entrega a Tesseract **una imagen rasterizada** y solicita salida `stdout` con `spa+eng`; los modelos se instalan desde paquetes en la imagen de solo lectura. Estas son **medidas de reducción de alcance**, no un dictamen `not_affected` sin comprobar los símbolos, las flags, el tarball y las llamadas de la versión exacta. Ejemplos de fuentes upstream: [CVE-2026-119339](https://github.com/tesseract-ocr/tesseract/security/advisories/GHSA-h9g4-frjx-6cj3), [CVE-2026-119338](https://github.com/tesseract-ocr/tesseract/security/advisories/GHSA-vf7v-2h4f-6f4j).

### Poppler (10)

`CVE-2026-107705`, `CVE-2026-102621`, `CVE-2026-102620`, `CVE-2026-93653`, `CVE-2026-93314`, `CVE-2026-93313`, `CVE-2026-93312`, `CVE-2026-93311`, `CVE-2019-9545`, `CVE-2019-9543`.

El filtro QPDF previo a Poppler evita que PDFs cifrados lleguen a sus parsers (**ADR-025**, pertinente a `CVE-2026-107705`), pero sigue habiendo análisis de PDFs no cifrados y rasterización Splash; no puede cerrarse `CVE-2026-93653` ni los fallos de `SplashClip`/JBIG2 por esa mitigación. Los dos CVE históricos están catalogados por Debian como `no-dsa/ignored`, no como ausentes del código. Las referencias individuales quedan en el JSON de revisión.

## Implementación

- `apps/inspector/native_advisory_ledger.py`: registro estático de 14+10 IDs de los rastreadores Debian, validado con identificadores CVE estrictos y **conteos esperados** (fallo cerrado si faltan entradas, aparecen duplicados o formato inválido).
- Llama siempre a `verify_native_source_inventory` y exige **imagen, modo, versiones, lista de utilidades, procedencia y hashes ELF** coherentes. Las filas conservan el SHA-256 del ejecutable, biblioteca, procedencia y las utilidades Poppler: el reporte se atribuye al contenido medido del contenedor, no a una etiqueta genérica.
- `apps/inspector/advisory_inventory.py` agrega `native_source_advisories` y `native_selected_cve_count` al JSON **solo informativo** de `--advisories`. Conserva separados `selected_blocking` de ClamAV/Expat y los 24 IDs de código fuente; **no los suma a Trivy** ni modifica el resultado del gate.
- En cualquier fila: `source_binary_applicability=unassessed`, `disposition=individual_review_required`. El reporte completo mantiene `complete_source_advisory_coverage=false`, `declares_not_affected=false`, `release_authorized=false`, `scope=selected_open_debian_trixie_advisories_not_exhaustive`.
- Los informes de la imagen `validation`, que no tiene componentes locales compilados, devuelven `status=not_applicable` para este registro; **no implica** que la imagen esté segura frente a CVE de paquetes del sistema.

## Verificación ejecutada

```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_native_advisory_ledger.py' -v
python3 -m unittest discover -s apps/inspector/tests -p 'test_advisory_inventory.py' -v
bash apps/inspector/audit_image.sh --experiment --advisories  # exit 2 esperado
sh scripts/ci.sh
```

En el escaneo de la imagen experimental local: **0 CRITICAL / 70 HIGH / 19 UNKNOWN** en Trivy, **13** advertencias priorizadas de ClamAV/Expat, **2** motores fuente sin revisión formal y **24** entradas fuente seleccionadas para investigar, atribuidas a los hashes Tesseract `229e33c23fdbfdcb08ea58fcdcf2d91ded744325d79ed2726a1c746a8629a732` y Poppler `888221ae778e7bc97261c743cf779d4a982c94afa70e91b2ef49eeef7897ebed`. La imagen siguió **bloqueada (exit 2)** y ninguna supresión/VEX se generó.

Las pruebas de unidad incluyen manipulación de versiones e identidad, cambio de clase de imagen, pérdida y duplicación de CVE, fuentes candidatas sin Poppler y validación vacía.

## Criterios para cerrar la deuda

1. Obtener listado actualizado de avisos upstream/OSV/GHSA de los dos proyectos y revisar **cada identificador** contra la versión fuente exacta, compilación y rutas de ejecución.
2. Para vulnerabilidades corregidas: identificar commit y versión que introducen la reparación, demostrar que el tarball/parches utilizados la contienen y volver a comprobar las huellas de una compilación limpia. Para rutas no ejecutables: documentar la prueba y la restricción permanente de acceso, con revisión independiente, no asumir.
3. Actualizar el registro al aparecer nuevos CVE; una fotografía que enumera 24 IDs **no acredita cobertura exhaustiva de advisories**.
4. Mantener pendiente cualquier excepción de seguridad hasta aprobación por responsable autorizado; no eliminar el bloqueo de `audit_image.py` por haber poblado este registro.
5. Resolver también Expat, Poppler y los HIGH/UNKNOWN restantes del sistema, además de reconstruir una imagen limpia y pasar el gate antes de cualquier despliegue.

**Gobierno:** [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md) permite fusionar este código, tests y documentación en `main`, sin liberar el runtime, desplegar Cloudflare ni modificar datos institucionales.
