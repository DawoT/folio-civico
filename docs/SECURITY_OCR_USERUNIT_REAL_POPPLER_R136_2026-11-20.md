# R1.36 · UserUnit vía QPDF y smoke de Poppler real (código para integración, NO RELEASE)

**Fecha:** 2026-11-20 (America/Lima). **Issue:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Rama aislada:** `security/ocr-real-smoke-r136`.

## Objetivo y defecto reproducido

R1.35 introdujo una barrera por MediaBox antes de `pdftoppm -r 180 -png`. Su parser `pdfinfo -box` no expone `/UserUnit`. La matriz sintética R1.34 de 9 páginas probó, **antes de R1.36**, que una página `/MediaBox [0 0 200 200] /UserUnit 10000` superaba el preflight a pesar de un factor de escala potencialmente extremo.

No se generó raster de esa página. Las observaciones de `UserUnit 5` con Poppler real no acreditan que todas las variantes de Poppler y el motor de renderizado honren o ignoren esa clave.

## Implementación R1.36

Se amplió `apps/inspector/inspector.py` únicamente en la ruta de páginas **sin texto**:

1. Se mantienen `clamscan`, `qpdf --is-encrypted`, `qpdf --check` y los controles sobre adjuntos/PDF antes de Poppler.
2. Si `pdftotext` devuelve vacío, el inspector solicita una sola vez `qpdf --json --json-key=pages PDF`. Su parser exige JSON v2, orden/contador de páginas exactos, referencias de objeto únicas y acotadas, sin claves duplicadas, valores numéricos no finitos ni salida excesiva.
3. Para la página OCR específica consulta `qpdf --json --json-key=qpdf --json-object=OBJECT,GEN PDF`. La respuesta debe referirse exactamente al objeto de página identificado, con `/Type /Page` y `/UserUnit` **numérico directo, finito, ≥1 y ≤75000**. Si no está presente, `UserUnit=1`. Referencias indirectas, null, strings o versiones/estructuras no soportadas se rechazan (fail-closed); pueden incluir PDFs legítimos que requieren evaluación separada.
4. `pdfinfo -f PAGE -l PAGE -box` sigue aportando el **MediaBox efectivo**, el CropBox y la rotación. La admisión presupone de forma conservadora la geometría efectiva `(lado MediaBox + 0,02 pt) × UserUnit × 180/72`, con techo Decimal y los límites de R1.35: **8192 px por lado y 32 millones de píxeles por página**. El parámetro `user_unit` ahora es obligatorio en la función de presupuesto para evitar omisiones accidentales.
5. Solo después se invoca `pdftoppm -f PAGE -l PAGE -singlefile -r 180 -png`. Los fallos de parser/QPDF, metadatos o geometría no emiten manifiesto limpio.

La multiplicación es **deliberadamente pesimista**: si Poppler ignora `UserUnit` al rasterizar, la estimación sobre-rechaza, pero no subestima por ignorar ese factor. Este supuesto no demuestra seguridad de asignaciones internas, contenidos/recursos PDF adversariales ni que todo PDF legítimo será admitido. A0 y documentos válidos con `/UserUnit` indirecto o escala grande pueden requerir flujo de revisión.

## Ensayo real: imagen Debian de laboratorio, NO runtime

Se creó **solo localmente** una imagen desechable mediante `apps/inspector/research/Dockerfile.poppler-ocr-lab`, basada en la caché local de `debian:trixie-slim`. Su construcción instaló paquetes mediante repositorios Debian con metadatos APT firmados, pero **no** demuestra una compilación desde fuentes ni una equivalencia source→ELF reproducible.

**Imagen local por ID completo:** `sha256:ae2af683610b3e1b0f5de12bbcda21f6c26649fc886c9fd4e8341b62c08deca6`.

**Identidades medidas mediante `dpkg-query` y `sha256sum` dentro de la imagen:**

| Artefacto | Versión / SHA-256 real |
| --- | --- |
| `poppler-utils` y `libpoppler147` | `25.03.0-5+deb13u4` |
| `qpdf` | `12.2.0-1` |
| `/usr/bin/pdfinfo` | `a1a371340d7b76e7d501da9136cc9256dfdb9cbdf09300520d7a3b4465343e67` |
| `/usr/bin/pdftoppm` | `f22d753dfb4c31c9f0198d608982dac5b06a3c5d9a08d7d9bf0c6004f08a1a56` |
| `/usr/bin/qpdf` | `30b2389c3ed0ba73434244fff5b149d4d919279ea7a8c3b1cd9fc25f57ec1792` |
| `/usr/lib/x86_64-linux-gnu/libpoppler.so.147` | `8f199d8f320d485c8a0051676b8a0d6c6019900e5643b685afd7e304250ef340` |

Este ID **no coincide** con la imagen de R1.33/R1.34 y **no** es una imagen candidata operativa. La construcción no cambia `apps/inspector/Dockerfile` ni publica OCI.

`apps/inspector/ocr_poppler_binary_smoke.py` toma la imagen como parámetro obligatorio por ID completo y recrea exclusivamente el PDF sintético de 1484 bytes SHA-256 `0641c796fea6cb2078376765e77dcf99bcb5995f3df0c79cbe3dfdacc5f47153`. Se ejecutó:

    python3 apps/inspector/ocr_poppler_binary_smoke.py \
      --offline-lab-smoke \
      --image-id sha256:ae2af683610b3e1b0f5de12bbcda21f6c26649fc886c9fd4e8341b62c08deca6

**Resultado: exit 0**. El harness usa Docker `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, sin privilegios, CPU 1, memoria 512 MiB, PID 64, `/tmp` tmpfs 64 MiB; PDF de entrada montado solo lectura. QPDF comprueba estructura y cifrado antes de usar Poppler. Solo rasteriza las páginas pequeñas de lista positiva: 1, 2, 4, 6, 7 y 8; compara además dos controles `-cropbox`. Inspecciona el encabezado/CRC/cola PNG (no decodifica el contenido).

| Página | Contexto sintético | Cota del preflight (px) | PNG real (px) |
| ---: | --- | ---: | ---: |
| 1 | A4 | 1488×2106 | 1488×2105 |
| 2 | MediaBox 200×200, CropBox 100×60 | 501×501 | 500×500 |
| 4 | MediaBox 200×200, UserUnit 5 | **2501×2501** | 500×500 |
| 6 | MediaBox 200×400, Rotate 90° | 1001×501 | 1000×500 |
| 7 | MediaBox heredado 500×300, CropBox 200×200 | 1251×751 | 1250×750 |
| 8 | MediaBox 0,01×0,02 | 1×1 | 1×1 |
| 5 | **UserUnit 10000** | Excede presupuesto | **NUNCA rasterizada** |
| 9 | **MediaBox 536870919×1**, CropBox 100×1 | Rechazada | **NUNCA rasterizada** |

Controles con `-cropbox`: página 2, 250×150 px; página 7, 500×500 px. Esta diferencia frente al raster normal confirma que no debe usarse `Page size` como límite de costo.

## Verificaciones de código

- TDD Red → Green para JSON QPDF, `UserUnit` directo/ausente, rechazo de tipos no confiables, objetos mezclados/duplicados, referencias indirectas y errores de motor, flujos OCR mixtos y ausencia de costes adicionales en páginas de texto.
- 9 nuevos tests de UserUnit con subtests adversariales; 6 tests de harness Docker; regresión del inspector **408/408 tests Python, 552 subtests** tras rebase a `main` en la rama local.
- Faltan por registrar CI integral local, CI remoto del PR y CI posterior a merge, cada uno por separado.
- No se ejecutó `inspect_pdf` completo con ClamAV, Tesseract y QPDF/Poppler **reales** en una única imagen operativa; el smoke prueba el subflujo QPDF → metadatos → preflight → raster en un laboratorio independiente, más unitaria de integración `inspect_pdf` con runner simulado.

## Gobierno y riesgos pendientes

- No se rehabilita un PDF hostil cuya geometría sea normal pero cuyos contenidos provoquen descompresión o consumo de recursos excesivos. Se mantienen los límites del subprocess/cgroup; una cota de píxeles **no** es una cota de memoria de todo Poppler.
- La equivalencia con el ELF/DSO de una imagen operativa y la reconstrucción fuente→ELF aún no se han demostrado.
- QPDF JSON v2 y `/UserUnit` directo son contratos deliberadamente estrictos. Otros formatos, claves indirectas o saltos de versiones fallan cerrado; medir el impacto en documentos válidos antes de un release.
- La fidelidad OCR A0/A1, las firmas ClamAV vigentes y el gate Trivy, además de las autorizaciones institucionales, siguen bloqueantes.

**Código para revisión/integración en `main`, pero `runtime_candidate_equivalence_verified=false`, `cve_remediation_claimed=false`, `source_to_elf_reproducibility_verified=false` y `release_authorized=false`.** No OCI operativo, Cloudflare, D1 remoto, Preview ni producción.
