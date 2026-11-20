# R1.39 · Fidelidad OCR A4/A1 con QPDF, Poppler y Tesseract reales (solo laboratorio)

**Fecha:** 2026-11-20 (America/Lima). **Seguimiento:** [#68](https://github.com/DawoT/folio-civico/issues/68).

## Necesidad y resultado

R1.35–R1.38 integraron controles geométricos previos y posteriores al raster, pero las pruebas A1 anteriores solo habían demostrado que una **página blanca** podía producir un PNG dentro del presupuesto. No medían reconocimiento OCR en un documento A1 realmente escaneado. R1.39 construye una prueba experimental reproducible con **tres PDFs originales, exclusivamente sintéticos**: A4, A1 con rótulo grande y A1 con texto técnico a 14 pt y líneas vectoriales.

El programa `apps/inspector/ocr_real_fidelity_lab.py`:

1. Genera cada página vectorial original y comprueba su estructura con QPDF.
2. Con `pdftoppm -gray -r 180` rasteriza el texto original, verifica el tamaño real del PGM y construye un **nuevo PDF con un XObject de imagen, sin objetos de fuente ni capa de texto**. Comprueba con `pdftotext` real que no hay texto extraíble.
3. Ejecuta `qpdf --is-encrypted` (salida 2 para PDF sin cifrar), `qpdf --check` y `pdfinfo -f 1 -l 1 -box` reales sobre ese PDF escaneado.
4. Ejecuta la **misma** función del inspector para presupuestar las dimensiones: `require_ocr_raster_geometry` con `UserUnit = 1`, seguido de `pdftoppm -f 1 -l 1 -singlefile -r 180 -png` y el **mismo** postflight operativo `require_ocr_png_envelope` de R1.38.
5. Ejecuta Tesseract **real** en `-l spa+eng`, normaliza el resultado mediante el algoritmo de la matriz de calidad existente, y compara con el texto de referencia. El contrato exige **cero errores de caracteres** en estos casos controlados; cualquier desviación falla cerrada.
6. Emite **solo métricas y SHA-256** del origen, documento escaneado, PNG y textos normalizados. No publica el OCR extraído, no retiene PDFs ni imágenes cuando termina y no incorpora contenido institucional.

## Imagen, motores y restricciones

Imagen creada **localmente para investigación**, a partir de la imagen previa experimental Poppler por ID completo `sha256:ae2af683610b3e1b0f5de12bbcda21f6c26649fc886c9fd4e8341b62c08deca6`; el Dockerfile experimental añadido es `apps/inspector/research/Dockerfile.ocr-fidelity-lab`. La imagen de R1.39 mide:

**`sha256:b2357bab9ae3c5f1e9e5398e0d7ab39b21e83c3491604dfd08be9a7b287797df`**

| Componente | Paquete Debian del laboratorio |
|---|---|
| `poppler-utils` / `libpoppler147` | `25.03.0-5+deb13u4` |
| `qpdf` | `12.2.0-1` |
| `tesseract-ocr` | `5.5.0-1+b1` |
| Modelos `spa/eng` | `1:4.1.0-2` cada uno |

SHA-256 medidos dentro de la imagen con `sha256sum`:

| Archivo | SHA-256 |
|---|---|
| `/usr/bin/pdfinfo` | `a1a371340d7b76e7d501da9136cc9256dfdb9cbdf09300520d7a3b4465343e67` |
| `/usr/bin/pdftoppm` | `f22d753dfb4c31c9f0198d608982dac5b06a3c5d9a08d7d9bf0c6004f08a1a56` |
| `/usr/bin/qpdf` | `30b2389c3ed0ba73434244fff5b149d4d919279ea7a8c3b1cd9fc25f57ec1792` |
| `/usr/bin/tesseract` | `74b76a5b994adcc18be362bf64ed5118082b2401d5d9a35242e92fc4c62e2b4b` |
| `/usr/lib/x86_64-linux-gnu/libpoppler.so.147` | `8f199d8f320d485c8a0051676b8a0d6c6019900e5643b685afd7e304250ef340` |
| `/usr/lib/x86_64-linux-gnu/libtesseract.so.5` | `66b27d857aa90bb7a31059c65bb624e918e96a7c276699bd5ac5dca4cf1ba322` |
| `spa.traineddata` | `6f2e04d02774a18f01bed44b1111f2cd7f3ba7ac9dc4373cd3f898a40ea6b464` |
| `eng.traineddata` | `7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2` |

**No es la imagen candidata del inspector.** El Dockerfile operativo requiere Tesseract **5.5.4 compilado desde código fuente** y elimina `libarchive`/`libcurl`/`libxml2` de su cadena; **el Tesseract Debian de este laboratorio es 5.5.0 y reporta dependencias a libarchive y libcurl**. La prueba no acredita seguridad, equivalencia fuente→ELF ni CVE del runtime operativo. La construcción requiere repositorios APT Debian; no es una reconstrucción inmutable ni un artefacto desplegable.

Cada motor se invoca en un **nuevo contenedor Docker, sin red**, con `--pull never --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --cpus 2 --memory 1g --memory-swap 1g`. `/tmp` es tmpfs de 64 MiB; se montan solo los directorios de fixtures y resultados temporales, sin secretos ni archivos institucionales. Los procesos están limitados a 90 segundos y la salida textual se acota a 64 KiB. El contrato exige la **identidad completa por SHA-256** de la imagen y los **ocho hashes de referencia del laboratorio**, incluidos ejecutables, bibliotecas Poppler/Tesseract y modelos OCR. Cualquier diferencia o informe incompleto aborta. Estas referencias son locales y no equivalen a una atestación de la imagen operativa.

## Resultados observados

**Resultado del ejecutor real: exit 0, 3/3 casos aceptados y 0 errores CER**. Los textos de prueba son deliberadamente cortos y se comparan de modo exacto tras normalización.

| Caso | Caracteres de referencia | Errores de caracteres | PNG real a 180 DPI | Observación |
|---|---:|---:|---|---|
| A4 · rótulo documental | 20 | **0** | 1530×1980 | Texto escaneado, no nativo |
| A1 · rótulo grande | 15 | **0** | 4210×5960 | MediaBox A1, 25 091 600 px |
| A1 · detalle 14 pt + líneas | 20 | **0** | 4210×5960 | Texto más fino junto a líneas vectoriales |

**Trazabilidad de los tres PDFs escaneados y los PNG reales (SHA-256):**

| Caso | PDF escaneado SHA-256 | PNG emitido SHA-256 |
|---|---|---|
| A4 | `80d2758afc10ba2e81709da4805cc11e89f6be9d9532d139346018449862f3ce` | `7a77440be02a0cc8861864b603c38c3a6ac1408a6b62bdffb3c941d194e343c0` |
| A1 rótulo | `818859a510d42e85d1c101e6c6c0990d6021ed08399d4484e337b5f4a1e6219a` | `cd1f5423a7488caad6c72c91966c19afaacd383ff35508053dbb1dfb3e0d9f94` |
| A1 detalle | `9da4edf5abbfe703adec724046ec2f46df4631f57e2bcac45859bd3d726e6c2b` | `1a55db88930a4d04722862ea1c2fcc423d3a094197d0a52c951ed9593a91bfb5` |

El ejecutor confirma, por documento, `QPDF→pdftotext sin texto→preflight MediaBox→PNG con postflight→Tesseract`. El ensayo previo R1.36 demostró el factor `UserUnit`; este corpus mide por diseño el valor predeterminado `UserUnit=1`. No se rasterizan PDF extremos ni documentos reales.

## Pruebas automatizadas y límites

Se añadió `apps/inspector/tests/test_ocr_real_fidelity_lab.py` con seis pruebas unitarias y 24 subtests: validez del corpus sintético, generación de PDF estrictamente de imagen, rechazo de parámetros/PGM corruptos, política Docker inmutable/no privilegiada y rechazo cerrado de informes de identidad ausentes, corruptos y hashes sintácticamente válidos pero distintos a las ocho huellas esperadas. En la rama local, **456/456 tests Python del inspector, 620 subtests** tras rebase a `main` pasaron; las seis pruebas nuevas pasaron también en **Python 3.12** dentro de Docker no privilegiado.

Aún quedan por realizar para cualquier aprobación operativa: inspección **completa** con ClamAV **1.5.5** y firmas oficiales vigentes + Tesseract fuente 5.5.4 y sus librerías originales, imagen candidata exacta, CVE/Trivy y cobertura fuente→ELF, pruebas de estrés y PDF hostil moderado, fidelidad de **planos reales autorizados** (A0 requiere decisión de producto), rotación de firmas y autorización independiente de Preview/producción.

**`antivirus_real_verified=false` · `clamav_1_5_5_verified=false` · `inspector_full_pipeline_verified=false` · `runtime_candidate_equivalence_verified=false` · `safe_for_untrusted_pdf_verified=false` · `release_authorized=false`.** El Issue #68 debe permanecer **ABIERTO**. La integración en `main` es únicamente integración de investigación, pruebas y documentación (ADR-023), nunca un release.
