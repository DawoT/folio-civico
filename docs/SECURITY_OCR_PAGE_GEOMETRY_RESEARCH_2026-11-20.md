# R1.33 · Geometría de páginas antes del OCR (investigación, NO RELEASE)

**Fecha:** 2026-11-20 (America/Lima). **Issue:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Rama aislada:** `security/ocr-raster-geometry-r133`. Este trabajo no modifica el scanner operativo ni autoriza OCI, Cloudflare, D1 remoto, Preview o producción.

## Brecha técnica

`apps/inspector/inspector.py` limita el PDF de entrada a 8 MiB y 100 páginas, verifica QPDF antes de Poppler y aplica timeouts a subprocess. Sin embargo, para páginas sin texto ejecuta `pdftoppm -f PAGE -l PAGE -singlefile -r 180 -png PDF PREFIX` sin una cota explícita de ancho, alto o píxeles de cada página **antes** de rasterizar. El límite de 32 MiB del PNG se comprueba **después** de la asignación por Poppler.

R1.31 verificó un overflow UBSan en `Splash.cc:1454` con un PDF sintético de MediaBox extremo y `pdftoppm -gray -r 72 -aaVector yes`. **No demuestra** que la configuración OCR operativa de 180 DPI y PNG alcance la misma multiplicación, ni identidad con el ELF operativo.

## Experimento aislado y atestado

`apps/inspector/poppler_ocr_geometry_research.py` no es importado por `inspector.py`. Genera un PDF 1.6 original, de 790 bytes, cuatro páginas y SHA-256 `f0ed77b9fad56aa7741ea02b9ebceb427bdf705913fbb643ee12a0b13acc5b2f`. Casos: A4 normal, ancho extremo `536870919 × 1`, A4 rotado 90° y página `200 × 200` con `/UserUnit 5`. Sin contenido institucional, fuentes, adjuntos, imágenes ni JavaScript.

El probe usa un ID de imagen Docker completo; `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, memoria 256 MiB, un CPU, límite de PID y timeout. En la imagen, valida mediante `sha256sum` el ejecutable `pdfinfo`, el ejecutable `pdftoppm` y `libpoppler.so.147`. Ejecuta `pdfinfo -f 1 -l 4 -box` y verifica todos los registros por página, coherencia de dimensiones y rotación; rechaza campos ausentes, extra malformados, duplicados, infinitos, resultados truncados y PDF cifrado.

Las estimaciones a 180 DPI usan `Decimal` y suman provisionalmente 0.02 puntos por el redondeo textual de MediaBox. El presupuesto **solo diagnóstico, NO aprobado para producción**, es 8192 píxeles por lado y 16 millones de píxeles por página.

Tras el análisis, vuelve a verificar el SHA-256 del PDF montado. Esto rechaza adulteraciones persistentes durante el ensayo, **no** excluye una carrera TOCTOU con restauración previa a la comprobación final.

Opcionalmente el mismo probe ejecuta `pdftoppm -r 180 -png`, con la configuración OCR exacta, **solo en páginas 1, 3 y 4**. La página extrema 2 NUNCA se rasteriza. Verifica código de salida, cabecera PNG IHDR/CRC, IEND, tamaño limitado y geometría. No decodifica ni certifica los datos de píxeles.

### Identidades locales fijadas

| Artefacto experimental | SHA-256 |
|---|---|
| Imagen local | `sha256:abf8192c743f176c6da02bcc288a4eb0ba2d9cb4377a7b8f1725ae9471798254` |
| `/opt/folio-poppler/lib/libpoppler.so.147` | `3ca61c1d42c8a040e47f01524d0bc3d45d73bc3e7981fe79a46b9cf9cb8dfe3b` |
| `/opt/folio-poppler/bin/pdftoppm` | `04dd62778926081c15bd437eaf58dab27e205e59f5b00a5d33585df7ce3617a0` |
| `/opt/folio-poppler/bin/pdfinfo` | `888221ae778e7bc97261c743cf779d4a982c94afa70e91b2ef49eeef7897ebed` |

Esta identidad de ELF es local y **no equivale** a fuente→ELF reproducible ni a equivalencia con la imagen `validation` o un runtime autorizado.

## Resultados del parser y raster

`pdfinfo` aceptó las cuatro páginas, `Encrypted: no` y sus MediaBox y rotaciones. En la página extrema, `Page size` aparece en notación científica (`5.36871e+08`); MediaBox informa `536870919.00`. Nunca bastaría consultar la primera página.

| Página | Geometría PDF | Estimación conservadora a 180 DPI | Salida PNG real |
|---|---|---|---|
| 1 | A4 595 × 842, rot. 0° | 1488 × 2106 | **1488 × 2105**, exit 0 |
| 2 | 536870919 × 1 | 1342177298 × 3 | **No rasterizada**, riesgo excede presupuesto provisional |
| 3 | 842 × 595, rot. 90° | 1488 × 2106 | **1488 × 2105**, exit 0 |
| 4 | 200 × 200, `/UserUnit 5` | 501 × 501 | **500 × 500**, exit 0 |

`/UserUnit 5` no fue expuesto en la salida `pdfinfo -box`. Su resultado particular de 500 × 500 no demuestra que todas las combinaciones de UserUnit, herencia, cajas, rotaciones, fuentes y versiones de Poppler respeten las cotas. La precisión de las coordenadas textuales es limitada.

Estado del reporte real: `real_pdfinfo_executed=true`, `experimental_elf_identity_verified=true`, `small_page_raster_controls_verified=true`; simultáneamente `page_geometry_safe_for_untrusted_pdf_verified=false`, `user_unit_effect_verified=false`, `runtime_guard_implemented=false`, `source_binary_equivalence_to_runtime_verified=false`, `cve_remediation_claimed=false` y **`release_authorized=false`**.

## Verificación

TDD: el módulo ausente falló al importar; después los tests rechazaron funciones PNG/raster no implementadas, falta de comprobación ELF, líneas adicionales malformadas y un PDF montado adulterado. Los casos adversariales se reprodujeron en Red y terminaron Green: **11/11 unitarios específicos y 19 subtests**. La comprobación final no es una firma externa ni una protección integral frente a TOCTOU. Las pruebas son deterministas, sin Docker en CI. La ejecución real de Docker es opt-in y requiere la imagen local SHA-pinned:

    python3 -m unittest discover -s apps/inspector/tests \
      -p 'test_poppler_ocr_geometry_research.py' -v
    python3 apps/inspector/poppler_ocr_geometry_research.py \
      --image-id sha256:abf8192c743f176c6da02bcc288a4eb0ba2d9cb4377a7b8f1725ae9471798254 \
      --with-small-raster-controls
    python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'
    sh scripts/ci.sh

**Verificación de regresión:** 320/320 pruebas Python del inspector y 409 subtests aprobados tras los cambios. Los 11 tests nuevos no reemplazan una prueba ASan/UBSan de la ruta OCR extrema.

## Requisitos pendientes para una mitigación real (#68)

1. Demostrar la semántica de `/UserUnit`, `/CropBox`, `/MediaBox`, escalado y rotación para el parser y el rasterizador de la imagen final; comparar con `GfxState` y el ELF operativo. Un parser de metadatos redondeados no es una garantía por sí mismo.
2. Definir y medir la política real de lado/píxeles a 180 DPI con OCR en páginas A4/A3 y formatos grandes legítimos, antes de elegir un presupuesto de producto.
3. Implementar, **en una entrega posterior**, un preflight seguro por página antes de ejecutar `pdftoppm`. Mantener QPDF temprano, timeouts y rechazo fail-closed.
4. Realizar un ensayo instrumentado ASan/UBSan con flags OCR exactos y PDFs sintéticos patológicos, recursos acotados y sin PDFs institucionales.
5. Completar trazabilidad source→ELF, cobertura de CVE/Trivy y aprobación separada de cualquier release.

**Gobierno ADR-023:** este PR solo incorpora investigación, pruebas y dossier. No introduce un guard en producción, no cambia Dockerfiles ni etiquetas OCI, no publica imágenes, no cierra CVE, no emite VEX ni toca Cloudflare/D1 remota.
