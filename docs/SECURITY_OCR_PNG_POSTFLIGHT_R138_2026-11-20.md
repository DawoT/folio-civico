# R1.38 · Verificación PNG posterior a Poppler y previa a Tesseract (NO RELEASE)

**Fecha:** 2026-11-20 (America/Lima). **Issue:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Rama:** `security/ocr-png-envelope-r138`.

## Problema real

R1.35–R1.36 presupuestan el tamaño de raster **antes** de ejecutar `pdftoppm -r 180 -png`, usando MediaBox, rotación y UserUnit. Sin embargo, después de la ejecución, `inspector.py` solo comprobaba la existencia de `ocr-page.png` y el límite de 32 MiB **del archivo comprimido** antes de pasarlo a Tesseract. Un PNG de escasos bytes puede contener una cabecera `IHDR` que declare 100000×100000 píxeles: el tamaño comprimido no limita la memoria que puede reservar un decodificador. La barrera posterior a Poppler complementa, pero no sustituye, la anterior.

## Cambio operativo (no habilita runtime remoto)

`apps/inspector/inspector.py` ahora conserva la tupla de cotas devuelta por `require_ocr_raster_geometry` y llama a `require_ocr_png_envelope(image, raster_budget)` **entre** `pdftoppm` y Tesseract.

El validador:

1. Recibe obligatoriamente una tupla estricta de dos enteros positivos, ≤8192 por lado y ≤32 millones de píxeles en producto. No interpreta valores implícitos, booleanos ni límites sobredimensionados.
2. Abre el PNG con descriptor Linux `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` y exige fichero regular, un solo enlace, **mínimo 57 bytes y máximo 32 MiB**. Rechaza archivos ausentes, directorios, symlinks y hardlinks. Lee exclusivamente 33 bytes del inicio y 12 del final mediante `os.pread`.
3. Comprueba firma PNG, `IHDR` de 13 bytes, bit depth 8, color RGB/RGBA (tipos 2/6), compresión, filtro y entrelazado estándar, CRC-32 de `IHDR` y cierre `IEND` al final.
4. Verifica ancho y alto reales de `IHDR` contra **cada dimensión de la misma página preadmitida**, y su producto contra el presupuesto general; ancho cero o alto cero se rechazan.
5. Cualquier incumplimiento produce `ReviewRequired`. **Tesseract no se ejecuta y no se emite manifiesto clean.**

El validador **no es un decodificador ni un sanitizador**: no verifica el flujo IDAT completo, todos los CRC de chunks intermedios ni el contenido visual. Tesseract sigue siendo un parser no confiable dentro de un sandbox con límites; el objetivo es evitar que un PNG enormemente comprimido eluda la cota geométrica después de Poppler.

Se conserva el orden **ClamAV → QPDF anti-cifrado/estructura → Poppler metadata/texto → preflight geométrico → pdftoppm → PNG postflight → Tesseract**. No cambian DPI, manifiestos, interfaces HTTP, Dockerfile operativo, Cloudflare ni D1.

La función antigua `inspect_png_envelope` del harness experimental R1.36 ahora **reutiliza el validador operativo** y traduce su excepción a `ValueError` para el contrato del laboratorio; evita mantener dos implementaciones con semánticas potencialmente divergentes.

## TDD, pruebas adversarias y compatibilidad

Se incorporaron `apps/inspector/tests/test_ocr_png_postflight.py` (**8 pruebas** con 34 subtests), junto con el pequeño generador determinista `apps/inspector/tests/png_fixtures.py`. Los mocks previos de OCR ahora escriben PNG estructuralmente válidos, en lugar de bytes arbitrarios, por lo que prueban el contrato real.

**Red:** el control no existía y el flujo llegaba a Tesseract cuando se simulaba un raster enorme en un PNG pequeño.

**Green:** **416/416 tests de inspector y 586 subtests**; nuevos casos de dimensiones gigantes con fichero comprimido pequeño, falta o corrupción de PNG, versión/CRC/`IEND` alterados, enlace simbólico, enlace duro, truncamiento, archivo excedido, color PNG no permitido, límites numéricos inválidos y paso limpio a Tesseract con PNG normal.

**Compatibilidad:** 8/8 pruebas del módulo nuevo dentro de `python:3.12-slim` en contenedor aislado, sin red, usuario no-root y montaje de código solo lectura.

## Evidencia contra motores reales (solo laboratorio)

Se repitió `apps/inspector/ocr_poppler_binary_smoke.py` con la imagen experimental local fija:

- Imagen **no operativa**: `sha256:ae2af683610b3e1b0f5de12bbcda21f6c26649fc886c9fd4e8341b62c08deca6`.
- Poppler: `25.03.0-5+deb13u4`; QPDF: `12.2.0-1`; identidad ELF completa en [dossier R1.36](SECURITY_OCR_USERUNIT_REAL_POPPLER_R136_2026-11-20.md).
- Corpus PDF sintético de 9 páginas SHA-256 `0641c796fea6cb2078376765e77dcf99bcb5995f3df0c79cbe3dfdacc5f47153`.
- **Exit 0**, seis páginas pequeñas rasterizadas con flags OCR reales y 2 controles con `-cropbox`, verificados con la **misma función operativa R1.38**. `MediaBox` extremo y `UserUnit 10000` rechazados, nunca rasterizados.
- Raster A1 sintético en la misma imagen, previamente generado con límite 256 MiB: preflight 4211×5961, PNG real 4210×5960 (86 929 bytes); validación R1.38 lo aceptó con dimensiones exactas. Es una **página blanca**, no un estudio de OCR de planos completos.

## Límites y autorización

Este incremento **no** acredita el inspector completo con ClamAV+QPDF+Poppler+Tesseract reales en una imagen candidata; tampoco prueba equivalencia fuente→ELF del runtime, seguridad ante PDFs hostiles de geometría moderada, fidelidad A0/A1, renovación de ClamAV, ni cierre del gate Trivy/ADR-023. Una cabecera PNG válida no demuestra que sus datos IDAT sean seguros para un decodificador.

**Código integrable en `main` tras CI. Issue #68 permanece abierto. `runtime_candidate_equivalence_verified=false`, `cve_remediation_claimed=false`, `release_authorized=false`.** Ninguna imagen OCI operativa publicada; sin Preview, Cloudflare, D1 remoto, producción ni VEX.
