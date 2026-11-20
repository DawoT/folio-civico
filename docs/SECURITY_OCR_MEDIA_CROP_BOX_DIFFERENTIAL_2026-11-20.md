# R1.34 · Diferencial MediaBox/CropBox vs raster OCR (investigación, NO RELEASE)

**Fecha:** 2026-11-20 (America/Lima). **Issue:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Rama:** `security/ocr-box-semantics-r134`. Esta entrega solo añade investigación y pruebas. **No** modifica `inspector.py`, Dockerfiles, imagen OCI, Cloudflare, D1 remoto, PDFs institucionales ni release.

## Hallazgo confirmado en Poppler experimental

El inspector usa `pdftoppm -f PAGE -l PAGE -singlefile -r 180 -png` **sin** la bandera `-cropbox`.

En el Poppler experimental identificado por el ID local `sha256:abf8192c743f176c6da02bcc288a4eb0ba2d9cb4377a7b8f1725ae9471798254`, la salida de `pdfinfo -f 1 -l 8 -box` muestra que `Page size` sigue la región `CropBox` en una página recortada. La salida PNG del `pdftoppm` **por defecto** no sigue esa región: rasteriza la extensión MediaBox.

| Caso con PDF sintético | `pdfinfo Page size` | Raster normal `-r 180 -png` | Raster con `-cropbox` |
| --- | ---: | ---: | ---: |
| MediaBox 200×200; CropBox [20,30,120,90] | 100×60 puntos | 500×500 px | 250×150 px |
| MediaBox heredado 500×300; CropBox [100,10,300,210] | 200×200 puntos | 1250×750 px | 500×500 px |
| MediaBox 200×200; CropBox [0,0,400,400] (fuera de MediaBox) | 200×200 puntos | 500×500 px | No medido |
| MediaBox 200×400; Rotate 90° | 200×400 puntos | 1000×500 px | No medido |
| MediaBox 200×200; UserUnit 5 | 200×200 puntos | 500×500 px | No medido |
| MediaBox 0.01×0.02 | 0.01×0.02 puntos | 1×1 px | No medido |

Esta es una observación **directa de comandos Docker sobre el corpus inicial de 8 páginas**, 1343 bytes y SHA-256 `663120bea558de94ad7edbab5f4fecf0766344e2b015cdbe2adc51333471a471`. Las nueve salidas PNG (incluidos los dos modos `-cropbox`) terminaron `exit 0`, con límites de CPU, memoria, PID, tiempo, sin red y Docker rootless. No se rasterizó ningún PDF institucional.

**Consecuencia:** estimar el coste de `pdftoppm` a partir de `Page size` solamente puede subestimar la reserva efectiva; utilizar `-cropbox` en el preflight sin utilizarlo en el rasterizador crearía una discrepancia de comportamiento.

## Caso adversarial adicional: recorte pequeño, MediaBox extremo

Se amplió el corpus a **9 páginas, 1484 bytes, SHA-256 `0641c796fea6cb2078376765e77dcf99bcb5995f3df0c79cbe3dfdacc5f47153`**. La novena página contiene:

    /MediaBox [0 0 536870919 1] /CropBox [0 0 100 1]

`pdfinfo -f 1 -l 9 -box` **real** informó `Page 9 size: 100 x 1 pts`, pero también `Page 9 MediaBox: 0 0 536870919 1`. El PDF aceptado por los metadatos no demuestra que el mismo programa alcance el overflow con `pdftoppm -r 180 -png`; **esta página nunca se rasterizó**.

La quinta página, `/UserUnit 10000` sobre MediaBox 200×200, **tampoco se rasterizó**. `pdfinfo -box` no muestra directamente `UserUnit` y la prueba pequeña con `UserUnit 5` solo describe el comportamiento observado en esa muestra. No se acredita seguridad general ante otras combinaciones, herencia de cajas, números o construcción malformada de PDF.

## Implementación R1.34 acotada

`apps/inspector/poppler_ocr_box_semantics_research.py`:

- Genera exclusivamente los 9 objetos sintéticos deterministas y falla cerrado si cambia el SHA-256; no acepta PDFs aportados por usuarios.
- Compara registros completos de `Page size`, `MediaBox`, `CropBox` y `Rotate` para **las 9 páginas** y los valores esperados del corpus; rechaza omisiones, duplicados, valores adulterados y salida no ASCII. No es un parser universal ni componente operativo.
- Calcula un presupuesto de diagnóstico del **MediaBox** con la resolución real de 180 DPI para no confiar en `Page size` en estas muestras. El gran MediaBox de la página 9 permanece fuera de cualquier raster.
- Bloquea explícitamente la rasterización de páginas 5 y 9; solo permite 9 controles acotados `p1`, `p2`, `p2crop`, `p3`, `p4`, `p6`, `p7`, `p7crop` y `p8`.
- Usa imagen exacta por ID, Docker `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL`, sin privilegios, memoria y procesos acotados; comprueba los SHA-256 ELF de los tres artefactos Poppler fijados previamente en R1.33, resultados de subprocess, dimensiones PNG y SHA posterior del PDF sintético.
- Siempre informa `runtime_guard_implemented=false`, `source_binary_equivalence_to_runtime_verified=false`, `user_unit_safety_verified=false`, `safe_for_untrusted_pdf_verified=false`, `cve_remediation_claimed=false`, `release_authorized=false`.

`apps/inspector/tests/test_poppler_ocr_box_semantics_research.py` cubre corpus, interpretación de cajas y presupuesto, alteración de registros, controles PNG, bloqueo de páginas extremas, Docker offline/rootless, falsificación de respuestas y fallo cerrado cuando no existe imagen. También fija una regresión observable: el parser anterior R1.33 rechaza la matriz recortada (`Page size and MediaBox disagree`); no se incorporó ese parser al inspector operativo.

## Estado real de la reconstrucción

**Verificado con Docker en esta investigación:** 9 procesos PNG sobre la **matriz precursora de 8 páginas** y `pdfinfo` sobre la **matriz final de 9 páginas**. Ambos se ejecutaron sin red en la imagen experimental identificada por ID SHA.

**No verificado:** el orquestador final `inspect_local_matrix()` end-to-end. Al intentar ejecutar la matriz final y medir nuevamente los hashes ELF, el daemon respondió:

    docker: Error response from daemon: No such image: sha256:abf8192c743f176c6da02bcc288a4eb0ba2d9cb4377a7b8f1725ae9471798254

La imagen fue retirada del daemon local entre los comandos anteriores y la nueva ejecución. El CLI devolvió `exit 3` con `status=research_inconclusive`. **No se reetiquetó, publicó, reconstruyó ni descargó imagen.** Los tests con `runner` simulado son pruebas de contrato; **no** sustituyen el experimento Docker de la matriz final. El harness conserva la comprobación fail-closed cuando la imagen falta.

Cuando esté disponible la imagen **exacta** (sin reutilizar un tag mutable), ejecutar de nuevo:

    python3 apps/inspector/poppler_ocr_box_semantics_research.py \
      --offline-local-experiment

No se declara completada esa prueba hasta obtener `exit 0` y cotejar el reporte.

## Verificación de código

- TDD Red → Green: el nuevo módulo faltaba durante la importación; después se aprobaron pruebas adversariales de integridad del corpus, metadatos, dimensiones, aislamiento y prohibición de raster extremo.
- `10/10` pruebas nuevas, con subtests; suite Python integral del inspector: **348/348 pruebas y 440 subtests**.
- CI integral local en ejecución durante la preparación del dossier; CI remoto del PR y CI posterior a cualquier integración se verifican por separado.

## Decisiones de seguridad

1. El futuro preflight del inspector debe medir, como mínimo, los límites de `MediaBox` por página **en la misma semántica que el `pdftoppm` real**; no puede aceptar solo `Page size`.
2. Corregir el falso rechazo de PDFs recortados en el *research parser* solo tras probar otro verificador; no modificar el runtime basándose en texto redondeado o sintaxis de un PDF.
3. Resolver campos `UserUnit`, boxes heredados, CropBox fuera de MediaBox, resolución, rotación y cambios entre el parser metadata y el raster; la verificación genérica de seguridad sigue pendiente.
4. Definir límites de píxeles tras medir impacto de OCR y documentos válidos; los umbrales de R1.33 (8192 px por lado, 16 Mpx) siguen siendo **provisionales**.
5. Mantener la ruta QPDF primero, scanner fail-closed, Trivy bloqueante, auditoría source→ELF/runtime y autorización institucional separada.

**ADR-023:** solo investigación y documentación integrables después de CI verde; sin release del inspector, sin VEX ni CVE cerrado.
