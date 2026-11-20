# R1.13 · RESEARCH ONLY — NO RUNTIME PATCH INSTALLATION

Estos **tres prototipos** son adaptaciones textuales de parches Debian
`26.07.0-4` a la fuente Debian Trixie `25.03.0-5+deb13u4`. Solo se
ejecutan sobre un árbol fuente temporal, verificado por SHA-256. **No
integrarlos en `Dockerfile.poppler-experiment`, no publicarlos ni
declararlos correcciones CVE sin revisión independiente.**

- `CVE-2026-102621-trixie-prototype.patch`: adapta SplashClip a la API
  antigua; persiste el cálculo sin guardia de `yMaxAA`.
- `CVE-2026-93312-trixie-prototype.patch`: aproxima el guard JBIG2
  `rewind` a la ruta `reset()` anterior; no prueba equivalencia.
- `CVE-2026-93313-trixie-prototype.patch`: adapta resta comprobada
  y devolución a `readCodeTableSeg(...)` antiguo (`void`).
- `check_numeric_boundaries.cc`: micro-harness independiente sobre
  `goo/GooCheckedOps.h` **del árbol Debian SHA-pinned**. Debe compilarse
  externamente con `-fsanitize=undefined`; no ejercita Poppler completo.

Toda verificación, SHA y sus límites están en
[el informe R1.13](../../../docs/SECURITY_POPPLER_SEMANTIC_PROTOTYPES_2026-11-19.md).


## R1.14 · Compilación sanitizada aislada (NO RELEASE)

Los nuevos scripts `build_sanitized_poppler.sh` y
`check_sanitized_poppler.sh` **no deben ejecutarse directamente en el host**.
Solo los invoca `../poppler_isolated_sanitizer.py` desde un contenedor
Poppler builder por digest, `--network none`, rootfs de solo lectura, sin
capacidades y como `65534:65534`. La ejecución lee hashes y fixtures
sintéticos montados en solo lectura; aplica cinco parches únicamente en
`/work` (tmpfs), compila Poppler con ASan/UBSan y no publica imágenes.

`pdftotext` y `pdftoppm` son los dos ejecutables de investigación.
El enlace ASan/UBSan de `pdfinfo` tiene un problema RTTI pendiente
(`typeinfo for AnnotLink`); **no declarar todas las utilidades verificadas**.
El verificador compara los cuatro rasters y dos salidas de texto contra el
builder Debian original. La investigación mantiene `release_authorized=false`,
sin VEX, CVE cerrados, recursos remotos ni autorización de procesamiento.
Véase [dossier R1.14](../../../docs/SECURITY_POPPLER_ASAN_UBSAN_BUILD_2026-11-19.md).


## R1.15 · Validación adicional de pdfinfo (SIN RELEASE)

El fallo RTTI `undefined reference to typeinfo for AnnotLink` de R1.14
fue causado por `-fvisibility=hidden` y la instrumentación `vptr` de
UBSan en `pdfinfo`. R1.15 añade `target_compile_options(pdfinfo PRIVATE
-fno-sanitize=vptr)` únicamente a la copia CMake dentro de `/work/source`
**después** de validar los SHA-256. No cambia el árbol del repositorio ni la
biblioteca/otros ejecutables. `pdfinfo` conserva ASan y los demás controles
de UBSan, y se ensaya con LeakSanitizer activo para 5 informes de metadatos
y 1 anotación URI sintética; los renderizadores conservan `detect_leaks=0`.

La ejecución completa exigió **5/5 metadatos y 1/1 salida de URL idénticos**
a la fuente Debian original, más los controles R1.14 de raster y texto.
`test_poppler_rtti_sanitizer.py` añade seis pruebas fail-closed.
Véase [R1.15](../../../docs/SECURITY_POPPLER_RTTI_SANITIZER_2026-11-19.md).
**No habilita CVE, imagen, OCR remoto, Preview ni producción.**
