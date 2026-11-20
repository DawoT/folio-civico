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


## R1.16 · Comparación adversaria de fuente, NO de runtime

Los nuevos artefactos `run_adversarial_differential.sh`,
`run_adversarial_cases.sh` y
`differential_arithmetic_boundaries.cc` son **exclusivamente de
investigación**. El orquestador `../poppler_adversarial_differential.py`
verifica los mismos SHA-256 de Debian y aplica los cinco parches solo a
una segunda copia de fuente temporal. Compila **dos bibliotecas Poppler
separadas** con ASan/UBSan (Debian original y prototipos), ejecuta PDFs
sintéticos con límites de tamaño/tiempo y reporta el comportamiento
observado sin cerrar CVE.

El orquestador `../poppler_arithmetic_boundary_probe.py` verifica
huellas fuente Debian exactas y compila un harness UBSan de operaciones
equivalentes, **no de rutas reales del parser**. Contrasta cuatro
operaciones aritméticas original/guardia y detecta riesgos todavía
presentes en `SplashClip::yMaxAA` y la alineación de `FoFiTrueType`.
No equiparar estos resultados con un PoC explotable ni afirmaciones
de que el binario operativo esté corregido.

Ambos flujos son offline: no PDFs institucionales, OCI, nube,
migraciones remotas ni cambios en imágenes `validation`. La
investigación no altera el gate de seguridad. Véase el
[dossier R1.16](../../../docs/SECURITY_POPPLER_ADVERSARIAL_DIFFERENTIAL_2026-11-19.md).


## R1.17 · Método Splash real y PDFs JBIG2/TrueType (SOLO INVESTIGACIÓN)

`splash_clip_method_probe.cc` compila y ejecuta el método auténtico
`SplashClip::clipToPath` a partir de los archivos fuente Debian originales
y con los cinco prototipos R1.13. El método reproduce UBSan en
`yMinAA` solamente en el original, mientras que **`yMaxAA` continúa
desbordándose en ambas versiones**. Esta ejecución C++ directa **NO** pasa
por un PDF ni certifica `CVE-2026-102621`.

`run_reachability_differential.sh` reutiliza las dos compilaciones
independientes, SHA-pinned, instrumentadas y aisladas de R1.16. Compila
`pdftops` para procesar una fuente TrueType sintética de dos glifos
(`folio_r117_synthetic_ttf.b64`, SHA-256 validado por el orquestador).
`run_reachability_cases.sh` comprueba 3 rechazos de páginas JBIG2
de dimensiones inválidas, 2 conversiones Type42 y 6 condiciones del
método Splash. Todos los resultados se verifican *fuera* del contenedor
por `../poppler_reachability_probe.py`; reportes falsificados o incompletos
provocan `exit 3`.

El valor del método es caracterizar mejor las rutas y sus precondiciones,
**no atribuir correcciones CVE**. La ruta JBIG2 de puntero nulo sigue sin
reproducirse, así como el overflow de glyph/loca TrueType. La exención
`vptr` R1.15 tampoco afecta a estas compilaciones. Véase
[el dossier R1.17](../../../docs/SECURITY_POPPLER_METHOD_REACHABILITY_2026-11-19.md).
Sin imagen operativa, OCI, despliegue, VEX ni PDF institucional.


## R1.19 · Overlay aislado para SplashClip::yMaxAA (NO RELEASE)

`SplashClip-ymax-checked-research-overlay.patch` es un **sexto cambio
independiente** que protege las tres operaciones aritméticas de
`(yMaxI+1)*splashAASize-1` mediante
`checkedAdd`, `checkedMultiply` y `checkedSubtraction`. Se aplica
**después** de los cinco cambios R1.13 (fuente y parches SHA-pinned)
exclusivamente a la tercera copia temporal de Poppler; **no** actualiza
ni sustituye los tres parches CVE prototipo con hashes inmutables.

`../poppler_splash_ymax_probe.py` invoca
`run_splash_ymax_overlay.sh` dentro del builder Docker aislado.
El `splash_ymax_method_probe.cc` compila por separado los **métodos
C++ reales** desde las tres variantes original, cinco prototipos y
overlay R1.19. Nueve resultados ASan/UBSan permiten verificar que el
overflow `yMaxAA` del método persiste en los dos primeros árboles,
pero se rechaza en el tercero sin perder el guard previo de `yMinAA`.
**NO** reproduce la ruta a través de PDF, ni compila el parser completo
con el sexto cambio. El CLI falla cerrado cuando la evidencia o los
hashes no coinciden y siempre declara `release_authorized=false`.

Véase [dossier R1.19](../../../docs/SECURITY_SPLASH_YMAX_CHECKED_OVERLAY_2026-11-19.md).
Sin imágenes operativas, publicación OCI, VEX, despliegue ni CVE declarados
corregidos.


## R1.21 · Overflow residual mediante SplashClip::test (NO RELEASE)

`splash_public_test_probe.cc` invoca la **API pública real**
`SplashClip::test(int x, int y)` con un rectángulo finito sintético,
sin reservar bitmap gigante. El punto `x=536870919` pasa el guard
rectangular, pero desborda `x *= splashAASize` dentro de
`SplashClip::testClipPaths`. El error UBSan ocurre en las tres variantes
de fuente: Debian original, cinco prototipos y cinco más overlay R1.19.

`run_splash_public_test.sh` reutiliza **sin alterarlo** el laboratorio
R1.19, sus SHA-256, tres árboles fuente, nueve regresiones y aislamiento
offline; después compila tres harnesses C++ nuevos con
`-fsanitize=address,undefined` para seis salidas adicionales. El
orquestador `../poppler_splash_public_test_probe.py` exige **15/15**
resultados reales, rechaza mensajes de sanitizador falsificados y falla
cerrado. **No** alcanza esta ruta mediante PDF ni implica CVE cerrado.
Véase [R1.21](../../../docs/SECURITY_SPLASH_PUBLIC_TEST_RESIDUAL_UB_2026-11-19.md).
Sin parche nuevo ni imagen operativa, OCI, VEX o despliegue.


## R1.24 · SplashClip::testSpan, triángulo y límites antialias (NO RELEASE)

`splash_span_method_probe.cc` llama a la API pública real
`SplashClip::testSpan` con un triángulo de recorte pequeño, un rectángulo
finito de coordenadas amplias y entradas sintéticas. Los tres árboles
original / cinco prototipos / sexto overlay R1.19 muestran el mismo
error UBSan `536870919 * 4` **solo** cuando, entre las cuatro condiciones
ensayadas, hay trayectoria de recorte y el punto extremo pasa el
guard rectangular. El mismo punto sin trayectoria y un punto fuera
del rectángulo no desbordan.

`run_splash_span_probe.sh` reutiliza el ejecutor R1.21, sus nueve
pruebas R1.19 y seis públicas R1.21, además de verificar doce nuevas
salidas C++ instrumentadas ASan/UBSan: **27/27 controles totales**.
`../poppler_splash_span_probe.py` valida fuente y parches SHA-pinned
y falla cerrado ante falsificación o ausencia de evidencia.

No se ejecuta ningún PDF a través del parser en este ensayo; la
alcanzabilidad desde PDF, la corrección CVE y el release están **sin
demostrar y no autorizados**. Dossier:
[SECURITY_SPLASH_SPAN_REACHABILITY](../../../docs/SECURITY_SPLASH_SPAN_REACHABILITY_2026-11-19.md).


## R1.26 · SplashClip::clipAALine con SplashBitmap real (NO RELEASE)

`splash_clipa_line_method_probe.cc` crea un bitmap auténtico de 64 × 4
subpíxeles con apenas 32 bytes de imagen y ejecuta `clipAALine` en las
tres variantes SHA-pinned de Poppler. Dos coordenadas **fuera de los límites
válidos del bitmap** reproducen sendos UBSan de entero con signo en
`*x0 * splashAASize` y `(*x1 + 1) * splashAASize`; los dos controles
normales pasan sin avisos.

`run_splash_clipa_line_probe.sh` reusa las 27 pruebas R1.19/R1.21/R1.24
y añade 12 llamadas con ASan/UBSan, **39/39 ejecuciones reales**. El
constructor de `SplashBitmap` se enlaza a un ELF auxiliar R1.14
**solo de investigación**, con SHA-256 validado fuera y dentro de Docker,
montado por el SONAME exacto `libpoppler.so.147`. El binario NO equivale
a una atestación del runtime operativo. El runner
`../poppler_splash_clipa_line_probe.py` rechaza evidencia inconsistente,
untrusted ELF, symlinks, fallos de linker, códigos de salida ajenos,
crashes y timeouts.

**No se prueba alcanzabilidad desde PDF ni desde un renderer con límites
válidos**, ni se aplica ningún parche a una imagen operativa o se cierra CVE.
Véase [dossier R1.26](../../../docs/SECURITY_SPLASH_CLIPAALINE_REAL_BITMAP_BOUNDS_2026-11-20.md).


## R1.27 · Splash constructors, ancho AA y bitmap Mono1 asignado (NO RELEASE)

`splash_aa_width_constructor_probe.cc` prueba **ambos constructores C++ reales**
de `Splash` y un bitmap `splashModeMono1` **realmente asignado**,
de una sola fila: 536870919 píxeles de ancho / 67108865 bytes (~64 MiB).
El caso ancho sin antialias construye correctamente, pero con
`vectorAntialias=true` reproduce UBSan `536870919 * 4` en
`Splash.cc:1454` y `Splash.cc:1476`. Los dos controles de tamaño
normal pasan. **8/8 ejecuciones reales** con la biblioteca completa
Poppler Debian reconstruida offline en CMake/Ninja (123 pasos) y
ASan/UBSan. La prueba inicial con RGB8 fue rechazada porque la reserva
falló antes de llegar a `Splash`.

`../poppler_splash_aa_constructor_probe.py` valida huellas de fuente
original y harness, compila `libpoppler.a` en tmpfs y exige los ocho
resultados instrumentados. El verificador falla cerrado ante otras
causas de error, source mismatches, archivos falsos o timeouts. La
prueba es de API C++, **no** demuestra alcanzabilidad desde PDF,
remediación CVE, equivalencia con runtime ni autorización de publicación.
Véase [dossier R1.27](../../../docs/SECURITY_SPLASH_AA_CONSTRUCTOR_WIDTH_2026-11-20.md).
