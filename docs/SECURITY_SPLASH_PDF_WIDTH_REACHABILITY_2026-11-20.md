# R1.31 · Puente PDF sintético → constructor Splash (investigación, sin release)

**Fecha:** 2026-11-20 (America/Lima). **Rama aislada:** `security/splash-pdf-width-r131`.
**Ámbito:** reproducir o descartar provisionalmente la alcanzabilidad del fallo aritmético R1.27 a través de un PDF sintético procesado por Poppler Debian instrumentado. **Sin payloads institucionales, OCI, Cloudflare, D1 remoto ni CVE corregidos.**

## Pregunta y contexto

R1.27 confirmó mediante 8/8 ejecuciones C++ originales de `Splash::Splash` que la expresión `splashAASize * bitmap->width` desborda `int` con un bitmap Mono1 de `width=536870919` y `height=1`, realmente asignado. R1.28 fijó por SHA-256 la totalidad de su ejecutor experimental. Ninguna de las dos entregas estableció si un PDF puede producir el mismo ancho tras la conversión de tamaño de página, DPI y límites del rasterizador.

En la fuente Debian exacta `25.03.0-5+deb13u4`, `SplashOutputDev::startPage` convierte `state->getPageWidth() + 0.5` a `int`, crea `SplashBitmap(w,h,...)` y, si `getDataPtr()` devuelve un puntero válido, invoca `new Splash(bitmap, vectorAntialias, &screenParams)` sin comprobar `w * 4` en ese tramo. **Si falla la asignación, recupera un bitmap 1×1**. `pdftoppm` puede seleccionar Mono1 y antialias vectorial, pero conserva sus propias conversiones y condiciones de validación; no se presume que la ruta extrema alcance el constructor.

## Implementación reversible

- `apps/inspector/poppler_splash_pdf_width_corpus.py`: dos PDFs PDF 1.4 originales, deterministas y de menos de 2 KiB, con `/MediaBox [0 0 8 1]` y `/MediaBox [0 0 536870919 1]`. Sin imágenes, fuentes, JavaScript, recursos externos ni contenido institucional. Los bytes se validan por SHA-256 antes de su uso.
- `apps/inspector/research_patches/run_splash_pdf_width_probe.sh`: compila `pdftoppm` y `pdfinfo` reales desde el árbol Debian original, con ASan/UBSan, y ejecuta siete procesos: consulta de metadatos del PDF extremo; raster normal Mono1 con/sin AA; raster extremo escalado a 32×1; raster extremo Mono1 sin AA; raster extremo Mono1 solicitando AA (control negativo), y raster extremo **Mono8/grises** con AA vectorial habilitado.
- `apps/inspector/poppler_splash_pdf_width_probe.py`: orquestador fail-closed; coteja la huella completa del script, las huellas originales de `Splash.cc`, `SplashOutputDev.cc` y `SplashBitmap.cc`, el corpus y los resultados separados de procesos. **Solo** reconoce alcanzabilidad desde PDF si hay diagnóstico UBSan exacto del constructor en `Splash.cc:1454`, código de salida esperado y metadatos de ancho extremo aceptados.
- `apps/inspector/tests/test_poppler_splash_pdf_width_probe.py`: prueba de integridad, adulteración del runner, controles positivos/negativos y rechazo de evidencia falseada.

**Aislamiento:** builder local `sha256:2f57f656317dc0b6106437640c8b91ee1a9452fe5c019b2e53dbd6a007272049`; Docker `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`. Límite de CPU 2, memoria 6 GiB, PID 256, tmpfs y 12 s por proceso. Los bitmaps grandes **no se guardan** en artefactos de la prueba instrumentada; su stdout se descarta. Los controles pequeños usan PBM acotados. La reserva para grises es considerablemente mayor que para Mono1, por lo que se conserva límite de memoria y tiempo. No se crea ni modifica ninguna imagen OCI.

## Criterio de interpretación

1. Un PDF con metadatos anchos aceptados **no es evidencia de overflow**; tampoco un render pequeño con `-scale-to-x 32 -scale-to-y 1`. El código original `SplashOutputDev::setVectorAntialias()` fuerza `vaa=false` para `splashModeMono1`, aun con `-aaVector yes`. Por ello el caso extremo Mono1 es un control negativo y no puede atribuirse a él una reproducción del defecto AA. En cambio `-gray` activa un modo raster no Mono1, y se investiga por separado.
2. Rechazo temprano, fallback 1×1, agotamiento del tiempo o proceso sin diagnóstico específico **mantienen `renderer_reachability_verified=false`**.
3. Un diagnóstico UBSan exacto desde la ejecución de `pdftoppm` instrumentado demostraría una ruta de entrada a ese constructor **bajo este PDF y esta configuración de laboratorio**. No acreditaría explotación, impacto operacional ni equivalencia source→ELF del inspector.
4. Fallos de controles normales, falsificación del diagnóstico o errores de sanitizador distintos producen fallo cerrado, sin aseveraciones de seguridad.
5. La investigación **no** sustituye la auditoría de los otros constructores y llamadores (transparencias, Type 3, grupos), ni el inventario de binarios finales.

## Validación

```sh
python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_splash_pdf_width_probe.py' -v
bash -n apps/inspector/research_patches/run_splash_pdf_width_probe.sh
python3 apps/inspector/poppler_splash_pdf_width_probe.py \
  --builder-image-id sha256:2f57f656317dc0b6106437640c8b91ee1a9452fe5c019b2e53dbd6a007272049
sh scripts/ci.sh
```

**Resultados unitarios:** Red inicial: error de importación antes de implementar los módulos; Green: 8/8. El nuevo control de distinción Mono1/grises pasó por Red **6/9** (tres fallidas) → Green **9/9**. La suite del inspector registra ahora **232/232 pruebas Python**, `bash -n` concluye con `exit 0`. Los unitarios no demuestran comportamiento del parser.

**Primer resultado instrumentado real (seis casos Mono1, antes de añadir Mono8):** `exit 0` en el ejecutor, seis procesos `exit 0`, metadatos de ancho extremo aceptados, control escalado 32×1 correcto, y **ningún diagnóstico UBSan**. Esto no era un fallo del sanitizador: el modo `Mono1` desactiva AA vectorial en `SplashOutputDev`, por lo que nunca ejercita la multiplicación vulnerable. Un segundo ensayo, con el binario Debian experimental *no instrumentado*, devolvió PBM `P4\\n536870919 1\\n`, de **67.108.880 bytes**, confirmando que ese modo puede conservar la geometría extrema sin AA. Este ensayo auxiliar no acredita alcanzabilidad de la multiplicación, ni equivalencia de binarios operativos.\n\n**Segundo resultado instrumentado real (siete procesos, grises Mono8):** ejecutor `exit 0` tras reconstruir desde la misma fuente Debian completa, imagen builder por digest, doble comprobación de SHA de fuente, corpus y runner. El verificador reportó `status=research_pdf_to_splash_constructor_ubsan`; seis procesos terminaron `exit 0` y **`wide_gray_aa` terminó `exit 1` con el diagnóstico UBSan exacto** `Splash.cc:1454`, `signed integer overflow: 536870919 * 4 cannot be represented in type 'int'`. Se confirmó `pdf_parser_to_splash_constructor_ubsan_observed=true`, `pdf_parser_reproducer_verified=true`, `renderer_reachability_verified=true`, *solo en este experimento*. Los demás casos fueron: `wide_metadata=0`, `normal_noaa=0`, `normal_aa=0`, `scaled_wide_aa=0`, `wide_noaa=0`, `wide_aa=0`. No se instaló modificación alguna de código en la imagen operativa.\n\n**Cadena causal:** el PDF sintético fija un ancho MediaBox de 536.870.919 puntos; `pdfinfo` lo admite. El modo Mono1 conserva el ancho pero `SplashOutputDev::setVectorAntialias()` anula el AA vectorial; en contraste `pdftoppm -gray -aa yes -aaVector yes -r 72` utiliza Mono8, acepta el bitmap asignado y llega al cálculo `bitmap->width * splashAASize` del constructor, donde UBSan interrumpe antes de que el buffer AA se cree. Esta reproducción **no** evalúa páginas ordinarias ni garantiza que un PDF conforme a las especificaciones habituales alcance esta ruta.\n\n**Procedencia local:** SHA-256 del runner experimental `b534efee0a9e7807ed52ee73a668400d774fe937ab900b2f8d916c1ee2ed7397`; hashes fuente Debian declarados en el verificador. El reporte no incorpora ni autentica un hash del ELF operativo.\n\n**CI integral local:** `FOLIO_E2E_PORT=43913 sh scripts/ci.sh` completó con **`exit 0`** sobre la rama aislada R1.31. Incluye 232/232 pruebas Python, Vitest, TypeScript, builds Workers `--dry-run`, Chromium E2E/accesibilidad, laboratorio de rendimiento, demo guiada y migraciones D1 **solo locales** hasta `0030`. Esta aprobación no reemplaza el gate pesado Trivy ni autoriza imágenes/despliegues.

## Gobierno y bloqueos

Todos los reportes mantienen `source_binary_equivalence_to_runtime_verified=false`, `cve_remediation_claimed=false` y `release_authorized=false`. El gate pesado Trivy permanece bloqueado hasta una auditoría posterior individual. La validación del CI general no lo reemplaza.

**ADR-023:** esta entrega solo puede integrar investigación, corpus sintético, pruebas y documentación. Nada de publicación OCI, `validation`/runtime alterado, VEX, PDFs institucionales, Preview, producción ni migraciones D1 remotas.
