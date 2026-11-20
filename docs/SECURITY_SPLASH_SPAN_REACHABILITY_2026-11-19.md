# R1.24 · Alcance del overflow en SplashClip::testSpan (investigación)

**Corte:** 2026-11-19, America/Lima. **Categoría:** fuente real de Poppler bajo ASan/UBSan, corpus sintético acotado. **No es remediación CVE, prueba de explotabilidad, ni autorización de OCI/runtime/release.**

## Contexto y objetivo

R1.19 añadió un sexto **overlay de investigación únicamente en fuente temporal** con operaciones comprobadas para `SplashClip::clipToPath::yMaxAA`. R1.21 demostró que otra operación `x *= splashAASize` dentro de `SplashClip::testClipPaths`, invocada por la API pública `SplashClip::test`, aún desborda `int32` en el código real. R1.20 inventarió expresiones adicionales.

R1.24 comprueba una segunda ruta de API pública: `SplashClip::testSpan(int spanXMin, int spanXMax, int spanY)`. La versión Debian Poppler Trixie `25.03.0-5+deb13u4` ejecuta, si está activado `antialias` y existe al menos una trayectoria, las tres expresiones:

```cpp
scanners[i]->testSpan(
    spanXMin * splashAASize,
    spanXMax * splashAASize + (splashAASize - 1),
    spanY * splashAASize);
```

El código comprueba primero si la franja está dentro de la parte rectangular del recorte, **pero esa comprobación no exige que los productos por `splashAASize` quepan en un entero con signo**.

## Procedimiento reproducible

Los nuevos archivos `splash_span_method_probe.cc`, `run_splash_span_probe.sh` y `poppler_splash_span_probe.py` reutilizan **sin modificar** la atestación fuente Debian R1.11–R1.19, los cinco prototipos (R1.13), el sexto overlay (R1.19), el orquestador R1.21 y sus nueve más seis resultados anteriores.

El método se compila **a partir de `SplashClip.cc`, `SplashXPath.cc`, `SplashXPathScanner.cc` y `SplashPath.cc` reales**, para tres árboles separados: original, cinco prototipos y seis overlays. Compilación con `-fsanitize=address,undefined -fno-sanitize-recover=all`, ejecución con timeout y validación estricta de los informes UBSan. **No se crea una imagen de 600 millones de píxeles**: la coordenada límite se usa solo como argumento del método C++.

El harness crea un rectángulo finito `SplashClip(0,0,600000000,10,true)`, agrega una trayectoria triangular pequeña no rectangular `(0,0)→(10,2)→(2,8)` mediante `clipToPath`, y evalúa cuatro condiciones:

1. `normal`: `testSpan(1,2,1)`, con triángulo.
2. `no_path_extreme`: `testSpan(536870919,536870919,1)`, **sin** agregar trayectoria.
3. `outside_guard`: `testSpan(600000010,600000010,1)`, con triángulo pero fuera del rectángulo.
4. `span_x_aa_overflow`: `testSpan(536870919,536870919,1)`, **dentro** de rectángulo y **con** triángulo.

La multiplicación `536870919 * 4` desborda `int32`. El parser PDF no se invoca.

### Resultados ejecutados

El runner completo finalizó con **`exit 0`** y `status=research_public_splash_testspan_residual_ub`.

| Entrada / propiedad | Debian original | Cinco prototipos | Cinco y sexto overlay |
|---|---|---|---|
| `normal`, con triángulo | `exit 0` | `exit 0` | `exit 0` |
| `no_path_extreme` | `exit 0` | `exit 0` | `exit 0` |
| `outside_guard` | `exit 0` | `exit 0` | `exit 0` |
| `span_x_aa_overflow` | **UBSan `exit 1`** | **UBSan `exit 1`** | **UBSan `exit 1`** |

El informe UBSan identifica `SplashClip.cc:264` con `signed integer overflow: 536870919 * 4` en los tres árboles de fuente. En total se verificaron **12/12 nuevas salidas** de método, **más 6/6 del ensayo de API pública R1.21 y 9/9 de R1.19: 27/27**.

La reproducción exige, para este harness, antialias activo, una trayectoria no rectangular y que el tramo atraviese el guard rectangular. **No prueba que estas sean las únicas condiciones posibles ni que un PDF real pueda alcanzarlas.**

## Llamadores reales y precondiciones de Splash

La revisión del `splash/Splash.cc` incluido en el archivo Debian oficial identifica al menos estos sitios de llamada en el árbol fuente exacto (líneas de esta revisión, no API estable):

| Método | Llamadores y contexto | Límite comprobado y riesgo pendiente |
|---|---|---|
| `state->clip->test(x,y)` | `drawPixel` (~1289), dibujo de imágenes (~3499), otros bucles de píxeles | Los llamadores suelen operar sobre dimensiones del bitmap o sobre coordenadas derivadas de la transformación, pero R1.21 **no demuestra** un PDF o bitmap que alcance su overflow. No asumir que todos los flujos tienen la misma cota. |
| `state->clip->testSpan(x0,x1,y)` | `fill` (~2443), `xorFill` (~2563), raster de imágenes (~3052 y ~3930), otro relleno (~6513) | Varias rutas recortan `x0/x1` contra `getXMinI/getXMaxI`, lo cual **no limita por sí solo** el producto `x * splashAASize` a `INT_MAX`. Otras rutas usan `xa` y `xb-1` calculados. Deben revisarse cotas de bitmap y conversiones numéricas antes de proponer un fix. |
| `state->clip->clipAALine(aaBuf,...)` | `drawAAPixel` (~1320), relleno antialias (~2415), otro render antialias (~6439) | `drawAAPixel` comprueba `x < bitmap->width` pero `clipAALine` usa también `*x0*splashAASize` y `(*x1+1)*splashAASize`. No hay reproducción segura aislada de esta ruta en R1.24; no se afirma ausencia ni presencia de un overflow UBSan nuevo. |

**Matiz importante:** el harness invoca directamente la API pública C++, no `Splash::fill`, `SplashOutputDev` ni `pdftoppm` sobre un PDF malicioso. La existencia de llamadas dentro de un renderer **no** equivale a explotabilidad desde PDF: sería necesario controlar las precondiciones completas, la validación de tamaño de bitmap, límites de coordenadas y el tratamiento de errores de `clipToPath`.

## Identidad, seguridad y criterios fail-closed

- Fuente base: Debian Poppler `25.03.0-5+deb13u4`, los tres archivos Debian y siete parches oficiales verificados por SHA-256; tres prototipos adaptados igualmente SHA-pinned.
- `SplashClip.cc` con cinco prototipos: `011866818f3494d808ed988eb13c61c312ba872b47551f8ed80d3cac44c9c77c`.
- `SplashClip.cc` tras el sexto overlay R1.19: `6512113e7233bfdd18d0c910a8f565b4f88adbfe172db5002bf0ca4e9477bdf4`.
- Overlay: `fc2983047d1f87e072760a5fca4f2e7130829b6272f37fa3488b40d318374720`.
- Builder local por digest `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, tmpfs efímero, límites de CPU/memoria/procesos. Sin servicios externos, PDFs institucionales ni cambios de imagen operativa.
- `verify_span_results` exige **12 resultados reales**, todos con ruta de código fuente, códigos de retorno y texto exacto, rechazando enlaces simbólicos, artefactos ausentes, valores de overflow distintos, falsos éxitos, timeouts y errores no relacionados. El runner entero además exige los 15 resultados R1.19/R1.21 previos. `exit 3` ante evidencia incompleta.
- `-fsanitize=address,undefined` activo; LeakSanitizer desactivado en estas pruebas aritméticas. No es una auditoría completa del motor.

## Verificación y siguientes pasos

Los nueve tests nuevos `test_poppler_splash_span_probe.py` cubren invariantes, falsificación de evidencia, tipos de error, rutas alteradas, contrapartidas sin trayectoria y límites de timeout. La suite completa del inspector, el CI integral y el gate CVE deben mantenerse independientes de la prueba concreta.

### Ejecución y comprobaciones realizadas

```sh
# Artefactos Debian exactos y parchado oficial R1.11-R1.19, fuera de runtime.
python3 apps/inspector/poppler_splash_span_probe.py \
  --source-directory /ruta/fuentes-debian-pinned \
  --fix-directory /ruta/parches-debian-pinned \
  --builder-image-id "sha256:<id-del-builder-local>"

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_splash_span_probe.py' -v
python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'
FOLIO_E2E_PORT=43079 sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

- Prueba real de fuente para las tres variantes: **exit 0, 27/27 controles
  ASan/UBSan**. Los 12 nuevos resultados se ejecutaron con el método
  real; no se confunden con resultados simulados de tests unitarios.
- **9/9 unitarias R1.24** y **199/199 pruebas Python del inspector**:
  exit 0. `bash -n` del nuevo script: exit 0.
- Auditoría Trivy `--experiment --advisories`: **exit 2,
  BLOQUEADO**, 0 CRITICAL / 70 HIGH / 19 UNKNOWN, dos componentes
  de fuente sin cobertura CVE completa. La entrada anterior de 89
  bloqueos no significa 89 CVE independientes corregibles.
- CI integral local `FOLIO_E2E_PORT=43079 sh scripts/ci.sh`: **exit 0**,
  incluyendo **199/199 pruebas Python del inspector**, **21/21 pruebas de
  estudio UX5**, Vitest/workerd, TypeScript, builds Workers `--dry-run`,
  Chromium E2E y migraciones D1 **solo locales hasta `0030`**.
- Smoke de motores existentes `bash apps/inspector/verify_raster_guard.sh`:
  **exit 0, 8/8** (antivirus, OCR, PDF nativo, aislamiento, cifrados,
  adjuntos y malformados). La imagen existente **no** incorpora el overlay
  ni el ensayo R1.24; el smoke no prueba la remediación del overflow.
- Este trabajo no modifica `Dockerfile.poppler-experiment`, etiquetas
  `validation`, `ocr-integrated` ni `poppler-experiment`.
  Tampoco realiza OCI push/retag, Cloudflare, D1 remoto o despliegues.

**Pendientes que NO resuelve este cambio:** revisión de `clipAALine` con límites reales de `SplashBitmap`, rangos de `testSpan` desde los llamadores del renderer, reproducción o descarte de ruta a través de PDF, análisis del contrato de un eventual `checkedMultiply` (el método devuelve un enum y puede alterar las decisiones de recorte), y paridad de Poppler completo R1.20 en su rama separada.

**Estado del reporte:** `complete_splash_arithmetic_review=false`, `pdf_parser_reproducer_verified=false`, `cve_remediation_claimed=false`, `release_authorized=false`. Trivy/Expat/ClamAV/JBIG2/TrueType y demás riesgos nativos siguen fuera del alcance de remediación de R1.24. Según ADR-023, solo puede integrarse investigación/tests/documentación tras CI; **no** runtime, publicación OCI, VEX, despliegue ni migraciones D1 remotas.
