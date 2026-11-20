# R1.27 · Overflow de ancho en los constructores reales de Splash

**Fecha:** 2026-11-20, America/Lima. **Categoría:** investigación defensiva C++ con ASan/UBSan y Poppler Debian original. **NO** demuestra alcanzabilidad desde PDF, reparación de un CVE, equivalencia con runtime ni autorización de despliegue.

## Causa raíz en código fuente

En Poppler Debian Trixie `25.03.0-5+deb13u4`, ambos constructores de `Splash` calculan el ancho antialias en un entero con signo antes de llamar al constructor de `SplashBitmap`:

```cpp
aaBuf = new SplashBitmap(splashAASize * bitmap->width,
                         splashAASize, 1, splashModeMono1, false);
```

Los sitios exactos son `splash/Splash.cc:1454` (overload con `SplashScreenParams *`) y `splash/Splash.cc:1476` (overload con `SplashScreen *`). El factor `splashAASize` vale **4** en la configuración investigada. Un ancho de **536870919** requiere `536870919 * 4`, resultado fuera de los límites de `int32`.

La comprobación de memoria del constructor de destino, `SplashBitmap`, **no precede ni protege esta multiplicación**. En contraste, `SplashBitmap` verifica varios tamaños de filas, pero sus controles dependen del modo de color y no prueban el rango del ancho antialias.

### Rastreo de los llamadores

En `poppler/SplashOutputDev.cc` de la misma fuente:

- El constructor de `SplashOutputDev` inicializa `SplashBitmap(1,1,...)` y un `Splash`.
- `SplashOutputDev::startPage` (~1314–1348) obtiene `w` y `h` desde `GfxState`, intenta reservar el bitmap y vuelve a uno de **1 × 1** cuando `getDataPtr()` es nulo.
- Cuando la reserva tiene éxito, la función pasa directamente el bitmap a `new Splash(bitmap, vectorAntialias, &screenParams)`. En **ese tramo** no se comprueba `w * splashAASize`.
- Hay otros llamadores en fuentes Type 3, transparencias y patrones. Sus invariantes completos no se han auditado.

**Limitación:** no se ha demostrado que un documento PDF pueda producir ese ancho después de las validaciones de página, DPI, conversiones de tamaños y políticas de recursos. La prueba directa del objeto C++ no equivale a un PoC de documento.

## Ensayo C++ ejecutado sobre biblioteca completa

`research_patches/splash_aa_width_constructor_probe.cc` crea **objetos verdaderos** `SplashBitmap`, `SplashScreen` y `Splash`; no utiliza ecuaciones simplificadas ni mocks. Se reconstruyó desde el builder original de Debian la biblioteca **`libpoppler.a` completa**, con **123 pasos Ninja**, vinculada al programa de prueba, usando `-fsanitize=address,undefined`, `-fno-sanitize-recover=all` y `-fno-sanitize=vptr`.

El control ancho se realiza con `SplashBitmap(width,1,1,splashModeMono1,false)`. Para `width=536870919` el buffer tiene **67108865 bytes (64 MiB + 1 byte)**. El harness comprueba que `getDataPtr()` **no** sea nulo y que el ancho, alto y tamaño de fila sean los esperados. Es por tanto un bitmap monocromo **realmente asignado**, con altura de una sola fila, no un objeto artificial sin memoria de píxeles.

Se ejecutan cuatro casos por cada uno de los **dos constructores reales**:

| Caso | Ancho de entrada | Antialias | Constructor con parámetros | Constructor con pantalla |
|---|---:|---|---|---|
| `normal_noaa` | 8 | No | `exit 0` | `exit 0` |
| `normal_aa` | 8 | Sí | `exit 0` | `exit 0` |
| `wide_noaa` | 536870919 | No | `exit 0` | `exit 0` |
| `wide_aa` | 536870919 | Sí | **UBSan `exit 1`** | **UBSan `exit 1`** |

El informe real en el primer overload identifica `Splash.cc:1454:103`; el segundo, `Splash.cc:1476:103`. Ambos señalan **`signed integer overflow: 536870919 * 4`**. Los otros seis procesos no emitieron alertas.

**Resultado real:** Docker completó con `exit 0`, los ocho registros de proceso cumplieron su contrato y `inspect_constructor` devolvió `status=research_real_splash_aa_width_constructor_overflow`. El test no procesa PDFs.

### Control negativo rechazado

Una primera versión del harness utilizó `splashModeRGB8` para el ancho extremo. `SplashBitmap` rechazó esa reserva antes de llegar a `Splash`, con mensaje `Bogus memory allocation size` y `exit 3`. El verificador **falló cerrado** y no lo consideró evidencia de overflow del constructor. La versión final utiliza Mono1 con asignación verificada y mantiene el caso ancho con antialias desactivado como control positivo.

### Fuente, aislamiento y límites del sanitizador

- Builder local inmutable: `sha256:2f57f656317dc0b6106437640c8b91ee1a9452fe5c019b2e53dbd6a007272049`; fuente Debian instalada y verificada con archivos originales SHA-pinned en su Dockerfile.
- `splash/Splash.cc`: SHA-256 `dbf3dcafa042348499ccefba4dd586979b7080ffa7064901a7ecebfc4c9fe27c`, validada antes y después de compilar.
- `splash/SplashBitmap.cc`: SHA-256 `206d9f4a6e5bb9054e7ef769d3b0fa3e9332b0f2c65ba062fe40f922d80ef7f0`.
- `poppler/SplashOutputDev.cc`: SHA-256 `f551d09a1dce5dda5787cc66305714259a0ba24766a765cbbcd9af27cc0cd741`.
- El código del harness está protegido por SHA-256 y el runner comprueba que las dos multiplicaciones originales siguen presentes.
- Docker ejecutado como `65534:65534`, con `--pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges`, CPU/memoria/procesos limitados y binarios solo en tmpfs. No modifica ninguna imagen existente.
- `-fsanitize=vptr` se excluye deliberadamente por la limitación RTTI registrada en investigación anterior; el resto de ASan/UBSan permanece activo. `LeakSanitizer` desactivado. No se prueba compatibilidad con todas las configuraciones de Poppler.

## Verificación y reproducción

`poppler_splash_aa_constructor_probe.py` comprueba el digest del builder, las huellas del harness y la existencia de **ocho salidas reales**. Rechaza cambios de líneas o operandos UBSan, sustituciones por avisos ASan, timeouts, symlinks, resultados simulados, fallos de compilación o marcas de éxito sin registros. Devuelve `exit 3` si la evidencia no está íntegra, con `release_authorized=false`.

```sh
python3 apps/inspector/poppler_splash_aa_constructor_probe.py \
  --builder-image-id "sha256:<ID-del-builder-local>"

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_splash_aa_constructor_probe.py' -v
python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'
FOLIO_E2E_PORT=43179 sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

**Ejecuciones verificadas:**
- Biblioteca Poppler original completa, **123 pasos de CMake/Ninja**;
  runner C++ real **exit 0, 8/8**, incluidos ambos overloads y el
  bitmap Mono1 físicamente asignado.
- **12/12 unitarias R1.27**, **222/222 Python del inspector** y
  validación sintáctica de C++ y Bash: **exit 0**.
- **CI integral local `FOLIO_E2E_PORT=43179 sh scripts/ci.sh`:
  exit 0**: 222 Python, 33 pruebas UX5, Vitest/workerd, TypeScript,
  builds de cinco paquetes, builds Workers `--dry-run`, Chromium E2E
  y migraciones D1 **solo locales hasta `0030`**.
- **Smoke existente `bash apps/inspector/verify_raster_guard.sh`:
  exit 0, 8/8**. Las etiquetas locales `validation`,
  `ocr-integrated` y `poppler-experiment` conservaron exactamente
  sus IDs previos; las imágenes existentes **no** incluyen esta prueba.
- **Auditoría experimental Trivy `exit 2`, BLOQUEADA**:
  0 CRITICAL, 70 HIGH y 19 UNKNOWN; dos componentes nativos sin
  cobertura CVE suficiente. No se aplicó waiver, VEX ni aprobación.

La aprobación del CI no autoriza releases ni prevalece sobre Trivy.

## Evaluación y siguientes pasos

1. Auditar los rangos máximos de páginas PDF, escalado, DPI y conversión a `int` antes de `SplashOutputDev::startPage`. Las llamadas de otros contextos (Type 3, transparencia, grupos y tiling) requieren revisión propia.
2. Evaluar `checkedMultiply(bitmap->width, splashAASize, &aaWidth)` u otra protección equivalente, **sin aplicar un parche aún**: hace falta definir el contrato de error, fallback y liberación de recursos cuando la reserva original existe pero el AA buffer no es representable.
3. Revisar por separado la expresión `(width+7)>>3` para `splashModeMono1` y los productos de `Splash::clipAALine` ya acotados en R1.26.
4. Mantener R1.20 (paridad completa de utilidades PDF con sexto overlay) en su worktree independiente; este ensayo no lo sustituye.

**Estado:** `pdf_parser_reproducer_verified=false`, `renderer_reachability_verified=false`, `source_binary_equivalence_to_runtime_verified=false`, `complete_splash_arithmetic_review=false`, `cve_remediation_claimed=false` y **`release_authorized=false`**.

**Gobierno ADR-023:** únicamente código de investigación, pruebas sintéticas y documentación. No cerrar CVE ni emitir VEX; no publicar/retaggear OCI, cambiar Dockerfile/runtime, Cloudflare, Preview/producción, D1 remoto ni procesar documentos institucionales.
