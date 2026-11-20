# R1.26 · `SplashClip::clipAALine` con `SplashBitmap` real y límites de argumentos

**Fecha de verificación:** 2026-11-20 (UTC; noche del 19 de noviembre en Lima). **Alcance:** investigación defensiva de código fuente Poppler Debian, no una reproducción de PDF, ni corrección de un CVE ni autorización para runtime.

## Pregunta y precondiciones reales

R1.21 y R1.24 identificaron desbordamientos en las APIs públicas `SplashClip::test` y `testSpan`. Quedaba por revisar `SplashClip::clipAALine`, llamado desde `Splash.cc` para rasterizado antialias.

En **Poppler Debian `25.03.0-5+deb13u4`** el método calcula:

```cpp
xx0 = *x0 * splashAASize;                   // SplashClip.cc:284
// ... delimitación xMin/xMax ...
xx1 = (*x1 + 1) * splashAASize;             // SplashClip.cc:308
```

La aritmética anterior no se comprueba con `checkedMultiply` ni `checkedAdd`. Sin embargo, **sus argumentos en las llamadas del renderer deben respetar los límites de bitmap y de su buffer antialias**; el mero hecho de que el método acepte `int` no significa que un documento pueda suministrarle valores arbitrarios.

**Llamadores revisados en la misma fuente:** `Splash.cc:1320` (`drawAAPixel`, inicializa `x0=0` y `x1=bitmap->width-1`, con guard de posición de píxel); `Splash.cc:2415` y `:6439` (usan resultados de `scanner.renderAALine`). `Splash.cc:1454` y `:1476` crean el buffer antialias mediante `splashAASize * bitmap->width`: esa multiplicación constituye **otro candidato estático de revisión**, todavía sin reproducción UBSan en R1.26.

La reserva de bitmap real `SplashBitmap(64,4,1,splashModeMono1,false)` ocupa solo **32 bytes de datos de imagen** (ancho 64 subpíxeles, cuatro filas, ocho bytes por fila). No se asignan cientos de millones de píxeles. El clip es `SplashClip(0,0,8,4,true)`.

## Comparación real bajo ASan/UBSan

El harness `research_patches/splash_clipa_line_method_probe.cc` llama a los métodos **reales** `SplashClip::clipAALine` y `SplashBitmap`, no a una fórmula aritmética simulada. Se compilan de manera independiente tres variantes exactas de `SplashClip.cc` desde los archivos SHA-256 de R1.11–R1.19:

1. Poppler Debian Trixie original.
2. Debian más los cinco prototipos de investigación R1.13.
3. Cinco prototipos y el sexto overlay R1.19 de `yMaxAA`.

Los cuatro casos por variante distinguen las entradas ordinarias de las que **deliberadamente incumplen las cotas de bitmap**:

| Caso sintético | Entradas `x0/x1` | Límite del bitmap | Resultado esperado del método |
|---|---|---|---|
| `normal_origin` | 0 / 0 | Válidas | `exit 0`, sin alertas |
| `normal_in_bounds` | 0 / 3 | Válidas | `exit 0`, sin alertas |
| `invalid_x0` | 536870919 / 536870919 | **Fuera del bitmap** | UBSan, `536870919 * 4` |
| `invalid_x1` | 0 / 536870919 | **Fuera del bitmap** | UBSan, `536870920 * 4` |

Para `invalid_x0` el diagnóstico apunta a `SplashClip.cc:284`; para `invalid_x1` a `SplashClip.cc:308`. **Se exige que ambos sean informes de overflow de entero con signo de la fuente exacta**, no excepciones de memoria ni crashes genéricos. Los valores inválidos no pasan por un parser PDF y no reproducen una llamada válida del renderer.

## Dependencia de biblioteca real, procedencia y aislamiento

La clase `SplashBitmap` se instancia mediante un ELF auxiliar **solo de investigación**, `libpoppler.so.147.0.0`, conservado de la compilación R1.14. Su SHA-256 es:

```
e4be4a8a2ca314740457a02f79527fe35f39272ea317e2076fb6c933a63c6195
```

Tamaño exacto: **95 862 952 bytes**. Se exige un **archivo regular, no un enlace simbólico**, con hash y tamaño correctos antes de ejecutar Docker. El fichero se monta individualmente como `/libhelper/libpoppler.so.147` (**SONAME correcto**), con bind de solo lectura. El contenedor verifica de nuevo su SHA-256 antes **y después** de los doce procesos; el script enlaza con `-l:libpoppler.so.147`.

**Una huella SHA del binario auxiliar solo identifica sus bytes; no aporta una nueva prueba de source→ELF o paridad de runtime.** Los métodos objeto de estudio sí se compilan directamente de los tres árboles fuente verificados. La dependencia auxiliar no se convierte en artefacto publicable ni modifica imágenes existentes.

El builder local se selecciona por ID inmutable con `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges` y recursos limitados. El script reutiliza los controles previos R1.19/R1.21/R1.24, sin editar parches originales.

En la primera ejecución, el ELF auxiliar se montó erróneamente como `libpoppler.so`, distinto del SONAME `libpoppler.so.147`, y los doce procesos retornaron `exit 127`. **El verificador lo rechazó con `exit 3`**. El enlace/montaje se corrigió para referirse al SONAME real y se añadió un test específico. Ese error inicial no se utilizó como evidencia del método.

## Reproducción y límites

```sh
# Requiere artefactos Debian y parches SHA-pinned de R1.11–R1.19.
# Requiere el ELF auxiliar R1.14 intacto, por ruta regular y digest.
python3 apps/inspector/poppler_splash_clipa_line_probe.py \
  --source-directory /ruta/artefactos-debian \
  --fix-directory /ruta/parches-oficiales-debian \
  --builder-image-id "sha256:<id-local-del-builder>" \
  --helper-library-path /ruta/libpoppler.so.147.0.0

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_splash_clipa_line_probe.py' -v

python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'
FOLIO_E2E_PORT=43099 sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

El verificador exige primero **27/27 resultados C++** anteriores y después **12/12 resultados de `clipAALine`** con salidas exactas, versión de fuente, códigos y ausencia de reportes ASan no relacionados. Las pruebas unitarias rechazan artefactos falsificados, rutas de fuente ajenas, salidas simbólicas, timeouts, ELF de tamaño o hash incorrectos y desajustes de SONAME. **Falla cerrado con `exit 3`**, siempre `release_authorized=false`.

### Validaciones ejecutadas

- **Runner de fuente R1.26: `exit 0`**, con 39/39 ensayos C++ reales;
  los 12 nuevos abarcan dos controles normales y dos errores UBSan
  por cada uno de los tres árboles SHA-pinned.
- **210/210 pruebas Python del inspector**, incluidas 11 unitarias nuevas;
  `bash -n` del script del contenedor: `exit 0`.
- **CI integral local `FOLIO_E2E_PORT=43139 sh scripts/ci.sh`: `exit 0`**:
  210/210 Python, 33/33 casos de estudio UX5, Vitest/workerd,
  TypeScript, cinco paquetes compilados, builds Workers `--dry-run`,
  Chromium E2E y migraciones D1 **únicamente locales hasta `0030`**.
  No equivale a aprobación de seguridad del inspector.
- Tras fusionar los cambios de `origin/main` relacionados con
  preflight de PDFs cortos y veredictos firmados (P9), se repitieron
  **210/210 Python del inspector** y **29/29 Vitest específicos**
  (`document-routes`, `inspector-gateway/route` y `documents/pdf`);
  todos aprobaron. El CI remoto del PR certificará la integración
  completa sobre esta base. El CI local completo anterior se ejecutó
  sobre la base anterior a P9.
- **Smoke de motores existentes `exit 0, 8/8`** (PDF nativo, OCR,
  antivirus, aislamiento, rechazos cifrados, archivos adjuntos y
  malformados). La imagen existente **no incorpora** estos métodos
  de investigación.
- **Auditoría Trivy `exit 2 BLOQUEADO`**, 0 CRITICAL, 70 HIGH,
  19 UNKNOWN, dos componentes nativos sin revisión CVE suficiente;
  no VEX ni remediación declarada.

### Conclusión y siguiente trabajo

Este ensayo identifica **dos sitios de desbordamiento potencial en una API nativa cuando se violan los límites de argumentos esperados**, no una vulnerabilidad PDF alcanzable. Antes de considerarlo corregible deben demostrarse las precondiciones del renderer, especialmente para los tres callsites `clipAALine` y la multiplicación de ancho en el constructor del buffer antialias. También queda pendiente la paridad de bibliotecas completas R1.20 en su propio worktree, y otras rutas Splash, JBIG2, TrueType, Expat y ClamAV.

**ADR-023:** solo código de investigación, tests y documentación integrables con CI. No se permite VEX, cerrar CVE, cambiar runtime, reconstruir/retaggear/publicar imágenes operativas, Cloudflare, Preview/producción, D1 remoto ni PDFs institucionales. El gate Trivy del inspector sigue bloqueado.
