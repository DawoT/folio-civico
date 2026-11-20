# R1.17 · Alcanzabilidad real de SplashClip, JBIG2 y TrueType en Poppler

**Fecha de investigación:** 2026-11-19 (America/Lima). **Estado:** evidencia experimental limitada a código/fuentes Debian exactas, con ASan/UBSan. **No hay autorización de runtime, CVE resueltos, VEX ni release.**

## Objetivo y decisión de diseño

R1.16 demostró dos diferencias bajo UBSan **dentro del parser PDF**: desplazamiento de 32 bits en `SampledFunction` y `lowVal=INT_MIN` en tabla Huffman JBIG2; dejó sin alcanzar otras tres rutas seleccionadas. R1.17 examina las rutas restantes con tres niveles de evidencia explícitamente separados:

1. **Método C++ real:** compilar desde ambas fuentes exactas `SplashClip::clipToPath` y sus cuatro archivos de implementación asociados; ejecutar condiciones extremas para `yMinAA` y `yMaxAA`.
2. **Parser PDF real, caso negativo/rechazo:** construir 3 PDF JBIG2 con dimensiones inválidas deliberadas y comprobar si `readPageInfoSeg` elimina el bitmap antes del `reset()`; observar el rechazo, no afirmar que `nullptr` fue desreferenciado.
3. **Parser PDF + conversión PostScript real:** generar un PDF sintético con una fuente TrueType mínima embebida de **dos glifos**, convertir mediante `pdftops -level2` instrumentado y comparar la salida Type42 con la fuente original. Esto prueba la ruta funcional, **no el overflow** de acumulación de longitudes de `FoFiTrueType`.

Cada nivel contiene entradas totalmente sintéticas, deterministas y acotadas. Se prohíben PDFs institucionales, PoCs de terceros y peticiones de red.

## Fuente/prototipos y aislamiento

**Debian original:** Poppler `25.03.0-5+deb13u4`, fuente oficial con sus 9 parches quilt. **Prototipos:** exactamente los cinco cambios R1.13 (dos parches Debian directos y tres adaptaciones investigativas). Se conserva y reutiliza el orquestador de R1.16 `run_adversarial_differential.sh`, que comprueba SHA-256 de fuente, parches y los seis archivos modificados **antes y después**, copia dos árboles a tmpfs y compila **dos variantes ASan/UBSan independientes**.

La investigación R1.17 se incorpora mediante `poppler_reachability_probe.py`, `poppler_reachability_corpus.py`, `splash_clip_method_probe.cc`, `run_reachability_differential.sh` y `run_reachability_cases.sh`. El nuevo orquestador **reutiliza** R1.16 sin duplicar la adquisición de fuentes ni desplazar su corpus ya verificado. Los dos `pdftops` instrumentados y los dos harnesses Splash se compilan después de esos pasos.

**Docker:** builder local por ID `sha256:2f57f656317dc0b6106437640c8b91ee1a9452fe5c019b2e53dbd6a007272049`, `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, con límites de CPU, memoria, PID, tiempo por prueba y artefactos de salida. No se etiqueta, modifica ni publica una imagen operativa.

## Resultados en el método real SplashClip

Los objetos `SplashClip.cc`, `SplashXPath.cc`, `SplashXPathScanner.cc` y `SplashPath.cc` se compilan **desde la fuente real de cada variante** con `g++ -fsanitize=address,undefined -fno-sanitize-recover=all`. Se crea un recorte triangular válido, antialias activado y una matriz identidad. Esta ejecución llama a la implementación verdadera de `SplashClip::clipToPath`, pero **no** atraviesa el parser de PDF.

| Método directo (original sintético) | Debian original | Fuente + cinco prototipos |
| --- | --- | --- |
| Recorte triangular normal | `exit 0`, ruta normal aceptada | `exit 0`, igual |
| `yMinI=536870919`, `yMinI * 4` | **UBSan: signed integer overflow**, `SplashClip.cc:212`, `exit 1` | **`checkedMultiply` rechaza**, `exit 0`, mensaje `splash_ymin_checked_rejected` |
| `yMinI=0`, `yMaxI=536870918`: `(yMaxI+1)*4` | **UBSan: signed integer overflow**, `SplashClip.cc:213`, `exit 1` | **UBSan persiste**, `SplashClip.cc:217`, `exit 1` |

El último resultado establece un defecto **residual en el mismo método** a pesar del guard de `yMinAA`. El reporte conserva `splash_cve_fully_verified=false` y `reached_through_pdf_parser=false`; no convierte esta evidencia en una remediación de `CVE-2026-102621`.

## Ruta JBIG2: rechazo temprano, no reproducción de nullptr

Se crean páginas sintéticas JBIG2 con:

| Fixture | Dimensiones internas (w, h) | Resultado del parser |
| --- | --- | --- |
| `jbig2_zero_width` | (0, 1) | `Syntax Error: invalid width/height` |
| `jbig2_zero_height` | (1, 0) | `Syntax Error: invalid width/height` |
| `jbig2_zero_stripe` | (1, desconocida), altura inicial 0 | `Syntax Error: invalid width/height` |

El código `readPageInfoSeg` de Trixie ya valida `if (!pageBitmap->isOk()) { delete pageBitmap; pageBitmap = nullptr; return; }` antes de que `reset()` use la memoria del bitmap. Estas tres entradas fueron rechazadas, tanto por la fuente original como por los prototipos, **sin UBSan** y con rasterizados idénticos. En consecuencia, **no** demuestran la aritmética nula que motivó `CVE-2026-93312`; solo delimitan un conjunto de entradas que se detienen en un guard anterior. **No se afirma** que otras transiciones, expansiones o estados de bitmap no puedan llegar a esa vulnerabilidad.

## Ruta TrueType Type42: fuente pequeña, sin overflow

Se construyó localmente con FontTools FontBuilder una fuente sintética de dos glifos originales (`.notdef` y `A` geométrica); su representación TTF se conserva en base64 dentro de la investigación para **no depender de FontTools** durante las pruebas. El código valida el SHA-256 y tamaño antes de generar un PDF PDF 1.4 que la incorpora en `/FontFile2`.

- Fuente TTF: **956 bytes**, SHA-256 `843b720df261131b2d0ce15ea4ace1157f96527bd194fac69da5612b35773078`.
- PDF sintético: **1.934 bytes**, SHA-256 `74b1a8cb79731bce11268ee6714c65dff30dd9d4d5e34622f15d56eeb4b5f279`.
- Se convierte mediante **`pdftops -level2`** con Poppler compilado con ASan/UBSan. Se exige `/FontType 42 def`, `/sfnts [` y el nombre sintético `FolioSynthetic-Regular` en el PostScript.
- La salida original y con prototipos fue idéntica byte a byte (19.668 bytes) en el pase de diagnóstico, sin informes de sanitizer.

El ensayo **no reproduce** overflow de suma de longitudes glyph/loca: una fuente con 956 bytes no puede reproducir la misma presión aritmética que entradas maliciosas enormes. Además, el harness aritmético de R1.16 señaló la alineación residual `length += 4 - (length & 3)`. **No se concluye** que `CVE-2026-102620` esté reparada.

### Identidad de los nuevos PDF sintéticos

| PDF | SHA-256 |
| --- | --- |
| `jbig2_zero_width` | `311be6c34560da242a14813352acfb5fcc7528c620f6e890af4428c96545e233` |
| `jbig2_zero_height` | `872b520070f1aca234c5bf5a76f89a89716c6a0873a0f7dbac326ec924d72bbf` |
| `jbig2_zero_stripe` | `7fe11eb1f42fcdf4fa5ddf028497213b5b7c58c0439921870aba909e9528967b` |
| `type42_synthetic` | `74b1a8cb79731bce11268ee6714c65dff30dd9d4d5e34622f15d56eeb4b5f279` |

## Reproducción

```sh
# Desde la raíz del repositorio, solo builder local de investigación.
docker build --target poppler_builder \
  --iidfile /tmp/folio-r117-builder.iid \
  -f apps/inspector/Dockerfile.poppler-experiment .

python3 apps/inspector/poppler_reachability_probe.py \
  --source-directory /ruta/tres-archivos-fuente-debian-r111 \
  --fix-directory /ruta/siete-parches-debian-r112 \
  --builder-image-id "$(cat /tmp/folio-r117-builder.iid)"

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_reachability_probe.py' -v
sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

El CLI comprueba los 6 casos de parser R1.16, las 3 pruebas del método Splash en cada variante, 3 rechazos JBIG2 por variante y 1 conversión Type42 por variante, además de todos los hashes y archivos de evidencia. Cualquier error, falta de evidencia, salida alterada, señal inesperada o diferencia del baseline termina **fail-closed con exit 3**. Nunca cambia el runtime ni devuelve `release_authorized=true`.

## Verificación definitiva R1.17

El ejecutor `poppler_reachability_probe.py` terminó con **`exit 0`**
y `status=source_method_reachability_research_only` en una reconstrucción
íntegra **desde dos árboles temporales** de fuente SHA-pinned.

- **Splash (método C++ real): 3/3 categorías verificadas en ambas variantes.**
  Original `yMinAA`: UBSan `exit 1`; parche: rechazo comprobado
  `exit 0`. `yMaxAA`: UBSan `exit 1` **en ambas**.
  Caso normal: `exit 0` en ambas.
- **JBIG2: 3/3 PDFs de página inválida**, rechazo inicial
  `invalid width/height` en ambas variantes, `exit 0`, sin UBSan,
  misma representación PGM; SHA-256 de cada raster
  `c8f707352f61f18c6120468e71d1dd2d77b107dbbee400b6e30da2c119b2c694`.
  **No se reproduce** la aritmética sobre `nullptr` de `reset()`.
- **TrueType: 1/1** PDF sintético con dos glifos convertido con
  `pdftops` de ambas fuentes: PostScript `/FontType 42` y `/sfnts`
  **idéntico byte a byte**, SHA-256
  `035772b3c50483e7e88a13863da16403fd9b5badf23a49c3041df1bb9b95a871`.
  **No se reproduce** overflow de glyph/loca.
- **R1.16 retenido:** dos diferencias UBSan anteriores
  (`sampled32`, `jbig2_intmin`) y cuatro controles raster con SHA
  idéntico; sin reclasificar CVE ni borrar el aviso de sintaxis JBIG2.
- **Pruebas unitarias:** `172/172` Python del inspector
  (10 nuevas R1.17 y 162 previas), incluyendo corrupción de corpus,
  diferencia de datos, simulaciones de éxito y evidencia ausente.
  `bash -n` de ambos scripts de laboratorio: `exit 0`.
- **CI general local:** `sh scripts/ci.sh` **exit 0**,
  con typecheck, Vitest/workerd, builds Workers `--dry-run`,
  Chromium E2E/accesibilidad y migraciones D1 `0027` **solo locales**.
  No incluye el gate pesado Trivy. La primera ejecución tras
  actualizar `main` encontró el puerto local `4175` ocupado por otro
  Playwright y terminó `exit 1` antes de iniciar las E2E. Se repitió
  el contrato completo con `FOLIO_E2E_PORT=42963`, **exit 0**,
  sin detener procesos ajenos ni editar la configuración compartida.
- **Smoke de motores existentes:** `bash apps/inspector/verify_raster_guard.sh` **exit 0, 8/8**, incluyendo antivirus, OCR, PDF nativo y rechazos de documentos cifrados/adjuntos. Se ejecutó sobre la imagen experimental existente **sin instalar los prototipos**, por lo que no certifica los binarios de investigación.
- **Auditoría experimental:** `bash apps/inspector/audit_image.sh
  --experiment --advisories` **exit 2 BLOQUEADO**:
  0 CRITICAL, 70 HIGH, 19 UNKNOWN, dos componentes fuente todavía
  sin cobertura CVE suficiente. Sin VEX.

La salida declara explícitamente `reached_through_pdf_parser=false` para
la prueba Splash, `null_bitmap_arithmetic_reproduced=false` para JBIG2
y `truetype_glyph_length_overflow_reproduced=false`. `release_authorized=false`
permanece inalterado. Los objetos y ejecutables de esta comparación solo
existieron en `/work` temporal, sin copiarse al inspector.

## Seguridad, deuda y siguiente etapa

- **Splash:** la ruta `yMaxAA` sigue desprotegida incluso después del guard `yMinAA`; requiere corrección específica, análisis completo de operaciones y revisión independiente (no una exención automática).
- **JBIG2:** la ruta de `pageBitmap->isOk()` en `reset()` no ha sido alcanzada con un bitmap no válido vivo. La comprobación anterior en `readPageInfoSeg` impide este conjunto de fallos. Es preciso investigar `expand()`, regiones inmediatas y otras transiciones de estado, sin grandes asignaciones ni riesgo de agotamiento real.
- **TrueType:** reproducir un desbordamiento real de `cvtSfnts` requiere entradas más complejas y revisar la alineación del buffer; las pruebas con una fuente pequeña no bastan.
- **CVE y release:** siguen sin resolver los CVE no cubiertos por los 5 prototipos, los HIGH/UNKNOWN, Expat, ClamAV, SBOM y source→ELF. `cve_remediation_claimed=false`, `all_three_cve_paths_verified=false` y `release_authorized=false` son obligaciones, **no opciones**.

De acuerdo con [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md), solo pueden integrarse **herramientas de investigación, pruebas y documentación**, tras CI. Sin Dockerfile/runtime nuevo, imágenes `validation`/`poppler-experiment` modificadas, publicación OCI, Cloudflare, Preview, producción, D1 remoto, VEX, datos sensibles ni documentos institucionales.

**Conclusión:** se amplía la evidencia de la fuente Poppler exacta, incluido un fallo aritmético residual en una función real. **El inspector continúa bloqueado para release.**
