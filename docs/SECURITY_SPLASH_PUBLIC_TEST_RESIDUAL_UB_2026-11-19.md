# R1.21 · Overflow residual en la API pública SplashClip::test (solo investigación)

**Corte:** 2026-11-19, America/Lima. **Ámbito:** prueba sintética de un método C++ real de Poppler Debian Trixie, no un PDF institucional ni un PoC de explotación. **NO** remediación CVE, imagen/runtime aprobado, VEX ni release.

## Contexto

R1.19 acreditó que un **sexto overlay temporal** sobre Poppler Debian `25.03.0-5+deb13u4` introduce `checkedAdd`, `checkedMultiply` y `checkedSubtraction` para la operación `SplashClip::yMaxAA`. El método `clipToPath` rechazó las coordenadas extremas ensayadas sin error UBSan, conservando la protección previa de `yMinAA`.

R1.20 identifica estáticamente varias expresiones aritméticas de `splash/SplashClip.cc` aún sin comprobación. R1.21 toma **una sola** para pasar de una búsqueda de texto a una prueba ejecutada: `SplashClip::testClipPaths` escala directamente las coordenadas enteras con `x *= splashAASize; y *= splashAASize;` cuando `antialias` está activo. El método es protegido, pero la API **pública** `SplashClip::test(int x, int y)` lo invoca después de validar la pertenencia al rectángulo.

## Experimento de la API real

`research_patches/splash_public_test_probe.cc` instancia:

```cpp
SplashClip clip(0, 0, 600000000, 10, true);
clip.test(3, 3);                  // Control válido
clip.test(INT_MAX / 4 + 8, 1);  // Dentro del rectángulo; x * 4 desborda int32
```

Estas coordenadas son **sintéticas y finitas**; no se reservó una imagen ni un bitmap de 600 millones de píxeles. El propósito es **medir el comportamiento del método C++**, sin especular sobre qué PDFs o parámetros de render llegarían allí.

El script `run_splash_public_test.sh` ejecuta primero **sin modificarlo** el experimento R1.19 `run_splash_ymax_overlay.sh`: comprueba las huellas SHA-256 de fuente oficial Debian, parches quilt, cinco cambios previos y sexto overlay, prepara tres árboles en tmpfs, compila los métodos reales `SplashClip` con ASan/UBSan y exige los nueve resultados diferenciales existentes.

Después compila una segunda prueba de la **API pública real** por cada variante:

- Debian Trixie original (`original`).
- Debian más cinco prototipos SHA-pinned (`patched`).
- Los cinco prototipos y el sexto overlay R1.19 aplicado a copia aislada (`extended`).

Cada ejecutable se construye directamente desde los archivos reales `SplashClip.cc`, `SplashXPath.cc`, `SplashXPathScanner.cc` y `SplashPath.cc`, con `-fsanitize=address,undefined -fno-sanitize-recover=all`. Se usan controles de proceso con `timeout`, límites de memoria y diagnósticos acotados. El runner de Python exige los 15 resultados y falla cerrado ante huellas alteradas, ausencia de salida, falso exit 0, sanitizadores distintos o paths de fuente no válidos. No se ejecuta ningún parser PDF en este experimento.

### Evidencia reproducida

La ejecución completa `poppler_splash_public_test_probe.py` terminó con **`exit 0`** y `status=research_public_splash_method_residual_ub`.

| Condición real de `SplashClip::test` | Fuente original | Cinco prototipos | Cinco + overlay |
|---|---|---|---|
| Coordenadas normales `(3,3)` | `exit 0` | `exit 0` | `exit 0` |
| Coordenada extrema `(536870919,1)` | `exit 1`, UBSan | `exit 1`, UBSan | `exit 1`, UBSan |

La salida UBSan de `SplashClip.cc` identifica **`signed integer overflow: 536870919 * 4`** en las tres fuentes. El sexto overlay **no modifica ni protege esta expresión**. Los nueve casos anteriores R1.19 volvieron a aprobar en la misma ejecución, así que los controles `yMinAA` y `yMaxAA` investigados se mantienen efectivos para sus propios inputs.

**Resultado técnico:** existe un overflow aritmético real, repetible mediante un método **público C++**. No se ha demostrado alcanzabilidad a través del parser PDF, carga de página no confiable, explotación, DoS operativo ni asociación formal a un CVE. Ninguna de las seis salidas acredita remediación.

### Identidad, aislamiento y límites

- Fuente: Poppler Debian `25.03.0-5+deb13u4`, archivos y patches SHA-256 verificados según R1.11–R1.19.
- `SplashClip.cc` tras cinco prototipos: SHA-256 `011866818f3494d808ed988eb13c61c312ba872b47551f8ed80d3cac44c9c77c`.
- `SplashClip.cc` tras sexto overlay: SHA-256 `6512113e7233bfdd18d0c910a8f565b4f88adbfe172db5002bf0ca4e9477bdf4`.
- Overlay experimental: SHA-256 `fc2983047d1f87e072760a5fca4f2e7130829b6272f37fa3488b40d318374720`.
- Builder **local** identificado por digest, `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`. Código y binarios solo en tmpfs de contenedor; ninguna publicación OCI ni sustitución de etiquetas.
- LeakSanitizer desactivado para este ensayo aritmético. El resto de ASan/UBSan permanece activo. No hay prueba de compatibilidad de todas las configuraciones Poppler ni source→ELF de runtime.

## Contratos de regresión y reproducción

```sh
# El builder se crea localmente según el Dockerfile experimental existente;
# NO se publica, retaggea ni utiliza como imagen operativa.
python3 apps/inspector/poppler_splash_public_test_probe.py \
  --source-directory /ruta/artefactos-oficiales-Debian-R1.11 \
  --fix-directory /ruta/parches-Debian-R1.12 \
  --builder-image-id "$(cat /tmp/folio-r114-poppler-builder.iid)"

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_splash_public_test_probe.py' -v
sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

La prueba unitaria específica incluye **nueve casos** que cubren resultados buenos y entradas falsificadas: salidas vacías o simuladas, avisos de otros sanitizadores, paths de fuente alterados, salidas simbólicas, códigos de timeout y falsos errores de overflow. El runner retorna **`exit 3`** cuando la evidencia no es íntegra; nunca devuelve `release_authorized=true`.

## Verificaciones de integración ejecutadas

- Verificador diferencial fuente R1.21: **`exit 0`**, 15/15
  ensayos reales de método C++ (9 controles R1.19 y seis nuevos);
  `status=research_public_splash_method_residual_ub`.
- `python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'`:
  **190/190 pruebas Python**, incluidas 9 pruebas nuevas R1.21.
- `bash -n apps/inspector/research_patches/run_splash_public_test.sh`:
  **exit 0**.
- `FOLIO_E2E_PORT=42995 sh scripts/ci.sh`: **exit 0** sobre la
  primera base; tras integrar los cambios UX5 recientes de `origin/main`,
  se repitió con **`FOLIO_E2E_PORT=43019`**, también **exit 0**:
  **190/190 tests Python del inspector, 129/129 Chromium**, 13 pruebas
  de captura de estudio UX5, Vitest/workerd, typecheck y builds Workers
  `--dry-run`. Tras fusionar otro cambio de `origin/main` (fencing de
  comisiones), **`FOLIO_E2E_PORT=43039 sh scripts/ci.sh` volvió a
  aprobar con exit 0**, incluidas las migraciones D1 **solo locales** hasta
  `0030_processing_commission_closure_guard.sql` en API, MCP y processor.
  No se autoriza acceso a D1 remoto.
- Auditoría experimental independiente:
  `bash apps/inspector/audit_image.sh --experiment --advisories`
  terminó en **exit 2 BLOQUEADO**, 0 CRITICAL, 70 HIGH,
  19 UNKNOWN y dos componentes nativos sin cobertura CVE suficiente.
- Smoke existente `bash apps/inspector/verify_raster_guard.sh`: **exit 0, 8/8**, incluyendo PDF nativo, OCR, antivirus, aislamiento y rechazos de archivos cifrados, incrustados y malformados. Esta imagen previa **no incluye** ni pretende verificar los prototipos experimentales R1.21.
- Las imágenes locales `validation`, `ocr-integrated` y
  `poppler-experiment` conservaron exactamente sus IDs SHA-256 conocidos;
  no se instaló el ensayo R1.21 en ninguna de ellas.

## Evaluación y decisiones siguientes

1. **Nueva obligación de revisión:** determinar qué invariantes de rango existen en los llamadores reales de `SplashClip::test`, `testSpan`, `clipAALine` y `testClipPaths`. El ensayo directo prueba el overflow en código fuente, **no** que un PDF pueda proporcionar coordenadas extremas a estos métodos.
2. **Alternativas de diseño:** considerar multiplicación comprobada o conversión acotada antes del escalado antialias, con un contrato de retorno congruente con los llamadores; examinar corrección de raster, costes y casos límite para no silenciar recortes válidos. No se introduce todavía ningún séptimo parche.
3. **R1.20 separado:** la compilación completa de bibliotecas Poppler con el sexto overlay se desarrolla en otra rama; R1.21 **no la reemplaza ni modifica**. Los hallazgos deben revisarse conjuntamente antes de plantear remediación.
4. **Gate:** Trivy sigue bloqueando el inspector; los riesgos de JBIG2, TrueType, Expat, ClamAV y los CVE sin prototipos permanecen pendientes.

**Gobierno ADR-023:** solo se permite integrar **herramientas de investigación, tests sintéticos y documentación** tras CI. Prohibido publicar o retaggear OCI, modificar runtime, Cloudflare, Preview o producción, ejecutar D1 remoto, emitir VEX o procesar documentos institucionales.

El reporte mantiene `complete_splash_arithmetic_review=false`, `reached_from_pdf_parser=false`, `source_binary_equivalence_to_runtime_verified=false`, `cve_remediation_claimed=false` y **`release_authorized=false`**.
