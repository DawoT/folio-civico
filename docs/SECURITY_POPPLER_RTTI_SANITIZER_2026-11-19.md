# R1.15 · Enlace ASan/UBSan de pdfinfo y paridad de metadatos Poppler

**Corte:** 2026-11-19 (America/Lima). **Estado:** investigación local sobre la fuente Debian Poppler fijada; **sin parche autorizado para runtime, sin CVE resuelto y sin release**.

## Problema reproducido en R1.14 y análisis causal

El paquete fuente exacto `25.03.0-5+deb13u4` compila `libpoppler.so.147` con `-fvisibility=hidden`. Su objeto `Annot.cc.o` contiene RTTI para `AnnotLink`, pero ese símbolo no está exportado en el ELF compartido: `nm -C` lo muestra como símbolo local y `nm -D -C` no lo ofrece como exportación pública. La instrumentación genérica `-fsanitize=address,undefined` de `pdfinfo.cc` incorpora controles UBSan de punteros virtuales (`vptr`) que requieren el RTTI no exportado; al enlazar `pdfinfo` se obtenía `undefined reference to typeinfo for AnnotLink`. La biblioteca y las otras utilidades instrumentadas sí compilaban.

**Solución de investigación probada:** añadir `target_compile_options(pdfinfo PRIVATE -fno-sanitize=vptr)` exclusivamente al **target CMake `pdfinfo`**, después de verificar SHA-256 del código fuente y aplicar los cinco parches al árbol temporal. La configuración añade esa línea solo a `/work/source/utils/CMakeLists.txt` de una copia aislada; **no modifica** los CMakeLists del repositorio, `Dockerfile.poppler-experiment`, la compilación principal de `libpoppler` ni los targets `pdftotext`/`pdftoppm`.

Se conservan **AddressSanitizer y los demás instrumentos de UBSan** en las tres utilidades. La exención puntual **pierde los controles UBSan `vptr` en `pdfinfo`**; por ello no debe trasladarse automáticamente a una imagen de operación sin revisión de riesgo. No se añade ningún export RTTI ni se altera ABI.

## Evidencia experimental real

Se ejecutó el verificador reproducible R1.14 ampliado, `apps/inspector/poppler_isolated_sanitizer.py`, con los mismos archivos fuente y parches oficiales Debian SHA-pinned, el mismo builder local identificado por digest y sin red. El resultado fue **`exit 0`** y `status=research_sanitizer_build_completed`.

- **Tres utilidades instrumentadas:** `pdftotext`, `pdftoppm`, **`pdfinfo`** y la biblioteca `libpoppler.so.147` recompilados con ASan/UBSan. `ldd` de `pdfinfo` confirma enlace con `libpoppler.so.147` de `/work/build`, `libasan.so` y `libubsan.so`.
- **5/5 informes de metadatos `pdfinfo` idénticos byte por byte** al builder original Debian: PDF nativo, escaneado, recorte vectorial, `SampledFunction BitsPerSample=32` y PDF original con enlace de anotación. Se validan también `Pages: 1`, `Encrypted: no` y `PDF version: 1.4`.
- **1/1 extracción `pdfinfo -url` idéntica** al baseline, sobre `AnnotLink` sintético con URI reservada `https://example.invalid/folio-r115`. No hubo navegación ni solicitud de red.
- **LeakSanitizer activado únicamente para `pdfinfo`** en cinco pruebas de metadatos y una de anotación (`ASAN_OPTIONS=detect_leaks=1:abort_on_error=1`): las seis terminaron sin informes de fuga ni errores de sanitizer. Se mantiene `detect_leaks=0` para `pdftotext` y `pdftoppm`; no se afirma cobertura de fugas para el inspector completo.
- Los controles heredados de R1.14 siguen aprobados: **4/4 rasters idénticos píxel a píxel**, **2/2 salidas de texto idénticas**, PDF truncado rechazado con `exit 1` y sin señal de sanitizador.
- Los SHA-256 de los seis archivos de fuente de R1.13 y los tres prototipos continúan verificados antes y después de aplicar los cambios, con operación limitada a tmpfs del contenedor.

La procedencia del builder local fue `sha256:2f57f656317dc0b6106437640c8b91ee1a9452fe5c019b2e53dbd6a007272049`. Es un ID de imagen de investigación **local**, no publicación OCI ni candidato autorizado. `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges` mantienen el aislamiento.

### Verificación negativa y controles

El pipeline rechaza salidas de `pdfinfo` vacías, ausentes, simbólicas, sobredimensionadas, con páginas inesperadas, cifrado no esperado, versión diferente o anotación sin la URI sintética exacta. También rechaza informes divergentes del baseline, incluido un solo cambio de byte de metadatos o texto de enlaces. Se añadieron **seis pruebas unitarias R1.15** de límites y falsificaciones; junto con la suite existente, **147/147 pruebas Python del inspector aprobaron**.

La auditoría de la imagen experimental **sigue bloqueada**: `bash apps/inspector/audit_image.sh --experiment --advisories` terminó en **`exit 2`, 0 CRITICAL / 70 HIGH / 19 UNKNOWN, dos componentes nativos todavía sin evaluación completa**. Ningún resultado modifica CVE, SBOM, ledger, VEX ni release gate.

### Validación de integración R1.15

- `python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'`: **147/147 pruebas aprobadas**, incluidas las seis nuevas R1.15.
- `sh scripts/ci.sh`: **exit 0** en la rama R1.15, incluidos Vitest, TypeScript, builds/dry-run, Chromium y migraciones D1 **locales** hasta la `0024`. No constituye un gate de CVE.
- `bash apps/inspector/verify_raster_guard.sh`: **exit 0, 8/8** sobre la imagen experimental existente, que no contiene los prototipos Poppler R1.13–R1.15. Verifica OCR/nativo, entorno aislado, AV y rechazos antes de Poppler; **no** sustituye al test del binario ASan/UBSan.
- `bash apps/inspector/audit_image.sh --experiment --advisories`: **exit 2 BLOQUEADO**, 0 CRITICAL / 70 HIGH / 19 UNKNOWN, dos motores fuente sin cobertura CVE completa.

## Reproducir sin alterar runtime

```sh
# 1. Builder local, sin sustituir etiquetas de runtime.
docker build --target poppler_builder \
  --iidfile /tmp/folio-r115-poppler-builder.iid \
  -f apps/inspector/Dockerfile.poppler-experiment .

# 2. Fuentes R1.11 y los siete parches Debian R1.12, todos SHA-pinned:
python3 apps/inspector/poppler_isolated_sanitizer.py \
  --source-directory /ruta/artefactos-fuente-debian \
  --fix-directory /ruta/siete-parches-debian \
  --builder-image-id "$(cat /tmp/folio-r115-poppler-builder.iid)"

# 3. Unitarias y contrato de integración:
python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'
sh scripts/ci.sh

# 4. Gate independiente, exit 2 esperado:
bash apps/inspector/audit_image.sh --experiment --advisories
```

El JSON final puede afirmar `research_binary_compiled=true`, `pdfinfo_sanitized_link_verified=true`, `pdfinfo_leak_probe_passed=true` y `ubsan_vptr_disabled_for=["pdfinfo"]`. **Nunca** afirma `cve_fixes_verified=true`, `source_binary_equivalence_to_runtime_verified=true` ni `release_authorized=true`.

## Riesgos y siguiente incremento

- No se han construido ni ejecutado **reproductores adversarios específicos por CVE**; la compatibilidad del corpus sintético normal no demuestra protección ante sus mecanismos de explotación.
- La exención de `vptr` en `pdfinfo` deja una clase de errores de uso de tipos sin instrumentar en ese ejecutable. Revisar alternativas de visibilidad/ABI y alcance de riesgo antes de cualquier uso fuera de investigación.
- La detección de fugas es parcial: faltan `pdftotext`, `pdftoppm` y el ciclo real `inspect_pdf`.
- Persisten los riesgos aritméticos de alineación TrueType, `SplashClip::yMaxAA` y equivalencia JBIG2 `reset()`/`rewind()`; además de CVE Poppler sin prototipo, Expat, ClamAV y demás hallazgos del runtime.

Según [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md), el merge puede incluir **solo verificadores, pruebas y documentación de investigación** después de CI. No publicar OCI, desplegar en Cloudflare/Preview/producción, ejecutar migraciones D1 remotas, emitir VEX ni procesar documentos institucionales.

**Conclusión:** R1.15 resuelve el problema de **enlace del ejecutable instrumentado `pdfinfo` en el sandbox de investigación**, no un CVE del inspector ni su admisión para operación.
