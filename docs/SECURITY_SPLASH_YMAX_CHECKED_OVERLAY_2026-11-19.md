# R1.19 · Guardia aritmética adicional para SplashClip::yMaxAA (INVESTIGACIÓN)

**Corte:** 2026-11-19, America/Lima. **Estado:** investigación de fuente exclusivamente, sin CVE corregidos, sin binario de parser completo, sin release.

## Contexto y causa raíz

R1.17 demostró sobre el método **real** `SplashClip::clipToPath`, compilado desde la fuente original Debian Poppler `25.03.0-5+deb13u4` y la fuente con cinco parches de investigación R1.13, que:

- `yMinAA = yMinI * splashAASize` producía overflow UBSan en la fuente original, pero el prototipo R1.13 incorporó `checkedMultiply` y rechazó la entrada.
- `yMaxAA = (yMaxI + 1) * splashAASize - 1` **continuaba con overflow UBSan en ambas versiones**, pues el prototipo no protegía la suma, multiplicación ni resta.

El overflow restante estaba en el **mismo método C++** y no quedó solucionado por el backport parcial. La ruta aún **no se ha reproducido a través del parser PDF**, y no se dispone de validación integral de CVE.

## Experimento ejecutado

Se añadió el overlay independiente, **no aprobado para runtime**:
`apps/inspector/research_patches/SplashClip-ymax-checked-research-overlay.patch`.

Reemplaza solo la línea problemática del fichero `splash/SplashClip.cc` por una secuencia de tres operaciones con comprobación de overflow y retorno `splashErrGeneric`:

```cpp
int yMaxIPlusOne, yMaxAAPadded;
if (unlikely(checkedAdd(yMaxI, 1, &yMaxIPlusOne)
             || checkedMultiply(yMaxIPlusOne, splashAASize, &yMaxAAPadded)
             || checkedSubtraction(yMaxAAPadded, 1, &yMaxAA))) {
    return splashErrGeneric;
}
```

**Aislamiento:** se preservan **sin cambios** las tres adaptaciones y dos fixes directos de R1.13 con hashes fijados. El nuevo overlay se aplica a una **tercera copia temporal** *solo después* de verificar la fuente Debian y los cinco cambios. No se integra en `Dockerfile.poppler-experiment`, no altera el CMake de producción, no construye ni sustituye imágenes operativas.

La prueba utiliza `poppler_splash_ymax_probe.py`, que:
1. Vuelve a comprobar **tres archivos fuente Debian**, siete parches oficiales y tres prototipos R1.13 con la atestación existente `inspect_semantic_prototypes`.
2. Valida SHA-256, tamaño y ruta única del overlay; genera manifests de fuente base, cinco prototipos y sexta modificación.
3. Ejecuta el contenedor Debian builder **por ID local inmutable**, `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`; directorio fuente temporal en tmpfs y condiciones limitadas de memoria, procesos y tiempo.
4. Compila **tres ejecutables ASan/UBSan independientes** con `SplashClip.cc`, `SplashXPath.cc`, `SplashXPathScanner.cc` y `SplashPath.cc` **reales**, sin aritmética simulada.
5. Verifica nueve salidas de procesos, incluidas los errores específicos UBSan de originales y ausencia de errores UBSan cuando la guardia actúa. Ante reportes falsificados, incompletos, señales, timeout o divergencias, falla con `exit 3`.

El builder configura CMake **solo para generar headers** y enlazar los métodos. **No** se compila `pdftoppm`, `pdftops` ni `libpoppler.so` completos con este sexto overlay; esa validación permanece pendiente.

### Identidad criptográfica de la sexta modificación

| Archivo | SHA-256 |
|---|---|
| SplashClip tras los cinco prototipos R1.13 | `011866818f3494d808ed988eb13c61c312ba872b47551f8ed80d3cac44c9c77c` |
| Overlay experimental R1.19 | `fc2983047d1f87e072760a5fca4f2e7130829b6272f37fa3488b40d318374720` |
| SplashClip tras los cinco prototipos y overlay R1.19 | `6512113e7233bfdd18d0c910a8f565b4f88adbfe172db5002bf0ca4e9477bdf4` |

Las restantes cinco rutas fuente relevantes de R1.13 conservan sus digests previos y se verifican dentro del contenedor.

## Resultados ejecutados en fuente real (ASan/UBSan)

| Condición | Debian original | Cinco prototipos | Cinco prototipos + overlay |
|---|---|---|---|
| Triángulo normal con AA | `exit 0`, aceptado | `exit 0`, aceptado | `exit 0`, aceptado |
| `yMinI=536870919`, multiplicación `*4` | `exit 1`, **signed integer overflow** | `exit 0`, rechazo controlado | `exit 0`, rechazo controlado |
| `yMaxI+1=536870919`, multiplicación `*4` | `exit 1`, **signed integer overflow** | `exit 1`, **signed integer overflow** | `exit 0`, **rechazo controlado sin overflow** |

**Ejecución completa:** `status=research_source_only_splash_ymax_overlay`, **`exit 0`**. El verificador reportó `sixth_overlay_ymax_rejected_without_ub=true`, `existing_ymin_guard_retained=true` y `normal_path_retained=true`.

Este resultado demuestra un diferencial aritmético del método **para los tres inputs concretos**. No prueba que todos los caminos de `SplashClip` sean seguros, que un PDF real llegue al mismo flujo, que los parches coincidan con un binario de runtime ni que `CVE-2026-102621` esté corregido. El overlay sigue siendo un prototipo independiente que requiere revisión.

## Reproducibilidad y CI

```sh
# Fuente Debian oficial y siete parches oficiales, ya SHA-pinned por R1.11/R1.12.
# ID de builder local: no publicar ni retaggear imágenes.
python3 apps/inspector/poppler_splash_ymax_probe.py \
  --source-directory /ruta/fuentes-debian \
  --fix-directory /ruta/parches-oficiales-debian \
  --builder-image-id "$(cat /tmp/folio-r119-poppler-builder.iid)"

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_splash_ymax_probe.py' -v
sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

La compilación y verificación real de los nueve ensayos pasó. También se incorporaron **nueve tests unitarios nuevos** que rechazan pruebas inexistentes, simulaciones exitosas sin artefactos, valores inventados, avisos de sanitizador sobre guardias y cambios en hashes. El shell pasó `bash -n`.

### Evidencia de pruebas de integración locales

- `python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'`:
  **181/181 aprobadas**, incluidas las nueve unitarias R1.19.
- `sh scripts/ci.sh` con `FOLIO_E2E_PORT=42973`: **exit 0**, 181/181 Python,
  Vitest/workerd, typecheck, builds Workers `--dry-run`, Chromium E2E y
  accesibilidad, migraciones D1 **solo locales** hasta `0027`; no implica
  autorización de seguridad ni despliegue.
- `bash -n apps/inspector/research_patches/run_splash_ymax_overlay.sh`:
  **exit 0**.
- `bash apps/inspector/verify_raster_guard.sh`: **exit 0, 8/8** con
  los motores e imagen existentes. La imagen **no** incluye el overlay.
- `bash apps/inspector/audit_image.sh --experiment --advisories`:
  **exit 2 BLOQUEADO**, 0 CRITICAL / 70 HIGH / 19 UNKNOWN;
  dos componentes nativos sin cobertura CVE completa.

## Gate y trabajo pendiente

- **NO CVE cerrado:** `cve_remediation_claimed=false`, `all_selected_cve_fixes_verified=false`, `release_authorized=false`, `source_binary_equivalence_to_runtime_verified=false`.
- **Límite del experimento:** `full_poppler_binary_compilation_verified=false`, `pdf_parser_regression_verified=false`.
- **Seguridad residual:** revisar `SplashClip` completo (conversión de coordenadas, crecimiento de flags, otros lugares que multiplican `splashAASize`), análisis de efectos al rechazar el recorte y compilación de biblioteca completa con la sexta modificación. Diseñar tests de PDF adversario alcanzables sin riesgos de memoria/DoS para el runner.
- **Vulnerabilidades no abordadas:** JBIG2 bitmap nulo, alineación de longitudes TrueType, CVE Poppler sin backport y Trivy/Expat/ClamAV.
- **Gate de auditoría del inspector:** permanece **BLOQUEADO**, `exit 2` (0 CRITICAL, 70 HIGH, 19 UNKNOWN, dos componentes fuente sin cobertura completa), sin VEX ni levantamiento del bloqueo.

**Gobierno:** [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md) permite integrar únicamente evidencia, tests y herramientas de investigación tras CI. No se permite modificar imágenes de runtime, retaggear ni publicar OCI, desplegar Cloudflare/Preview/producción, migrar D1 remoto ni procesar PDFs institucionales.

**Conclusión:** el overlay elimina **para los inputs probados del método** el overflow residual de `yMaxAA`, pero permanece una investigación de fuente sin autorización de despliegue.
