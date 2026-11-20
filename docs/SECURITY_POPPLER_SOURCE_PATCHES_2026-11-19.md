# R1.11 · Procedencia verificable de Poppler y análisis de los 10 avisos seleccionados

**Corte de investigación:** 2026-11-19 (America/Lima). **Estado:** revisión de fuente Debian y procedencia parcial; **sin CVE resueltos, sin VEX y sin autorización de ejecución remota**.

## Conclusión de seguridad

La imagen local experimental fue compilada desde **Poppler Debian `25.03.0-5+deb13u4`**. La consulta individual de los diez identificadores registrados en R1.9 contra el [Debian Security Tracker](https://security-tracker.debian.org/tracker/source-package/poppler) arroja **`vulnerable` en la fuente Trixie `25.03.0-5+deb13u4` en los diez casos**. Esta clasificación es del **paquete fuente**: no demuestra por sí sola explotabilidad de cada ruta en el ELF local concreto, ni permite ignorar los avisos. Se conserva `source_binary_applicability=unassessed` y no se modifica la decisión de bloqueo.

La versión `25.03.0-5+deb13u4` **sí** incorpora un parche de `SplashOutputDev::tilingPatternFill`, pero su cabecera Debian dice **`CVE-2026-10118`**, no `CVE-2026-93653`. El primero protege multiplicaciones de tamaño de superficie mediante `checkedMultiply`; el segundo sigue descrito por Debian como un bucle excesivo por conteos de repetición de patrón. Compartir el método no acredita corregir ambas fallas.

### Matriz fuente auditada

| CVE | Función descrita / archivo fuente observado en 25.03.0 | Estado Debian Trixie |
| --- | --- | --- |
| `CVE-2026-107705` | `revision6Hash` — `poppler/Decrypt.cc` | Vulnerable |
| `CVE-2026-102621` | `SplashClip::clipToPath` — `splash/SplashClip.cc` | Vulnerable |
| `CVE-2026-102620` | `FoFiTrueType::cvtSfnts` — `fofi/FoFiTrueType.cc` | Vulnerable |
| `CVE-2026-93653` | `SplashOutputDev::tilingPatternFill` — `poppler/SplashOutputDev.cc` | Vulnerable |
| `CVE-2026-93314` | `FoFiTrueType::mapCodeToGID` — `fofi/FoFiTrueType.cc` | Vulnerable |
| `CVE-2026-93313` | `JBIG2Stream::readCodeTableSeg` — `poppler/JBIG2Stream.cc` | Vulnerable |
| `CVE-2026-93312` | `JBIG2Stream::rewind` — `poppler/JBIG2Stream.cc` | Vulnerable |
| `CVE-2026-93311` | `SampledFunction::SampledFunction` — `poppler/Function.cc` | Vulnerable |
| `CVE-2019-9545` | `JBIG2Stream::readTextRegion` — `poppler/JBIG2Stream.cc` | Vulnerable, prioridad `no-dsa/ignored` de Debian |
| `CVE-2019-9543` | `JBIG2Stream::readGenericBitmap` — `poppler/JBIG2Stream.cc` | Vulnerable, prioridad `no-dsa/ignored` de Debian |

Referencias individuales: [107705](https://security-tracker.debian.org/tracker/CVE-2026-107705), [102621](https://security-tracker.debian.org/tracker/CVE-2026-102621), [102620](https://security-tracker.debian.org/tracker/CVE-2026-102620), [93653](https://security-tracker.debian.org/tracker/CVE-2026-93653), [93314](https://security-tracker.debian.org/tracker/CVE-2026-93314), [93313](https://security-tracker.debian.org/tracker/CVE-2026-93313), [93312](https://security-tracker.debian.org/tracker/CVE-2026-93312), [93311](https://security-tracker.debian.org/tracker/CVE-2026-93311), [9545](https://security-tracker.debian.org/tracker/CVE-2019-9545), [9543](https://security-tracker.debian.org/tracker/CVE-2019-9543).

**Matiz importante:** el símbolo textual `JBIG2Stream::rewind` no aparece en `poppler/JBIG2Stream.cc` de esta fuente exacta, a pesar del estado `vulnerable` del tracker para `CVE-2026-93312`. El nuevo informe expone `jbig2_rewind_symbol_observed=false` solo como observación verificable de fuente; no cierra el CVE ni sustituye una revisión de ABI, rutas equivalentes, semántica de versión o commits de reparación.

## Procedencia Debian fijada por contenido

Se verificaron directamente los tres artefactos oficiales de `https://deb.debian.org/debian/pool/main/p/poppler/`:

| Archivo del paquete `25.03.0-5+deb13u4` | Bytes | SHA-256 |
| --- | ---: | --- |
| `poppler_25.03.0.orig.tar.xz` | 1.954.516 | `97da4ff88517a6bbd729529f195f85c8d7a0c3bb4a3d57cb0c685cbb052fe837` |
| `poppler_25.03.0-5+deb13u4.debian.tar.xz` | 44.732 | `2605b5d7e6ce17a307d067048386deedfc41fdac6f75f81ad76050f517fc0de4` |
| `poppler_25.03.0-5+deb13u4.dsc` | 3.966 | `b895e1e28568a486523f93dd5a8707ecb16767c5f134a6e23510b0597114c628` |

El descriptor `.dsc` coincide en **versión, tamaños y SHA-256** de los otros dos archivos. `dpkg-source -x` procesó correctamente el descriptor y aplicó los **nueve parches** del archivo `debian/patches/series`, incluido `SplashOutputDev-Fix-integer-overflow-in-tilingPatter.patch`. Sobre el árbol reconstruido, se verificó la presencia de `checkedMultiply(surface_width, repeatX, &result_width)`.

**Límite de autenticidad:** `dpkg-source` notificó que el host de investigación **no tenía la clave pública del firmante del `.dsc`**, por lo que no pudo verificar independientemente su firma inline. Los tres SHA-256 fijados y la correspondencia con los hashes del descriptor demuestran **identidad exacta**; no deben confundirse con verificación GPG del descriptor. El Dockerfile experimental obtiene estos artefactos a través de `apt-get source` con repositorios Debian y metadatos APT firmados, y ahora exige que los tres archivos recibidos coincidan con esos hashes. La imagen local ya construida **no se reconstruyó** con esta nueva condición.

## Archivos afectados: huellas tras aplicar los parches

| Fuente | SHA-256 del archivo parcheado |
| --- | --- |
| `poppler/Decrypt.cc` | `2c345f73f0403590554e1f1bc81c6e725376e4851ee041cb9fbe53e79e46ca94` |
| `splash/SplashClip.cc` | `9449ee782a2d13e424d4b94eaca5e87f0ec59b310bf2e6c05366cc154eebf599` |
| `fofi/FoFiTrueType.cc` | `9e58abd2c38276b18a7f073b6d3154cae6ee1236fc076c7967f1a80aef139119` |
| `poppler/SplashOutputDev.cc` | `f551d09a1dce5dda5787cc66305714259a0ba24766a765cbbcd9af27cc0cd741` |
| `poppler/JBIG2Stream.cc` | `3dce697c3bb86440bab753e210cbab8b95264c44e951065695555ecc007575fe` |
| `poppler/Function.cc` | `de8be371640a95e0eda20b8517262f9c4f4965c22c852c3ccb5fe5744c298a46` |

Estos son hashes de **archivos fuente con quilt aplicado**, no hashes de los archivos compilados, símbolos enlazados ni reproducciones de vulnerabilidades.

## Cambios y contrato de comprobación

- `apps/inspector/poppler_source_patch_probe.py`: verificador **offline y sin entradas de documentos** que exige los tres artefactos, hashes fijados, descriptor `.dsc` válido, los nueve parches exactos y el identificador del parche `CVE-2026-10118`. Usa `dpkg-source -x` en temporal privado, comprueba su estado de salida, verifica seis archivos/símbolos acotados y produce sus hashes. El CLI entrega **exit 3** ante metadatos, hashes, símbolos o aplicación de parches incompletos.
- `apps/inspector/Dockerfile.poppler-experiment`: conserva el flujo de `apt-get source` con Debian Trixie y agrega `sha256sum --check` de los **tres artefactos exactos**. Un cambio silencioso de la revisión fuente aborta la futura construcción.
- `apps/inspector/native_advisory_ledger.py`: cada CVE seleccionado de Poppler expone el archivo de código asociado y `debian_trixie_source_status=vulnerable` para la fotografía del 19-11-2026, **manteniendo** `source_binary_applicability=unassessed`, `individual_review_required`, `declares_not_affected=false` y `release_authorized=false`. Nunca se atribuye un CVE como corregido al ELF.
- Pruebas unitarias: versión incorrecta, digest alterado, patch series incompleta, marcador falso, extracción fallida, símbolos omitidos e informes positivos con flags de liberación siempre falsos.

### Reproducción offline

```sh
# Descargar los tres artefactos oficiales a un directorio de investigación
# y después comprobar sin permitir conexiones de red al propio probe:
python3 apps/inspector/poppler_source_patch_probe.py --directory /ruta/a/artefactos-poppler

python3 -m unittest discover -s apps/inspector/tests -p 'test_poppler_source_patch_probe.py' -v
sh scripts/ci.sh

# Comprobación separada; exit 2 es esperado mientras haya CVE pendientes:
bash apps/inspector/audit_image.sh --experiment --advisories
```

En la ejecución real de investigación, el probe devolvió **exit 0**, `quilt_application_verified=true`, `patch_count=9` y hashes de seis archivos; **`selected_cve_fixes_verified=false`, `binary_equivalence_verified=false`, `dsc_signature_verified_by_probe=false`, `complete_source_advisory_coverage=false` y `release_authorized=false`**. La comprobación de fuentes no debe sustituir la auditoría Trivy ni la admisión de runtime.

## Riesgos y próximo trabajo

El hecho de que `CVE-2026-93653` continúe abierto **pese** a un parche de multiplicación en la misma función hace especialmente importante comprobar la causa raíz, no solo buscar marcadores. Poppler sigue analizando PDFs no cifrados con las rutas Splash/JBIG2/fuentes, y sus 10 avisos requieren tratamiento individual con backports mantenidos y probados o una actualización de versión compatible, sin aceptar versiones `sid` en producción. Permanecen abiertos Expat, ClamAV, los demás HIGH/UNKNOWN, la equivalencia binaria reproducible y la construcción de una imagen final limpia.

La [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md) permite integrar esta evidencia en `main` con CI, **pero no liberar el inspector**, procesar PDFs institucionales, emitir VEX sin aprobación, modificar recursos Cloudflare, migrar D1 remotos ni publicar imágenes.
