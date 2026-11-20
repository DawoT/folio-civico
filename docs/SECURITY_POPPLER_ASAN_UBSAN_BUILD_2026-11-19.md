# R1.14 · Compilación aislada ASan/UBSan y regresión PDF sintética Poppler

**Fecha:** 2026-11-19 (America/Lima). **Estado:** compilación de investigación y pruebas controladas; **no** binarios de release ni CVE cerrados. El incremento NO modifica `Dockerfile.poppler-experiment`, etiquetas `validation`/`poppler-experiment`, runtime, Cloudflare ni datos de usuario.

## Objetivo

R1.13 dejó cinco cambios sobre la fuente Poppler Debian `25.03.0-5+deb13u4` (dos parches oficiales de Debian `26.07.0-4` y tres prototipos de compatibilidad Trixie) sin una compilación completa, por ausencia de FreeType en el host. R1.14 intenta compilar y ejecutar **únicamente código de investigación** en un builder efímero con `-fsanitize=address,undefined`, ensayar un corpus sintético e investigar regresiones de renderizado y extracción.

**Límites fundamentales:** superar pruebas de compilación y un corpus sintético **no acredita reparar** `CVE-2026-102620`, `CVE-2026-102621`, `CVE-2026-93311`, `CVE-2026-93312` ni `CVE-2026-93313`. No existe corpus explotable específico por CVE, verificación independiente de la adaptación `reset`/`rewind` ni equivalencia reproducible con ELF de imagen operativa. Además, permanecen CVE Poppler, Expat, ClamAV y otras dependencias pendientes.

## Builder de procedencia fija

Se reutilizó únicamente el target `poppler_builder` del Dockerfile experimental (sin construir ni sustituir el runtime final):

```sh
docker build --target poppler_builder \
  --iidfile /tmp/folio-r114-poppler-builder.iid \
  -f apps/inspector/Dockerfile.poppler-experiment .
```

El Dockerfile ya exige tres archivos fuente Debian por SHA-256 (el `.dsc`, el `.orig.tar.xz` y el `.debian.tar.xz`) y aplica los nueve parches del paquete Trixie. El builder tiene FreeType y CMake/Ninja; se ejecutó por su **ID de imagen local por contenido**, no por etiqueta mutable. Esta etapa produce una imagen **solo local, sin etiqueta de runtime**; no hay OCI push, red de inspección ni modificación Cloudflare.

Antes de iniciar Docker, `apps/inspector/poppler_isolated_sanitizer.py` ejecuta de nuevo la verificación R1.13 de los 10 artefactos SHA-pinned y prepara dos manifiestos de hashes de los **seis archivos de código fuente**: antes y después de aplicar los cinco parches. El script en `research_patches/build_sanitized_poppler.sh` los comprueba **dentro del contenedor** con `sha256sum --check`. Si un fichero de código cambia sin autorización o un parche aplica con fuzz/rechazos, la investigación falla.

**Aislamiento del contenedor:** `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, límites de CPU, memoria y procesos; bind mounts de origen/fixes/prototipos/fixtures en solo lectura; `/work` y `/tmp` en tmpfs; exportación de resultados **solo sintéticos** a un directorio efímero. No se procesan PDFs institucionales. Ninguna imagen de release se actualiza ni ejecuta el código parcheado.

## Evidencia de compilación

**Primer intento (construcción completa de tres herramientas):** la biblioteca `libpoppler.so.147` y el ejecutable `pdftoppm` compilaron, pero el enlace instrumentado de `pdfinfo` falló por símbolo RTTI **`typeinfo for AnnotLink`** indefinido. Se conservó el fallo, sin atribuírselo causalmente a uno de los cinco parches. La infraestructura de investigación limita por ahora su target instrumentado a `pdftotext` y `pdftoppm`, que son los binarios necesarios para el corpus de renderizado/extracción. **`pdfinfo` instrumentado permanece no verificado.**

**Compilación y ensayo acotados:** se enlazaron `libpoppler.so.147`, `pdftotext` y `pdftoppm` con AddressSanitizer/UndefinedBehaviorSanitizer; `ldd` confirmó que `pdftotext` usa la biblioteca recompilada y `libasan.so`/`libubsan.so`. Para evitar falsos positivos de terceros y acotar este pase, `ASAN_OPTIONS` usa `detect_leaks=0`: **no** se evaluaron fugas de memoria. Los errores de ASan/UBSan abortan o invalidan la ejecución.

## Corpus sintético y comparación con el builder original

Los PDF se generan en memoria a partir de fixtures originales del repositorio: ninguno proviene de expedientes reales. Se ejecutaron `pdftotext` y `pdftoppm` de la fuente parcheada, y se compararon con las utilidades **no modificadas** instaladas en el mismo builder Debian.

| Fixture | Qué evalúa | Resultado observado en el primer pase de diagnóstico |
| --- | --- | --- |
| Texto nativo con Helvetica | Texto y fidelidad de raster; Fontconfig presente | 657 × 850, 2.130 píxeles de tinta |
| Imagen escaneada sin texto | Render de mapa de bits; sin capa de texto | 657 × 850, 9.127 píxeles de tinta |
| Recorte vectorial triangular | Render rasterizado con recorte Splash no rectangular | 657 × 850, 136 píxeles de tinta |
| Función muestreada `BitsPerSample=32` | Ejercicio sintético del código de sampled function | 657 × 850, 503.200 píxeles de tinta |
| PDF truncado deliberadamente | Rechazo sin crash ni informe ASan/UBSan | `pdftotext exit 1` |

Los cuatro rasters de este pase produjeron **identidad exacta de píxeles, 4/4**, con el Poppler original no instrumentado de la misma fuente Debian; texto nativo y ausencia de texto en scan, **2/2** salidas idénticas. La paridad mide fidelidad sintética y no prueba que una ruta CVE adversaria esté mitigada.

El ejecutor `poppler_isolated_sanitizer.py` valida de nuevo todas las salidas (cabecera PGM, tamaño, píxeles oscuros, texto, ausencia de capa OCR), rechaza enlaces simbólicos/salidas anómalas y **falla cerrado si cambia un solo píxel** respecto del builder sin parches. Se separan claramente `research_binary_compiled` y los flags **siempre falsos** `cve_fixes_verified`, `source_binary_equivalence_to_runtime_verified` y `release_authorized`.

### Verificación limpia definitiva R1.14

La ejecución completa, nueva e independiente del script
`poppler_isolated_sanitizer.py` devolvió **exit 0** y
`status=research_sanitizer_build_completed`, incluyendo:

- Builder local por contenido `sha256:2f57f656317dc0b6106437640c8b91ee1a9452fe5c019b2e53dbd6a007272049`. Esta identidad depende del build local; el script admite únicamente un ID `sha256:` verificado por Docker con `--pull never`, no un nombre de tag.
- Construcción ASan/UBSan **desde cero y sin red** de `libpoppler.so.147`, `pdftotext` y `pdftoppm`, tras aplicación estricta de los cinco parches sobre fuente temporal. Los hashes de los seis archivos fuente coinciden con la atestación offline de R1.13.
- **4/4 imágenes idénticas píxel a píxel** respecto del Poppler original en el builder; **2/2** salidas de texto idénticas; comprobaciones de tinta en todas las imágenes y rechazo `exit 1` de PDF truncado.
- Cero informes de ASan/UBSan en este corpus acotado; `detect_leaks=0` mantiene explícita la falta de detección de fugas.
- `research_binary_compiled=true`, **`pdfinfo_sanitized_link_verified=false`**, `cve_fixes_verified=false`, `source_binary_equivalence_to_runtime_verified=false`, `image_release_authorized=false` y `release_authorized=false`.

Identidades SHA-256 de los píxeles PGM verificados:

| Fixture | SHA-256 de píxeles (igual baseline y experimental) |
| --- | --- |
| Nativo | `c5734e5fe9e3ea2e2f67adb8e0c540ce0c49a732cfea8487a677b3a1baca2987` |
| Scan | `88b4877c2a35a3c49bbbc79e29f462140ad33b09d2ec6a122c59570665adf3cd` |
| Recorte vectorial | `5ef1fd6164dd963f2fa5b0d3330275f890da5d908bf0233df4df9d054624cf57` |
| SampledFunction 32 bits | `519f33017da7da6d93a9c5c3c3328a7844f60b51cb23c6556b50c56e7c8c4594` |

### Reproducción local controlada

```sh
# Ejecutar desde la raíz del repositorio, con Docker local autorizado.
docker build --target poppler_builder \
  --iidfile /tmp/folio-r114-poppler-builder.iid \
  -f apps/inspector/Dockerfile.poppler-experiment .

python3 apps/inspector/poppler_isolated_sanitizer.py \
  --builder-image-id "$(cat /tmp/folio-r114-poppler-builder.iid)" \
  --source-directory /ruta/tres-archivos-fuente-poppler-r111 \
  --fix-directory /ruta/siete-parches-debian-r112

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_isolated_sanitizer.py' -v
sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

**Interpretación de salidas:** el CLI solo devuelve `exit 0` si hubo compilación instrumentada, salidas sintéticas verificadas y paridad exacta con el baseline. Esto representa **evidencia experimental, no permiso de operación**. Un error devuelve `exit 3`, no un éxito simulado. La auditoría independiente del inspector debe seguir devolviendo `exit 2` mientras permanezcan vulnerabilidades, incertidumbre de componentes fuente o controles de release pendientes.

## Controles de integración y release

- `python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'`: **141/141 pruebas aprobadas**, con 9 pruebas nuevas de R1.14 que validan autenticidad de entradas, aislamiento Docker, sanitizadores no simulados, límites de salida y bloqueo ante divergencias de texto o píxeles.
- `bash -n` de los dos scripts de investigación: **2/2 aprobados**.
- `sh scripts/ci.sh`: **exit 0** en la base de trabajo de R1.14, incluidos TypeScript, Workers, builds/dry-run, Chromium y migraciones D1 estrictamente **locales**. Este CI no evalúa el gate pesado Trivy.
- `bash apps/inspector/audit_image.sh --experiment --advisories`: **exit 2 (bloqueado)**: 0 CRITICAL, **70 HIGH, 19 UNKNOWN**, dos componentes fuente sin revisión completa. **No se desactiva ningún gate ni se emite VEX.**

## Pendientes críticos

1. Resolver/revisar el enlace de `pdfinfo` con sanitizadores y ampliar el build a herramientas restantes antes de afirmar compilación instrumental integral.
2. Corpus JBIG2, TrueType y Splash adversario específico para cada CVE, con resultados negativos demostrables, ASan/UBSan y tests de regresión del flujo real `inspect_pdf`. Los fixtures actuales no sustituyen ese corpus.
3. Evaluar las operaciones aritméticas todavía sin guardia de `FoFiTrueType` (alineación), `SplashClip` (`yMaxAA`) y equivalencia semántica `JBIG2Stream::reset`/`rewind`.
4. Resolver los CVE y HIGH/UNKNOWN restantes, cerrar cobertura source→ELF, obtener SBOM/gate estricto y autorización independiente de runtime. Conforme a [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md), solo pueden integrarse **código de investigación, pruebas y documentación**, nunca esta imagen como runtime.

**Conclusión:** el progreso de R1.14 evalúa una combinación concreta de cinco parches en una infraestructura aislada. La seguridad del inspector **sigue bloqueada** aunque la investigación genere binarios experimentales que compilen y reproduzcan los fixtures.
