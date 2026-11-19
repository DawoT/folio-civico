# R1.13 · Prototipos semánticos aislados de Poppler Debian Trixie

**Fecha de investigación:** 2026-11-19 (America/Lima).  
**Estado:** cinco modificaciones de fuente **solo para investigación**, sin build de runtime verificado, sin CVE resueltos y sin autorización de despliegue.

## Objetivo y procedencia

El [incremento R1.12](SECURITY_POPPLER_BACKPORT_FEASIBILITY_2026-11-19.md) demostró que dos parches Debian `26.07.0-4` aplican textualmente a la fuente `25.03.0-5+deb13u4`, mientras que cinco requieren adaptación. R1.13 profundiza **los dos directos** y prepara **tres prototipos** para Splash/JBIG2, preservando una separación estricta entre compatibilidad, semántica y cierre de vulnerabilidades.

**Fuente:** los tres artefactos Debian `25.03.0-5+deb13u4` fijados por SHA-256 en R1.11. **Parches upstream/debian de referencia:** los siete ficheros `CVE-....patch` con SHA-256 fijado en R1.12 y publicados en [Debian Sources `26.07.0-4`](https://sources.debian.org/patches/poppler/26.07.0-4/). **Prototipos de adaptación Trixie:** tres diffs versionados bajo `apps/inspector/research_patches/`, cada uno con digest SHA-256 fijado y destino de archivo único.

Todos los cambios se aplican con `patch --batch --forward --fuzz=0 -p1` sobre una extracción **temporal** de los archivos fuente oficiales. El Dockerfile, las imágenes OCI, el gate CVE, las etiquetas y el código operativo del inspector no cambian.

## Análisis de los dos parches directos

| CVE | Evidencia de fuente | Límite de la demostración |
| --- | --- | --- |
| `CVE-2026-93311` | `SampledFunction` valida `1 <= BitsPerSample <= 32`; el parche reemplaza `1 << sampleBits` por `1ULL << sampleBits` con conversión a `unsigned int`. Así evita desplazar el tipo `int` por 32 bits. | Se comprobó numéricamente con UBSan para 1..32; **no** se ejecutó un PDF que reproduzca la falla ni se demostró el binario Poppler corregido. |
| `CVE-2026-102620` | `FoFiTrueType::cvtSfnts` sustituye la suma de longitudes de glifos por `checkedAdd(length, locaTable[j].len, &length)`, detecta overflow y marca `ok=false`. | Persisten adiciones de alineación `length += 4 - (length & 3)` sin guardia local y rutas posteriores que no comprueban ese `ok` inmediatamente. **Se requiere revisión de flujo, tipos y límites**; un parche que aplica no equivale a garantía de seguridad completa. |

## Tres adaptaciones de fuente no aprobadas

| CVE | Motivo por el que el parche Debian posterior no aplica | Adaptación de investigación |
| --- | --- | --- |
| `CVE-2026-102621` | `SplashClip::clipToPath` tiene firma antigua y usa códigos de error `splashErrGeneric` en vez de `SplashError::Generic`. | Importa `GooCheckedOps`/`GooLikely` y comprueba `checkedMultiply(yMinI, splashAASize, &yMinAA)`; devuelve `splashErrGeneric` ante overflow. **Sigue pendiente** `yMaxAA = (yMaxI + 1) * splashAASize - 1`. |
| `CVE-2026-93312` | La fuente 25.03.0 ejecuta `JBIG2Stream::reset()`, no contiene `JBIG2Stream::rewind()`. | Añade `pageBitmap->isOk()` antes de obtener el puntero de datos de la página, evitando la ruta directa con bitmap de datos nulos. **Falta** demostrar equivalencia semántica de `reset()` y cobertura de todas las rutas nulas. |
| `CVE-2026-93313` | `readCodeTableSeg` devuelve `void` y posee una firma diferente de la versión posterior. | Usa `checkedSubtraction(lowVal, 1, &lowValMinusOne)`, libera la tabla Huffman y hace `return` si hay underflow; preserva la firma `void`. **Falta** revisar el resto de desplazamientos y tamaños de la función. |

**No incluidos como backports aprobados:** `CVE-2026-93314` y `CVE-2026-107705`, cuyos parches todavía requieren adaptación; `CVE-2026-93653`, `CVE-2019-9545` y `CVE-2019-9543` tampoco quedan resueltos. Expat, ClamAV y los demás hallazgos del runtime mantienen sus propios controles independientes.

### Huellas exactas de los tres prototipos

| Archivo | SHA-256 |
| --- | --- |
| `CVE-2026-102621-trixie-prototype.patch` | `f86222d7269e66bb1a333722bf334c778f2e76eb2ef74a5594f4e34390c60aec` |
| `CVE-2026-93312-trixie-prototype.patch` | `d7dbe7b47a048406f9598497602445db918721ace181f8bf7f4f80a5a4440d04` |
| `CVE-2026-93313-trixie-prototype.patch` | `09b19f6115253993a51ed4695d5b643c8d341892b484ee49018f7e70b977fb66` |

## Comprobaciones reproducibles

`apps/inspector/poppler_semantic_research.py` exige los diez artefactos oficiales de R1.12, verifica los tres prototipos y aplica exactamente **dos parches Debian directos + tres prototipos** en un árbol efímero sin tocar el repositorio. Verifica los SHA-256 de los seis archivos fuente antes/después de aplicar, las cuatro rutas modificadas y los marcadores acotados de código, **incluyendo la persistencia de riesgos sin resolver**. Fallos de hash, archivos, rutas, aplicación, mutación colateral o semántica esperada devuelven **exit 3**.

```sh
python3 apps/inspector/poppler_semantic_research.py \
  --source-directory /ruta/fuentes-poppler-r111 \
  --fix-directory /ruta/siete-parches-debian-r112

python3 -m unittest discover -s apps/inspector/tests \
  -p 'test_poppler_semantic_research.py' -v

# Una vez extraído el código fuente exacto de R1.11:
g++ -std=c++20 -O1 -g -fsanitize=undefined -fno-sanitize-recover=all \
  -I /ruta/fuente-poppler-extraida \
  apps/inspector/research_patches/check_numeric_boundaries.cc -o /tmp/folio-r113-ubsan
/tmp/folio-r113-ubsan

sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

El reporte JSON devuelve siempre `status=research_source_prototypes_only`, `all_selected_cve_fixes_verified=false`, `cve_remediation_claimed=false`, `runtime_compilation_verified=false`, `binary_equivalence_verified=false`, `backports_approved=false`, `complete_source_advisory_coverage=false` y `release_authorized=false`.

**Evidencia numérica separada:** se compiló y ejecutó un micro-harness C++ con **UBSan** sobre el encabezado real `goo/GooCheckedOps.h` y el desplazamiento propuesto `1ULL << sampleBits`. Pasaron las 32 anchuras y los límites de sumas, restas y multiplicaciones sin errores de sanitizer. **No prueba** la seguridad, pruebas de regresión PDF ni compilación del código completo.

**Limitación de compilación:** un intento de configurar la biblioteca Poppler completa en un directorio temporal con CMake falló **antes de compilar**: el host de investigación no tenía `FREETYPE_LIBRARY`/`FREETYPE_INCLUDE_DIRS` (requisito `>=2.11`). No se instaló nada ni se alteraron imágenes. Los cinco prototipos **no** están validados por compilación del proyecto, y esta ausencia de evidencia obliga a mantener su estado experimental.

## CI y gates reproducidos

- Probe con **diez artefactos SHA-pinned** y los tres prototipos versionados: **exit 0**, exactamente cinco cambios en fuente temporal; los nueve marcadores de fuente previstos presentes, incluidos tres riesgos residuales explícitos. `release_authorized=false` y `runtime_compilation_verified=false`.
- Pruebas Python del inspector: **132/132 aprobadas**, incluidas **7 nuevas** para hashes, objetivos de archivos, mutaciones ajenas, errores de herramientas, ausencias y marcas semánticas.
- `sh scripts/ci.sh`: **exit 0**, Vitest/workerd, typecheck, builds dry-run, Chromium E2E/accesibilidad y migraciones D1 **locales** hasta `0022`.
- `bash apps/inspector/verify_raster_guard.sh`: **exit 0, 8/8** controles de motores de la imagen experimental existente, con el código actual en memoria (sin rebuild): OCR, PDF, cifrado antes de Poppler, adjuntos, AV y aislamiento de entorno. Es regresión del inspector **sin** los prototipos R1.13 dentro del ELF.
- `bash apps/inspector/audit_image.sh --experiment --advisories`: **exit 2**, imagen experimental **bloqueada**: 0 CRITICAL / **70 HIGH / 19 UNKNOWN**, 2 motores fuente todavía sin evaluación completa.

## Gobierno y próximos criterios

- Completar un entorno builder aislado con dependencias de desarrollo y compilar/ejecutar tests reales sobre los cinco cambios, incluyendo regresiones PDF adversarias sintéticas y sanitizadores. Revisar específicamente `length`/alineación y `yMaxAA`, para no crear un falso cierre parcial.
- Investigar equivalencia de rutas JBIG2, comportamiento de manejo de errores y los dos avisos para los que todavía no hay prototipo. Aislar un caso reproducible por CVE antes de proponer correcciones a runtime.
- Mantener el gate Trivy **bloqueado** hasta que no existan vulnerabilidades pendientes y se demuestre procedencia binaria, SBOM, pruebas del corpus y revisión independiente. Conforme a [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md), **no** publicar OCI, activar Cloudflare/Preview/producción, migrar D1 remoto, emitir VEX ni tratar documentos institucionales.

**Conclusión:** R1.13 aumenta la evidencia de semántica y prepara tres prototipos **no aprobados**; no certifica CVE corregidos ni desbloquea el inspector.
