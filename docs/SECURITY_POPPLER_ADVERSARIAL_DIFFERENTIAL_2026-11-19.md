# R1.16 · Comparación adversaria de fuente Poppler con ASan/UBSan

**Corte:** 2026-11-19 (America/Lima). **Alcance:** investigación defensiva sin release, sin CVE adjudicados, sin tratamiento de PDFs institucionales y sin cambios en imágenes de runtime.

## Pregunta y principio de comparación

R1.15 demostró que la fuente Debian Trixie `25.03.0-5+deb13u4` con cinco parches de investigación compila y conserva salidas de PDFs benignos. Eso **no** prueba que las correcciones eliminen operaciones vulnerables: el baseline de R1.15 usaba binarios Debian **no instrumentados**.

R1.16 construye **dos árboles independientes con los mismos parámetros CMake, compilador, bibliotecas, ASan y UBSan** dentro de un builder identificado por `sha256:` y sin red:

- **`original`:** `dpkg-source` de Debian con los nueve parches quilt oficiales de Trixie, sin los cinco parches R1.13.
- **`patched`:** copia separada del mismo código fuente, con exactamente dos parches directos oficiales `26.07.0-4` y tres prototipos R1.13. Los SHA-256 de los seis archivos fuente seleccionados son verificados **antes y después** del cambio.

Ambos ejecutan `pdftoppm` bajo `-fsanitize=address,undefined -fno-sanitize-recover=all` sobre **seis PDFs sintéticos** pequeños, sin entradas externas. La ejecución está limitada a **8 segundos por caso**, memoria, CPU y procesos del contenedor; el contenedor emplea `--pull never --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`. Todas las rutas de entrada se verifican por SHA-256 y los archivos de salida se leen con límites estrictos.

El motor Docker Debian del builder **no contiene Python**. Un primer intento devolvió `exit 3` por ese error de orquestación, **sin acreditar diferencia de CVE**. La ruta corregida ejecuta solo Bash/coreutils y binarios instrumentados dentro del contenedor, y **clasifica los resultados fuera**, en Python sobre el host. El diagnóstico original se preservó; el código operativo del inspector nunca se ejecutó con los prototipos.

## Comparación real del parser PDF, observación reproducida

| PDF sintético y ruta | Fuente original, ASan/UBSan | Fuente con prototipos, ASan/UBSan | Interpretación permitida |
| --- | --- | --- | --- |
| `sampled32` — `SampledFunction` de 32 bits | `exit 1`: **UBSan shift exponent 32** en `poppler/Function.cc:373` | `exit 0`, raster presente, sin señal UBSan | Evidencia de que el nuevo desplazamiento de 64 bits elimina **ese UB observado**; no CVE integralmente certificado |
| `jbig2_intmin` — segmento tabla Huffman con `lowVal=INT_MIN` | `exit 1`: **UBSan signed integer overflow** en `poppler/JBIG2Stream.cc:3962` | `exit 0`, raster presente, sin señal UBSan; **permanece aviso de sintaxis** por byte excedente | Evidencia de que `checkedSubtraction` evita **ese overflow observado**; no demuestra validez del PDF ni reparación completa de `CVE-2026-93313` |
| `jbig2_zero` — control de tabla Huffman sin overflow | `exit 0`, raster presente | `exit 0`, raster **idéntico** | Control de estabilidad sin int mínimo |
| `jbig2_large_page` — bitmap con dimensiones extremas | `exit 0`, diagnóstico de **anchura inválida** | `exit 0`, mismo diagnóstico y raster **idéntico** | **No alcanza ni reproduce** la aritmética de puntero nulo del caso `CVE-2026-93312` |
| `splash_triangle` — recorte vectorial triangular | `exit 0`, raster presente | `exit 0`, raster **idéntico** | Control normal del renderizador Splash |
| `splash_far` — recorte de path trasladado a Y=600 000 000 | `exit 0`, raster presente | `exit 0`, raster **idéntico** | **No reproduce** el overflow de `yMinAA`; la ventana de raster puede limitar la ruta |

Los cuatro casos control conservan **identidad exacta de raster** entre ambas compilaciones. Los dos casos con UBSan en el original no pueden tener paridad de raster porque el original aborta por instrumentación antes de terminar; **no** se les atribuye identidad de renderizado. El harness clasifica `runtime error:` y diagnósticos ASan antes de interpretar salidas `exit 0`.

### Identidad del corpus PDF

| Fixture | SHA-256 del PDF sintético |
| --- | --- |
| `sampled32` | `6d4b324176994bbfd19a883e55e09598ad22acd97a17f61444d9d32ea7f2f1cb` |
| `jbig2_intmin` | `16aa5d91d6fc389b958d5a1a1d97d8c8c568882f6dca02a0abaf217b96186efa` |
| `jbig2_zero` | `d4a8ef239fb67d98dce3794181ba23ea64247084d97da406916024d9e44a86ce` |
| `jbig2_large_page` | `8c2c18a0572372bb4f8475580331c8db04d3f5ec347bfde7a3c6e9bff69276a5` |
| `splash_triangle` | `f1a3b46b6801f1dfb1432a46b3ab54f56a6f40be617dffead450c0769eaf7575` |
| `splash_far` | `13bcd1fc4385cca9bb4ac72c30ff3e87dcbd9bb2cd868d5ff3a93b4ebcdb5e0f` |

### Verificación limpia definitiva

Tras corregir la dependencia accidental de Python dentro del builder, la ejecución
**completa desde fuentes originales**, sin reutilizar los objetos compilados
del pase de diagnóstico, devolvió `exit 0` y
`status=isolated_adversarial_source_comparison_only`.

- **`two_numeric_ub_differentials_observed=true`**: dos rutas reales
  de `pdftoppm` produjeron UBSan en la fuente original y ninguna señal
  en la variante con los cinco parches de investigación.
- **`four_control_rasters_identical=true`**: dos controles JBIG2 y dos
  controles Splash reprodujeron el mismo SHA-256 del raster en ambas
  compilaciones. Los dos casos con abortos UBSan no se cuentan como paridad.
- `original_sanitizer_findings` contiene exclusivamente
  `sampled32=ubsan_shift_exponent_32` y
  `jbig2_intmin=ubsan_signed_integer_overflow`.
  `prototype_sanitizer_findings={}` para el corpus observado.
- **`jbig2_intmin_syntax_warning_remains=true`** y
  `targeted_pdf_cases_without_exploit_reproduction=["splash_far","jbig2_large_page"]`.
  Estos estados **no** se ocultan ni reclasifican como corrección.
- Builder local de investigación por digest:
  `sha256:2f57f656317dc0b6106437640c8b91ee1a9452fe5c019b2e53dbd6a007272049`.
  No se generó ni etiquetó una imagen de runtime.

## Comprobación aritmética independiente: fuente, no parser

`apps/inspector/poppler_arithmetic_boundary_probe.py` valida SHA-256 exactos de cinco archivos de la extracción Debian (`FoFiTrueType.cc`, `Function.cc`, `JBIG2Stream.cc`, `SplashClip.cc`, `GooCheckedOps.h`) y compila con UBSan `research_patches/differential_arithmetic_boundaries.cc`. Este micro-harness **reproduce las expresiones**, pero **no invoca** las rutas de procesamiento del PDF. Los resultados diferenciados se deben interpretar como **pruebas de las operaciones aritméticas**, no como PoCs de las CVE.

| Operación aislada | Original | Control equivalente al parche |
| --- | --- | --- |
| `SampledFunction` desplazamiento 32 bits | Error UBSan | Sin error |
| JBIG2 `lowVal - 1`, con `INT_MIN` | Error UBSan | `checkedSubtraction` detecta overflow |
| Splash `yMinI * splashAASize` | Error UBSan | `checkedMultiply` detecta overflow |
| TrueType `length + locaTable[j].len` | Error UBSan | `checkedAdd` detecta overflow |
| **Residual:** Splash `yMaxAA=(yMaxI+1)*splashAASize-1` | Error UBSan | **Error UBSan permanece** |
| **Residual:** alineación TrueType `length += 4-(length & 3)` | Error UBSan | **Error UBSan permanece** |

El harness devuelve `exit 0` **solo** si los cuatro contrastes y las dos persistencias de overflow ocurren exactamente como se espera. El reporte mantiene `actual_pdf_parser_path_verified=false`, `cve_remediation_claimed=false` y `release_authorized=false`.

## Procedimiento offline reproducible

```sh
# Builder local de investigación R1.14/R1.15, no runtime:
docker build --target poppler_builder \
  --iidfile /tmp/folio-r116-builder.iid \
  -f apps/inspector/Dockerfile.poppler-experiment .

# Dos árboles fuente con ASan/UBSan, mismo compilador y seis PDFs sintéticos:
python3 apps/inspector/poppler_adversarial_differential.py \
  --source-directory /ruta/tres-archivos-fuente-debian-r111 \
  --fix-directory /ruta/siete-parches-oficiales-debian-r112 \
  --builder-image-id "$(cat /tmp/folio-r116-builder.iid)"

# Contrastes de operaciones aritméticas (NO ruta PDF):
python3 apps/inspector/poppler_arithmetic_boundary_probe.py \
  --pinned-source-tree /ruta/fuente-original-debian-extraida

python3 -m unittest discover -s apps/inspector/tests -p 'test_*.py'
sh scripts/ci.sh
bash apps/inspector/audit_image.sh --experiment --advisories
```

El JSON principal solo puede afirmar `status=isolated_adversarial_source_comparison_only` tras verificar **dos diferencias UBSan** esperadas, **cuatro controles raster idénticos** y todos los artefactos de entrada/salida. Independientemente del resultado, siempre conserva `individual_cve_fix_verified=false`, `cve_remediation_claimed=false`, `source_binary_equivalence_to_runtime_verified=false` y `release_authorized=false`. Cualquier ejecución incompleta o evidencia inesperada devuelve `exit 3`.

## Verificaciones de integración y gates, ejecutadas

- **Probe completo offline desde cero:** `poppler_adversarial_differential.py` terminó con
  **`exit 0`**, después de compilar ambos árboles con ASan/UBSan y
  verificar dos errores del parser original, ninguna señal de sanitizador en
  los seis casos parcheados y cuatro controles con raster idéntico.
- **Harness aritmético de fuente SHA-pinned:** `poppler_arithmetic_boundary_probe.py`
  terminó con **`exit 0`**: cuatro fallos del original/guards de prototipo
  y dos expresiones todavía desprotegidas en ambas variantes.
- **Unitarias del inspector:** `python3 -m unittest discover -s apps/inspector/tests
  -p 'test_*.py'`: **162/162 aprobadas**, incluidas 13 nuevas R1.16
  de corpus sintético, validadores negativos, errores de entrada y hashes.
- **`sh scripts/ci.sh`: exit 0** sobre los últimos cambios concurrentes de
  UX y R2 integrados en la rama: Vitest/workerd, TypeScript, builds dry-run,
  Playwright Chromium E2E/accesibilidad y migraciones D1 `0025`
  **exclusivamente locales**. El CI general no ejecuta Trivy.
- **`bash apps/inspector/verify_raster_guard.sh`: exit 0, 8/8** sobre la
  imagen experimental existente **sin** los prototipos, incluidos antivirus,
  parser aislado, OCR/nativo y rechazo de PDFs prohibidos.
- **`bash apps/inspector/audit_image.sh --experiment --advisories`: exit 2
  BLOQUEADO** — 0 CRITICAL, **70 HIGH / 19 UNKNOWN**, dos motores nativos
  sin cobertura CVE completa. Sin VEX ni excepción.

## Riesgos no resueltos y siguiente criterio

- **`CVE-2026-93312`**: el corpus de página JBIG2 extrema se rechaza antes de reproducir la aritmética sobre `nullptr`; la equivalencia semántica `reset()`/ `rewind()` necesita pruebas dirigidas con bitmap `!isOk()`.
- **`CVE-2026-102621`**: Splash con CTM distante no alcanza el overflow; hace falta construir un path con clipping e intervalos de escaneo suficientemente extremos **sin otros errores previos**.
- **`CVE-2026-102620`**: solo se probó la operación equivalente; es necesario un corpus TrueType Type42 sintético que alcance `cvtSfnts` y revisiones adicionales de alineación.
- **Otros advisories Poppler, Expat, ClamAV y dependencias nativas:** ninguno queda resuelto por los contrastes de dos operadores. Permanecen incertidumbre source→ELF, cobertura CVE y gate Trivy.

La imagen experimental existente sigue **BLOQUEADA** al ejecutar `audit_image.sh --experiment --advisories`: **exit 2, 0 CRITICAL, 70 HIGH, 19 UNKNOWN y dos motores fuente sin evaluación completa**. No se reconstruyen/etiquetan imágenes operativas, no se publica OCI, no se despliega Cloudflare/Preview/producción, no se aplica D1 remoto, no se emite VEX y no se utilizan PDFs institucionales. Solo se integran código, pruebas y documentación de investigación conforme a [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md).

**Resultado:** dos errores UBSan demostrados en el parser original y ausentes en los prototipos para esos inputs concretos; otros mecanismos y riesgos residuales siguen abiertos. El inspector **no** está autorizado para liberación.
