# R1.42 — Tesseract 5.5.4: guardas semánticas acotadas y cadena de identidades ELF (NO RELEASE)

**Fecha:** 2026-11-20. **Seguimiento:** G2 / [issue #75](https://github.com/DawoT/folio-civico/issues/75). **Paquete examinado:** Tesseract 5.5.4 compilado desde el tarball upstream del Dockerfile existente. **Ámbito:** investigación privada no privilegiada, sin alterar imágenes ni instalar paquetes.

## Decisión y límites de confianza

R1.41 comparó literalmente los parches upstream de 14 CVE contra el tarball 5.5.4: **49/61 hunks exactos; 10/14 CVE con todas las postimágenes**. Los cuatro restantes tenían modificaciones de contexto posteriores o hunks solo de eliminación, por lo que el comparador textual los dejó correctamente como **parciales**: `CVE-2026-119341`, `CVE-2026-73067`, `CVE-2026-88052`, `CVE-2026-88053`.

R1.42 **no altera** esas cifras y **no reclasifica esos cuatro CVE como corregidos**. En lugar de exigir una copia textual exacta de parches anteriores, inspecciona en el **tarball entero verificado por SHA** el orden y el alcance de **14 condiciones explícitas** que restringen las rutas relevantes. Se comprueba así la presencia de mitigaciones seleccionadas en la fuente actual, pero sigue siendo posible que existan vulnerabilidades en otras rutas o diferencias de ejecución que esta revisión no cubra. El tracker de Debian distingue además el paquete corregido en forky/sid 5.5.4-1 de Trixie 5.5.0-1: ese dictamen de empaquetado no certifica el ELF personalizado.

## Resultado estático de los cuatro CVE

| CVE | Control de código fuente concretamente examinado | Guardas |
| --- | --- | ---: |
| `CVE-2026-119341` | Liberación de bitvectors antes de sobrescritura por `FRead`; neutralización de punteros `TempProtos` y `Config[]` antes de rutas de destructor; inicialización de unions y límites del destructor | **4/4** |
| `CVE-2026-73067` | Conteo de aristas limitado por los bytes disponibles y por un techo, antes de reservar memoria; validación de `next_node`; secuencias `forward_edge` obligadas a terminar dentro de `num_edges_` | **3/3** |
| `CVE-2026-88052` | Rechazo de tamaño de unicharset no positivo o superior a `MAX_NUM_CLASSES`; comprobación de inserción duplicada/vacía antes de escrituras por ID; dos entradas de carga dirigidas al parser validado | **3/3** |
| `CVE-2026-88053` | `std::array` inicializados; destructor limitado por `MAX_NUM_CLASSES`; neutralización de punteros deserializados antes de limpieza; fallback y propagación de fallos en clasificador legacy | **4/4** |

**Resultado:** **14/14 condiciones de revisión estática presentes** en siete archivos reales de la fuente admitida por SHA-256. No se ejecutaron payloads CVE, no se auditó exhaustivamente C++ ni se demostró un build reproducible. Los 14 controles son landmarks ordenados/focalizados, **no pruebas de seguridad dinámicas o una excepción al inventario de CVE**.

Se incorporó `apps/inspector/tesseract_554_guard_landmarks.py`, que:

1. Verifica el SHA-256 exacto del tarball `tesseract_5.5.4.orig.tar.gz`: `a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4`, idéntico al argumento de `Dockerfile`.
2. Compara los siete archivos C++ con **sus siete hashes SHA-256 individuales previamente fijados**. Las comprobaciones se limitan a funciones y estructuras nombradas; eliminan comentarios para no aceptar pruebas ficticias y exigen orden relativo entre guardas y usos de punteros/memoria.
3. Ejecuta la adquisición HTTPS únicamente en un contenedor Python desechable local, UID/GID `65534:65534`, `--cap-drop ALL`, `--read-only`, `--security-opt no-new-privileges`, sin mounts ni documentos institucionales.
4. Guarda los siete extractos fuente comprimidos en un informe **privado** con permisos 0600. `--verify-only` los descomprime con límite, recalcula hashes y los **14 controles** sin Docker ni red; rechaza cambios de fuente, falsificaciones de release o guardas omitidas.
5. Devuelve **`exit 2`** por expediente completo y siempre `security_gate=blocked`. Si la fuente o una prueba es inválida, **`exit 3`** fail-closed.

**Pruebas adversariales:** se elimina una protección crítica distinta de cada CVE, se inyecta una ruta de destrucción prematura, se crean funciones duplicadas o falsas en comentarios, se altera la fuente comprimida con hashes recalculados y se intenta falsear cobertura o autorización. **10 pruebas TDD nuevas** pasan.

## Cadena de identidades entre tarball, metadatos y binarios existentes

R1.42 incorpora además `apps/inspector/tesseract_554_candidate_lineage.py`. **No compila** Tesseract. Verifica la identidad de la imagen local ya analizada por R1.40 y repite el inventario dentro del mismo contenedor **identificado por su ID inmutable**, sin red, sin capacidades y como UID/GID `65534:65534`. Exige igualdad completa con el inventario nativo guardado en el expediente R1.40 y con los hashes de la fuente R1.42.

| Eslabón contrastado | Identidad SHA-256 o valor |
| --- | --- |
| Fuente tarball Tesseract 5.5.4 | `a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4` |
| **ID local Docker** del inspector `ocr-integrated` | `b5aadc6c3bfc60471070095c60f756552f83452989017581081e341e0b9adb8a` |
| Reporte R1.40 inmóvil (CycloneDX/Trivy/inventario) | `9e79df93c1560a796f09bf72aa89dc8e915707c5320d82b780d08f77c1fa11f1` |
| ELF `/opt/folio-ocr/bin/tesseract` | `229e33c23fdbfdcb08ea58fcdcf2d91ded744325d79ed2726a1c746a8629a732` |
| ELF `libtesseract.so.5.5.4` | `7ee12c44e33afa46e6e7b5eca176090a63309ba06a69167d7a383d8634384f79` |
| Metadatos instalados `source-provenance.json` | `b9918231729b9cc8fa0a3b59463bbed698da22ca0d37963bd0b4a0536ee19720` |
| Modelo OCR `eng.traineddata` | `7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2` |
| Modelo OCR `spa.traineddata` | `6f2e04d02774a18f01bed44b1111f2cd7f3ba7ac9dc4373cd3f898a40ea6b464` |
| Estado | `runtime_inventory_matches_R140=true`; `source_to_ELF_reproducible_build_attested=false` |

La cadena **sí demuestra** que el ELF, biblioteca, metadatos y modelos del mismo ID local coinciden con las mediciones de R1.40 y que los metadatos *declaran* el SHA de la fuente 5.5.4 revisada. **No demuestra** que un compilador concreto ejecutó precisamente esa fuente sin modificaciones: los metadatos `source-provenance.json` son producidos por el Dockerfile y no constituyen una atestación firmada o reproducción byte a byte. Tampoco existe digest de manifiesto OCI publicado/aprobado.

La verificación negativa incluye sustitución de etiqueta durante análisis, alteración del hash ELF y falsa afirmación de `source_to_ELF_reproducible_build_attested=true`. **7 pruebas TDD nuevas** pasan.

## Evidencias originales y reproducción

Los dos informes R1.42 permanecen **fuera de Git**, en el directorio temporal privado:

| Evidencia | Ruta exacta | SHA-256 |
| --- | --- | --- |
| Guardas estáticas, 7 archivos comprimidos y 14 checks | `/tmp/folio-r142-tesseract-finala.json` | `c897f17e36946f7493ece88aaebd9793dd7c50d41a544f123be734d76c3c064c` |
| Cadena de identidad ELF/modelos/metadatos | `/tmp/folio-r142-lineage-finala.json` | `50dfc01db278ebcbba1767417498c897ae16e7a2c08e263b64de82d52a7f0dc0` |

```bash
# Reanaliza los siete extractos de fuente sin Docker ni red.
python3 apps/inspector/tesseract_554_guard_landmarks.py \
  --verify-only /tmp/folio-r142-tesseract-finala.json
# Exit 2, 14/14 landmarks, NO RELEASE

# Reconcilia nuevamente, sin Docker/red, ambas identidades e inventarios.
python3 apps/inspector/tesseract_554_candidate_lineage.py \
  --snapshot-dir /tmp/folio-r140-candidate-20261120b \
  --source-report /tmp/folio-r142-tesseract-finala.json \
  --verify-only /tmp/folio-r142-lineage-finala.json
# Exit 2, exact candidate image identity, NO build attestation / NO RELEASE
```

El `main` previo a R1.42 ya había integrado investigación concurrente de poda Kerberos (PR #114). **Estas medidas R1.42 no cambian ni auditaban una imagen de reemplazo**; sus resultados se limitan al ID inmutable de R1.40 y no descuentan findings de la investigación concurrente.

## Decisión G2 y próximos controles

**G2 continúa bloqueado**, `release_authorized=false`, `vex=not_issued`, `complete_source_advisory_coverage=false`. La imagen R1.40 tenía **143 hallazgos bloqueantes** (128 HIGH y 15 UNKNOWN) y un componente Tesseract sin cobertura dinámica CVE verificada. No se emitieron supresiones Trivy, CVE `fixed`/`not_affected`, VEX, autorización, instalación, push ni despliegue.

Para avanzar a una atestación binaria auténtica se necesita reproducir de manera independiente el build `ocr_builder` con imagen base/toolchain/pkgs fijados por digest, emitir hashes ELF deterministas comparables, validar funciones vulnerables mediante pruebas de regresión específicas y después repetir el escaneo **sobre una nueva imagen candidata exacta**, con sus firmas ClamAV, OCR/PDF/AV y gate independiente. Un resultado verde del pipeline CI de esta PR significa que el **instrumental de revisión** funciona; no que G2 esté despejado.
