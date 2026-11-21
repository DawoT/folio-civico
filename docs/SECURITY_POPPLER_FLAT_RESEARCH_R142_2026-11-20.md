# R1.42 · Flattening controlado de Poppler R1.41: capas, ELF, CVE y OCR

**Fecha local:** 2026-11-20 (America/Lima). **Issue:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Estado:** investigación técnica, sin release, sin uso de documentos institucionales.

## Contexto y decisión

En R1.41 se eliminaron del filesystem fusionado cuatro paquetes Kerberos, libcurl y dos paquetes Debian Poppler, y se obtuvo una reducción de hallazgos visibles de Trivy de **143 a 85**; los smokes reales y cuatro casos OCR sintéticos no mostraron regresión. Sin embargo, el experimento conservó **las 14 capas históricas de la candidata en un total de 16 capas**. Esa forma de distribución conserva la posibilidad de recuperar archivos purgados desde capas inferiores.

R1.42 prueba exclusivamente una **copia del filesystem final fusionado** en una imagen `FROM scratch`, con validación de identidad de los motores y del inventario de seguridad. **No** convierte el experimento en un artefacto apto para producción.

## Identidades, insumos y construcción

| Tipo | Imagen exacta | Tamaño informado por Docker | Capas |
|---|---|---:|---:|
| Candidata R1.40 no autorizada | `sha256:b5aadc6c3bfc60471070095c60f756552f83452989017581081e341e0b9adb8a` | 379,98 MiB | 14 |
| Poppler R1.41 original | `sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f` | 381,78 MiB | 16 |
| **Poppler plano R1.42 — solo investigación** | `sha256:e8107e124dbe55b813a5f85ecf11103cb3540260f730966d60c7d3fe8b154ade` | **277,39 MiB** | **2** |

Diferencia R1.41→R1.42: **104,39 MiB menos** en el tamaño informado, no una garantía de coste de transferencia o de almacenamiento universal.

### Pasos ejecutados

`bash apps/inspector/build_poppler_flat_research.sh`:

1. Ejecuta `preflight.py --mode build` y **exige exactamente** el ID previamente aprobado para investigación R1.41; no acepta que la etiqueta experimental se redirija a otro ID.
2. La referencia local `nombre@sha256` resultó insuficiente en este BuildKit por intento de consulta a un registro remoto. Para evitar descargas y conservar identidad, crea solo localmente una **etiqueta derivada de los 64 hex del ID verificado**, comprueba el resultado y pasa esa referencia a `POPPLER_FLAT_SOURCE`. Se usa `docker build --pull=false --network=none`, sin comandos APT ni `RUN` de capa final.
3. `Dockerfile.poppler-flat-research` genera `FROM scratch` y `COPY --from=source / /`. Conserva el metadato operativo de R1.41 (`USER 65534:65534`, `CMD`, `WORKDIR`, `EXPOSE 8789` y las variables funcionales). Omite únicamente el valor público `GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305`, innecesario para runtime.
4. Verifica mediante `docker image inspect` que hay **exactamente dos DiffIDs**, uno de contenido nuevo y otro correspondiente a la capa vacía canónica de BuildKit generada por `WORKDIR`. Ninguno de los DiffIDs no vacíos de las 16 capas R1.41 coincide con los de R1.42.
5. Ejecuta dentro del ID plano exacto, con `docker run --pull never --network none --read-only --user no-root --cap-drop ALL --security-opt no-new-privileges`, límites de CPU/memoria y tmpfs sin ejecución, los smokes de motores PDF/AV/OCR, del controlador HTTP y de caducidad de firmas. Comprueba nuevamente los IDs de origen, alias local y salida al terminar.

**Resultado real del builder:** exit 0. Motor: 8/8 controles **passed** (EICAR detectado, OCR/extracción nativa, cifrado/adjuntos/malformación rechazados, entorno aislado); HTTP: 4/4 **passed**; firmas actuales **passed** y caducidad simulada >72h **blocked**. La imagen no publicó puertos ni fue enviada a un registro.

La copia del árbol fusionado no hereda **capas originales por DiffID**. Esto no constituye una atestación forense de inexistencia de todos los bytes sensibles posibles dentro del contenido final, ni firma reproducible del toolchain completo.

## Seguridad diferencial: igual número de CVE, identidad de binarios conservada

`bash apps/inspector/scan_poppler_flat_research.sh` actualiza una sola vez la base de Trivy y usa **la misma DB local para ambas imágenes**. Produce informes JSON de vulnerabilidades, CycloneDX, metadatos de imagen y un inventario ELF real (`source_inventory.py --mode experiment`) ejecutado offline por cada ID inmutable.

`poppler_flat_comparison.py` reutiliza los parsers estrictos del repositorio y exige:

- Los dos IDs Docker distintos y de 64 hex, plataforma `linux/amd64`, **dos capas de salida sin coincidencia de contenido histórico**, configuración operativa inalterada salvo la única variable pública indicada.
- Igualdad exacta de **todos los registros CVE de Trivy** (paquete, versión, advisory, severidad y multiplicidad), e igualdad completa de **los 159 componentes CycloneDX**.
- Igualdad del inventario de **Poppler y Tesseract compilados desde fuente**, de los hashes SHA-256 de sus bibliotecas/ejecutables y del conjunto de cinco utilidades Poppler y dos modelos OCR (`eng`, `spa`).
- Cobertura CVE de ambos componentes nativos expresamente `not_verified`; ante un informe coherente, la herramienta devuelve **exit 2 / release_authorized=false**. Ante evidencia faltante, corrupta, cambiada o ambigua devuelve **exit 3**.

**Resultado real de scanner/comparador: exit 2 (BLOCKED como se diseñó).**

| Evidencia | R1.41 | R1.42 | Cambio |
|---|---:|---:|---|
| DiffIDs OCI | 16 | **2** | −14 |
| DiffIDs históricos no vacíos reutilizados | — | **0** | Correcto |
| HIGH | 70 | **70** | 0 |
| UNKNOWN | 15 | **15** | 0 |
| CRITICAL | 0 | **0** | 0 |
| Bloqueantes | 85 | **85** | **0** |
| CycloneDX | 159 | **159** | 0 |
| Compilados sin CVE completa | 2 | **2** | 0 |
| ELF, herramientas, modelos y procedencia | Registrados | **Idénticos** | 0 |

**Ningún CVE se corrigió en este incremento.** La ausencia de capas heredadas evita transportar esa cadena histórica de capas, pero el riesgo CVE en los paquetes presentes y el riesgo de código fuente nativo permanecen inalterados. Una imagen plana solo tiene sentido como reducción de superficie de distribución, no como aval de seguridad.

### Fidelidad OCR real — exclusivamente sintética

`bash apps/inspector/compare_poppler_flat_quality.sh` ejecuta el harness OCR real de cuatro casos en **ambos IDs**, sin red ni archivos institucionales. Resultado **exit 0 / no_regression**, textos hash idénticos **4/4**, errores de caracteres **0/0**. No mide precisión en planos reales ni documentos hostiles.

## Pruebas e integración

Nuevo contrato de regresión `test_poppler_flat_comparison.py` con tests sobre el comparador, CLI y scripts. Rechaza cambios del DiffID, pertenencia a capas históricas, IDs, arquitectura, usuario, configuración, variables, paquetes, CVE, severidades, ELF, herramientas y cobertura de origen. Los tests se ejecutaron en host y Python 3.12 no-root/no-network/noexec.

**Regresión Python inspector:** 511/511 tests y 652 subtests PASS en rama de investigación (antes de integrar). El CI integral y el CI remoto se registran separadamente; el CI local no sustituye el gate de seguridad.

## Límites, prioridades y gobierno

**Bloqueos restantes:** 70 HIGH, 15 UNKNOWN, CVE nativos de Poppler/Tesseract sin cobertura equivalente, Expat y ClamAV pendientes de revisión por advisory, falta de fuzzing/adversarial y evidencia de calidad en documentos reales autorizados, pruebas de rotación de firmas y autorización de entorno. La eliminación de DiffIDs tampoco elimina por sí misma archivos no deseados que pudieran encontrarse en el filesystem final; no se ejecutó una auditoría exhaustiva de secretos en el contenido de la imagen.

**`native_source_cve_coverage_verified=false`; `trivy_release_gate_passed=false`; `safe_for_untrusted_pdf_verified=false`; `release_authorized=false`.**

**Autorización de alcance:** integrar investigación y tests a `main` tras CI. **Prohibido** publicar OCI, desplegar Preview/producción, modificar Cloudflare/D1 remoto, conceder VEX, cerrar Issue #68 o usar material institucional.
