# R1.41 · Poppler sin dependencias Kerberos: diferencial estricto y límite de release

**Fecha:** 2026-11-20 (America/Lima). **Issue:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Estado:** experimento local, NO RELEASE.

## Objetivo

La candidata de R1.40 contiene la cadena dinámica libcurl-gnutls → Kerberos al cargar PDF con Poppler. El inspector necesita procesar PDFs locales, no descargar recursos de red. El repositorio ya ofrecía `Dockerfile.poppler-experiment`, compilando la **fuente Debian parchada** de Poppler `25.03.0-5+deb13u4` con `ENABLE_LIBCURL=OFF`, `ENABLE_GPGME=OFF` y `ENABLE_NSS3=OFF`. R1.41 reconstruye y prueba esta variante sin modificar la candidata, y comprueba la diferencia por registros de advisory, no solo por cifras globales.

| Uso | ID Docker completo |
|---|---|
| Candidata R1.40 NO aprobada | `sha256:b5aadc6c3bfc60471070095c60f756552f83452989017581081e341e0b9adb8a` |
| Poppler experimental R1.41 | `sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f` |

El builder verifica la fuente Debian con archivos `.dsc`, `.orig.tar.xz` y `.debian.tar.xz` fijados por SHA-256 (más APT Debian firmado). **No** es una prueba de ELF reproducible ni de corrección de los CVE del Poppler recompilado.

## Evidencia real de dependencias y funcionalidad

`bash apps/inspector/build_poppler_experiment.sh`: preflight local PASS, build y smoke **exit 0**. Cinco herramientas PDF (`pdfinfo`, `pdftoppm`, `pdftotext`, `pdfdetach`, `pdfattach`) resuelven a `/opt/folio-poppler/bin/`, y sus `ldd` no contienen libcurl, GSSAPI, Kerberos, GPGME ni NSS3. Los siete paquetes indicados abajo están ausentes del inventario Debian instalado. Fontconfig se mantiene, y **Expat sigue vinculado**.

Los smokes con **motores reales** confirmaron controles de antivirus/PDF/OCR y negativos de cifrado, adjuntos y malformación (**8/8**) más HTTP real (**4/4**), en contenedores sin red y con límites. `bash apps/inspector/compare_ocr_quality.sh --experiment` completó **exit 0**: cuatro casos sintéticos, hashes de texto iguales **4/4**, cero errores de caracteres y ninguna regresión entre la candidata y el experimento. No se extrapola a planos reales, A0 o PDFs adversariales.

## Trivy: diferencia por advisory y SBOM, no remediación

Se ejecutó Trivy 0.76.2 sobre ambas imágenes locales con `--skip-db-update` y la **misma DB v2** (actualizada 2026-11-20 18:59:53 UTC). Los cuatro archivos JSON/CycloneDX y los dos IDs Docker se contrastaron con el comparador de R1.41: exige **exactamente siete paquetes Debian retirados, cero paquetes nuevos y cero CVE nuevos/modificados/desaparecidos de paquetes retenidos**. Verifica los IDs en CycloneDX. El resultado es **exit 2 / release bloqueado**, mientras toda evidencia incompleta o incoherente produce exit 3.

| Indicador | Candidata | Experimento | Diferencia |
|---|---:|---:|---:|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 128 | 70 | **−58** |
| UNKNOWN | 15 | 15 | 0 |
| MEDIUM | 189 | 146 | −43 |
| LOW | 203 | 141 | −62 |
| Bloqueantes HIGH/CRITICAL/UNKNOWN | **143** | **85** | **−58** |
| Componentes CycloneDX | 166 | 159 | −7 |
| Componentes compilados sin cobertura CVE completa | 1 | **2** | +1 |

Los **58 HIGH que ya no son visibles para Trivy como paquetes Debian** pertenecían a `libgssapi-krb5-2` (14), `libk5crypto3` (14), `libkrb5-3` (14), `libkrb5support0` (14) y `libcurl3t64-gnutls` (2). También se retiraron `poppler-utils` y `libpoppler147`, sin HIGH registrados en esos dos paquetes en esta instantánea. **Cero advisories nuevos observados en paquetes retenidos**. El cambio en los resultados del escáner NO equivale a aplicar 58 parches CVE ni a declarar inocuo Poppler.

La auditoría oficial `bash apps/inspector/audit_image.sh --experiment --triage --advisories` terminó **exit 2 / blocked**: 0 CRITICAL, 70 HIGH, 15 UNKNOWN, 159 componentes, 2 binarios fuente sin cobertura advisory completa (Poppler, Tesseract), 12 propietarios Debian de bibliotecas aún no resueltos. Expat sigue presente, con alertas pendientes; sin VEX ni exenciones.

## Capas de imagen: razón adicional para no publicar

Docker `RootFS.Layers` verificó **14 capas** de candidata y **16** del experimento. **Las 14 primeras son exactamente iguales**. La purga elimina archivos del filesystem fusionado, pero **los bytes originales podrían permanecer recuperables de las capas inferiores**. Ninguna reducción de Trivy justifica distribuir estas capas; requeriría reconstrucción mínima/flattening con otra auditoría y aprobación.

## Código y TDD de R1.41

Endurecimientos sin alterar el runtime operativo:

1. `build_poppler_experiment.sh` fija el ID de la candidata antes de construir, valida el digest local `folio-civico-inspector@sha256:...` y pasa la referencia por `POPPLER_BASE_IMAGE` a `FROM` en el Dockerfile. El ARG sin valor explícito toma `scratch`, que **no permite superar los RUN del stage runtime**. Build con `--pull=false`.
2. La imagen experimental se resuelve a un ID Docker estricto; los tres smokes ejecutan `docker run --pull never` contra el **mismo ID**, sin red, y las dos etiquetas se verifican otra vez al terminar. Cambio de tag, digest erróneo o evidencia ausente ⇒ **exit 3**.
3. `kerberos_poppler_comparison.py` reutiliza los parsers `_scan`/`_sbom` existentes; exige diferencias de paquete/CVE estrictas, preserva los UNKNOWN y **siempre** devuelve exit 2 con `release_authorized=false` cuando la evidencia es coherente.
4. TDD Red→Green con `test_poppler_experiment_image_pin.py` y `test_kerberos_poppler_comparison.py`, más corrección de importación aislada en `test_poppler_experiment.py`.

**Regresión Python del inspector:** **493/493 pruebas**, **631 subtests** PASS. **Python 3.12** aislado, sin red, read-only y /tmp noexec: **6/6 pruebas del builder** PASS. CI integral local y CI remoto del PR se verifican aparte.

## Decisión

**Investigación integrable en main con CI, pero NO candidata al release.** Faltan 85 hallazgos HIGH/UNKNOWN, cobertura de CVE de **Poppler y Tesseract compilados**, revisión de Expat/ClamAV, eliminación comprobada de bytes históricos, fuente→ELF, PDFs reales autorizados, estrés adversarial, rotación de firmas y autorización explícita de entorno remoto.

`poppler_native_cve_coverage_verified=false`; `tesseract_native_cve_coverage_verified=false`; `trivy_release_gate_passed=false`; `release_authorized=false`.

No se publicó OCI, ejecutó Preview/Cloudflare/D1 remoto, trató documento institucional, concedió VEX ni cerró el Issue #68.
