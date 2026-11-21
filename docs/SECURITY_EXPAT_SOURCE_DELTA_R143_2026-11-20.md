# R1.43 — Expat 2.10.0 con fuente fijada, delta CVE y procedencia por ID

**Corte:** 2026-11-20 America/Lima. **Seguimiento:** [Issue #68](https://github.com/DawoT/folio-civico/issues/68). **Decisión:** investigación integrable; **NO RELEASE / NO VEX**.

## Alcance y fuentes

El inspector experimental Poppler R1.41 utiliza Debian Expat `2.9.0-1~deb13u1`. El prototipo existente compila **Expat 2.10.0** desde tres archivos Debian fijados por SHA-256, y aplica un parche local de [PR upstream #1492](https://github.com/libexpat/libexpat/pull/1492) para CVE-2026-124317. R1.43 endurece la cadena de construcción, ejecuta ese runtime y mide el diferencial real sin modificar el Dockerfile operativo.

**Fuentes oficiales:** [Debian Security Tracker](https://security-tracker.debian.org/tracker/source-package/expat); [anuncio Debian 2.10.0-1](https://tracker.debian.org/news/1818607/accepted-expat-2100-1-source-into-unstable/); [Debian Bug #1153368 — CVE-2026-124317](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1153368). El tracker mantiene Trixie vulnerable en los seis CVE de Expat revisados. Expat 2.10.0 incorpora correcciones documentadas para cuatro CVE, pero los registros del escáner y la falta de atestación total **impiden afirmar su remediación para release**.

| Evidencia | Poppler R1.41 | Expat R1.43 |
|---|---|---|
| Docker ID | `sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f` | `sha256:3447fed5e20f4c7f31110403738ffba08ab6b203141cea1b2158f60ef3ed5731` |
| Versión Expat | `2.9.0-1~deb13u1` | `2.10.0-1+folio1` |
| Tamaño (Docker) | 381,78 MiB | 382,16 MiB |
| Capas | 16 | **18 (las 16 anteriores se conservan)** |

**La imagen Expat no es plana ni publicable**: conserva las 16 capas de origen como prefijo; archivos reemplazados pueden persistir en su historia OCI.

### Fuente y ELF medidos

- Fuente Debian `expat_2.10.0.orig.tar.gz` SHA-256 `b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f`. También se fijan por hash el `.dsc` y `.debian.tar.xz`. Se usan HTTPS, hashes y el toolchain Debian Trixie, **sin verificar una firma GPG separada del anuncio Debian ni reproducibilidad binaria**.
- Parche local aplicado con `patch --fuzz=0`, SHA-256 `0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3`. El build completó CMake, **CTest nativo**, `dpkg-buildpackage`, instalación `dpkg -i` y verificación del runtime con `ctypes.XML_ExpatVersion()`.
- El runtime declaró `libexpat1 2.10.0-1+folio1`, versión `expat_2.10.0`, enlazada en cinco utilidades Poppler. `xmlwf` está ausente; ello **no** equivale a VEX `not_affected` para CVE-2026-128241.
- Hash SHA-256 real del ELF de `libexpat.so.1`: `4bea107cfb1ec4dcbe2bc0062967cd8ee1df80f830da203dc60b477bc8beecef`.

## Integridad de imagen (R1.43)

`build_expat_experiment.sh` ahora exige el **ID exacto de R1.41** antes de construir. Por la limitación observada de BuildKit resolviendo manifest digests locales, usa un **alias local derivado del ID completo** y verificado antes y después de construir; pasa `EXPAT_BASE_IMAGE` al `FROM` global del Dockerfile, con valor seguro predeterminado `scratch` y `docker build --pull=false`. El resultado se inspecciona y los tres smokes usan `docker run --pull never --network none --read-only --user 65534:65534 --cap-drop ALL` contra el **mismo ID inmutable**. Un retarget del tag original, alias o experimento produce exit 3. No se publica ni despliega ningún artefacto.

## Validación real

- **Builder/smoke**: `bash apps/inspector/build_expat_experiment.sh` **exit 0**; 8/8 controles de motor AV/PDF/OCR y entradas sintéticas negativas (EICAR detectado, cifrado/adjuntos/malformación rechazados), **4/4 HTTP**.
- **OCR diferencial**: `bash apps/inspector/compare_expat_ocr_r143.sh` **exit 0**, **4/4 hashes de texto idénticos, 0 errores de caracteres, ninguna regresión**; corpus exclusivamente sintético.
- **CVE probes reales acotados** sobre el ID experimental: parser reset, amplificación artificialmente limitada y subparser vacío PASS; **CVE-2026-118370 NO EJERCITADO** en entrada extrema multigigabyte. Máximo 100 KB de entrada y 15 s declarados. No equivalen a pruebas completas de explotación.
- **Trivy/CycloneDX**: `scan_expat_experiment.sh` y `scan_expat_delta_r143.sh` devuelven **exit 2 / BLOCKED**. El segundo actualiza primero una DB y luego usa `--skip-db-update` en ambos scans; compara por paquete/advisory, verifica el SBOM y los hashes reales de Expat, Poppler, Tesseract y modelos OCR. Incluye los probes anteriores y exige que su hash Expat coincida con el ELF medido.

| Hallazgos reales | Base Poppler | Expat reconstruido |
|---|---:|---:|
| CRITICAL | 0 | 0 |
| HIGH | **70** | **70** |
| UNKNOWN | **15** | **15** |
| **Total bloqueante** | **85** | **85** |
| CycloneDX | 159 | 159 |
| CVE Expat registrados | 4 HIGH + 2 UNKNOWN | **4 HIGH + 2 UNKNOWN** |
| Motores fuente sin CVE cubierta | 2 | **3** |

**Cero cambios en otros paquetes o advisories; cero avisos Expat añadidos o desaparecidos del escáner.** El salto de versión no autoriza reclasificarlos como corregidos. `expat_evidence.py` confirma 159 componentes, los hashes de fuente/parche/ELF y **24 CVE nativos seleccionados sin evaluación de cobertura completa**. Un diferencial coherente produce exit 2; evidencia ausente, discrepante o alterada produce exit 3.

### Calidad y limitaciones

TDD Red→Green: `test_expat_candidate_pin_r143.py` cubre identidad de imagen, colisión de alias, retarget e invocaciones por ID; `test_expat_delta_r143.py` valida paquetes, CVE, SBOM, nativos, CLI y scripts mediante pruebas adversarias; `test_expat_prototype.py` preserva los contratos anteriores. Se verificó el mock del builder en Python **3.12 aislado**. Suite inspector: **538 tests y 672 subtests PASS** antes del cambio documental; CI integral y Actions se registran por separado.

**Pendientes de release:** 70 HIGH/15 UNKNOWN, cobertura CVE de tres nativos y 24 casos seleccionados, firma/reproducibilidad binaria, revisión de Expat/ClamAV por advisory, aplanamiento de la variante Expat, pruebas de PDFs hostiles y material institucional autorizado, rotación de firmas, rollback y aprobaciones de entorno. Los CVE publicados en el [aviso Cisco de noviembre de 2026](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-clamav-multi-e93M3vdA.html) también deberán confrontarse con la versión ClamAV 1.5.5 y el inventario del escáner; **una alerta ausente no demuestra cobertura completa**.

`trivy_release_gate_passed=false` · `native_expat_cve_coverage_verified=false` · `native_poppler_tesseract_cve_coverage_verified=false` · `release_authorized=false`.

**Issue #68 ABIERTO. No OCI remoto, Cloudflare/Preview/producción, D1 remoto, VEX ni documentos institucionales.**
