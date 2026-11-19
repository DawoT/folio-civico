# Investigación local · Poppler reducido sin HTTP ni Kerberos (no desplegable)

**Fecha:** 2026-11-19 (America/Lima)
**Estado:** experimento reproducible construido en `fix/tesseract-5.5.4-archive-free`. **No adoptar ni publicar el runtime.** La integración posterior de **código** en `main` se autoriza por [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md); el gate CVE del inspector continúa bloqueado.

## Hipótesis y alcance

La imagen candidata `folio-civico-inspector:ocr-integrated` contiene `libpoppler147` Debian 25.03.0-5+deb13u4, cuya cadena dinámica `libcurl3t64-gnutls` introduce cuatro paquetes de Kerberos que Trivy atribuye 14 HIGH a cada uno (56 HIGH en total). La simulación de retirar Kerberos directamente elimina `poppler-utils` y `libpoppler147`; no es viable sin sustituir las herramientas PDF.

Se construyó **únicamente como prueba** `folio-civico-inspector:poppler-experiment`. `apps/inspector/Dockerfile.poppler-experiment` hereda la imagen candidata local, compila **el paquete de fuente Debian con parches** `poppler=25.03.0-5+deb13u4` mediante `apt-get source` de índices de APT firmados y verifica `dpkg-parsechangelog`. El log de `dpkg-source` confirmó aplicación de `CVE-2025-32364.patch`, `CVE-2025-32365.patch`, `CVE-2025-43903.patch`, `CVE-2025-52886.patch`, `CVE-2025-50420.patch` y otros parches Debian. No se compiló el tarball upstream sin parches ni se instalaron paquetes de `sid`.

Se compila con `ENABLE_LIBCURL=OFF`, `ENABLE_GPGME=OFF`, `ENABLE_NSS3=OFF`; sin bindings Qt/GLib/C++, con herramientas CLI habilitadas. El runtime experimental instala `/opt/folio-poppler`, prioriza sus binarios en `PATH`, registra `source-provenance.json` y elimina únicamente los paquetes Debian `poppler-utils`, `libpoppler147`, `libcurl3t64-gnutls`, `libgssapi-krb5-2`, `libk5crypto3`, `libkrb5-3`, `libkrb5support0` de **esa imagen experimental**. No se utilizó `apt-get autoremove` que pudiera quitar librerías OCR o antimalware. La compilación sigue desactivada en el Dockerfile de producción/candidata.

**Funcionalidad deliberadamente omitida:** lectura HTTP de PDFs y backends de verificación de firmas digitales del motor Poppler. El pipeline actual abre archivos locales y no invoca `pdfsig`; **no** se debe interpretar esta variante como validador de firmas PDF. La autenticidad de los manifiestos del inspector se comprueba por el mecanismo HMAC independiente, no por Poppler.

## Evidencia ejecutada

| Control | Candidata Tesseract | Experimento Poppler |
| --- | ---: | ---: |
| CRITICAL | 0 | **0** |
| HIGH | 128 | **70** |
| UNKNOWN | 19 | **19** |
| Hallazgos totales | 531 | **368** |
| Componentes CycloneDX | 166 | **159** |
| Bloqueantes CRITICAL/HIGH/UNKNOWN | 147 | **89** |
| Bloqueantes con enlace dinámico observado | 82 | **22** |
| Bloqueantes sin enlace observado | 65 | **67** |
| Bibliotecas/ejecutables sin propietario Debian resuelto | 4 | **12** |
| Gate `audit_image.py` | blocked / 2 | **blocked / 2** |

`ldd` sobre `libpoppler.so.147` y las herramientas `pdfinfo`, `pdftotext`, `pdftoppm`, `pdfdetach`, `pdfattach` confirmó ausencia de enlaces dinámicos hacia `libcurl`, `libgssapi`, `libkrb5`, `libk5crypto`, GPGME y NSS3. `dpkg-query` confirmó ausencia de los paquetes retirados. Se mantuvieron `libfontconfig` y `libexpat1` (último con 4 HIGH/2 UNKNOWN de Trivy), necesarios para funciones relacionadas con fuentes.

`bash apps/inspector/build_poppler_experiment.sh` terminó con exit 0: 6/6 motores PDF/OCR/AV reales, 4/4 HTTP en contenedor offline, sin recursos Cloudflare, sin acceso a originales institucionales, y sin cambiar las imágenes `validation` ni `ocr-integrated`. Se corrigió un bug de verificación con `dpkg-query` en la primera ejecución: la comprobación inicial estaba negada y ocultaba un error de expansión shell; ahora se consulta cada paquete y el error no puede pasar silenciosamente. La verificación posterior retornó **exit 0 real**. `bash apps/inspector/compare_ocr_quality.sh --experiment` aprobó **4/4** fixtures sintéticos, con hashes normalizados iguales y **0 errores de caracteres en ambas imágenes**.

`bash apps/inspector/audit_image.sh --experiment --triage` ejecuta **el mismo** scanner Trivy/CycloneDX y el mismo gate global que `--candidate`: no se rebajan umbrales, no hay `--ignore-unfixed`, VEX o supresiones. El resultado final fue **exit 2, blocked**. `sh scripts/ci.sh` aprobó con **84 tests Python** del inspector, Vitest, 5 tests workerd, typecheck, builds y migraciones D1 locales. La imagen experimental final tiene ID Docker local `sha256:abf8192c743f176c6da02bcc288a4eb0ba2d9cb4377a7b8f1725ae9471798254`; **no es un digest de registry publicado**.

## Riesgos críticos antes de cualquier integración

1. **Brecha de visibilidad SBOM:** al compilar Poppler desde fuente y retirar su paquete Debian, Trivy podría dejar de detectar advisories del propio Poppler. La reducción de 58 HIGH es reducción de hallazgos *detectados*, **no demostración de 58 vulnerabilidades corregidas**. Falta inventario explícito de binarios compilados, análisis actualizado de CVE/backports Debian y un mecanismo auditable de correspondencia componente–versión–parches.
2. **Base heredada en capas:** la imagen experimental parte de `ocr-integrated` y usa `apt-get purge`, de modo que los archivos de paquetes quitados podrían persistir en capas inferiores de la imagen OCI aunque no aparezcan en el sistema de archivos de ejecución. Una futura imagen candidata, si se decide este diseño, deberá integrar Poppler mínimo desde el Dockerfile multi-stage original **sin instalar antes** Poppler Debian ni libcurl/Kerberos.
3. **Funciones omitidas:** validar que ninguna ruta futura de ingestión requiera firmas PDF, descargas remotas ni otras herramientas de Poppler deshabilitadas. Los 4 fixtures OCR sintéticos no equivalen a cobertura representativa de documentos oficiales complejos, fuentes embebidas, tablas, escaneos degradados ni firmas.
4. **Gate todavía bloqueado:** 70 HIGH y 19 UNKNOWN, incluyendo ClamAV (7 HIGH), `libexpat1` (4 HIGH/2 UNKNOWN) y util-linux. Resolver o emitir VEX **individual** aprobado; no se declara `not_affected` por ausencia en `ldd`.
5. **Ciclo de firmas:** la imagen hereda bases ClamAV de la candidata; este experimento no implementa renovación remota ni despliegue con digest/rollback. Las firmas siguen expirando a las 72 horas.

## Reproducción local sin despliegue

```sh
python3 -m unittest apps.inspector.tests.test_poppler_experiment
bash apps/inspector/build_poppler_experiment.sh
bash apps/inspector/compare_ocr_quality.sh --experiment
bash apps/inspector/audit_image.sh --experiment --triage  # bloqueado, exit 2
sh scripts/ci.sh
```

**Decisión provisional:** conservar la variante como investigación local. Una [prueba posterior de backend genérico sin Fontconfig](RESEARCH-poppler-fontconfig-regression.md) reveló que la misma página Helvetica sintética se rasteriza con **1882 píxeles oscuros en Fontconfig y 0 en modo genérico**. Esa reducción de dependencias se descartó por pérdida silenciosa de contenido; el harness ahora rechaza rasterizaciones sintéticas en blanco. El [dossier R1.5](SECURITY_CVE_REVIEW_2026-11-19.md) añadió inventario de ELF medidos y un gate explícito para cobertura de fuente: Poppler y Tesseract siguen sin evaluación individual de todos sus advisories, aunque se verifiquen hashes y enlaces. Debe analizarse si compensa la complejidad de mantener dos bibliotecas nativas compiladas desde fuente. Las imágenes aprobables y Cloudflare permanecen intactos. La eventual integración del código en `main` no constituye un despliegue ni una aprobación de seguridad ([ADR-023](ADR-023-main-code-integration-runtime-release-gate.md)).

Referencias: [ADR-015](ADR-015-runtime-cve-triage.md) · [ADR-021](ADR-021-minimal-tesseract-ocr.md) · [ADR-022](ADR-022-ocr-cve-and-signature-renewal.md).
