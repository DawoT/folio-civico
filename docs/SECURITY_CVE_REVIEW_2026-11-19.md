# Seguridad R1.5 · CVE de ClamAV/Expat y cobertura de nativos

**Fecha de revisión:** 2026-11-19 (America/Lima)
**Ámbito:** imagen **local** `folio-civico-inspector:poppler-experiment` y comparación con `ocr-integrated` y `validation`.
**Decisión de release:** **NO APROBADO** para Preview ni producción. La integración de código en `main` se separa expresamente de la liberación del runtime en [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md). El gate original permanece bloqueado. Esta investigación **no** constituye un VEX aprobado, una excepción de vulnerabilidades ni una autorización de despliegue.

## Escaneo real e inventario de CVE

`bash apps/inspector/audit_image.sh --experiment --triage --advisories` recupera el informe Trivy JSON, CycloneDX y la evidencia ELF desde **el mismo ID de imagen inmutable**, sin red en el contenedor ni documentos institucionales. El resumen conserva los conteos de Trivy y añade la cantidad de componentes nativos cuya cobertura de CVE **no está demostrada**. Las salidas de detalle no pueden cambiar el código del gate.

| Control | Resultado observado |
| --- | ---: |
| Trivy CRITICAL / HIGH / UNKNOWN | **0 / 70 / 19** |
| Hallazgos Trivy totales / componentes CycloneDX | **368 / 159** |
| Total de hallazgos HIGH + UNKNOWN | **89** |
| ClamAV | **7 HIGH** |
| `libexpat1` | **4 HIGH + 2 UNKNOWN** |
| Otros hallazgos bloqueantes | **76** |
| Componentes compilados y sin evaluación individual de CVE | **2** |
| Estado y salida del gate | **blocked / exit 2** |

No se deduce que `159` componentes CycloneDX incluyan a los dos motores compilados desde fuente. El nuevo inventario **complementa** el SBOM original: identifica físicamente los ELF, sus huellas SHA-256, versión declarada y observable, flags de procedencia y enlace dinámico. Todavía no proporciona una cobertura automatizada equivalente a la de paquetes Debian.

### ClamAV: siete alertas con indicios de discrepancia de versión

**Hecho verificable:** el contenedor ejecuta `ClamAV 1.5.5`; la instalación reporta `clamav 1.5.5-1`. El Dockerfile descarga el .deb del fabricante Cisco Talos y exige verificar su firma GPG contra la huella primaria `5BADCA2665EF59DCF8A23D8B707F0DB480836771` durante el build. Las bases `daily`, `main`, `bytecode` pasan `freshclam` al construir y son rechazadas al superar las 72 h.

**Trivy todavía notifica estos CVE, todos HIGH y sin `FixedVersion` en su informe**:

| CVE | Subsistema citado por Cisco | Corrección documentada |
| --- | --- | --- |
| `CVE-2026-20213` | PE/Aspack | ClamAV 1.5.3 |
| `CVE-2026-20214` | FSG | ClamAV 1.5.3 |
| `CVE-2026-20215` | 7z | ClamAV 1.5.3 |
| `CVE-2026-20216` | InstallShield | ClamAV 1.5.3 |
| `CVE-2026-20217` | PESpin | ClamAV 1.5.3 |
| `CVE-2026-20243` | ALZ | ClamAV 1.5.3 |
| `CVE-2026-20244` | DMG | ClamAV 1.5.3 |

**Fuentes oficiales:** [Cisco, aviso de julio de 2026](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-clamav-88cFYyxR.html), [Ubuntu USN-8517-1, 8-7-2026](https://ubuntu.com/security/notices/USN-8517-1) (todos los CVE en actualización `1.5.3+dfsg`) y [publicación ClamAV 1.5.3](https://blog.clamav.net/2026/07/clamav-153-and-145-security-patch.html). La [publicación oficial 1.5.5 del 18-11-2026](https://blog.clamav.net/2026/11/clamav-155-147-security-patch-release.html) contiene además nuevas correcciones de seguridad.

**Interpretación:** existe evidencia sólida **a nivel de versión** de que 1.5.5 incorpora correcciones publicadas antes en 1.5.3. No se ha demostrado una regresión concreta, pero tampoco se ha realizado auditoría binaria/reproducibilidad bit a bit ni se ha aprobado VEX por propietario de seguridad. Se mantienen los siete hallazgos dentro del gate hasta completar esa evaluación. La evaluación Linux no debe basarse únicamente en el CVSS agregado para Windows.

### Expat: seis avisos aún pendientes para la versión instalada

Versión en imagen: **`libexpat1 2.9.0-1~deb13u1`** de Debian Trixie. [Debian Security Tracker](https://security-tracker.debian.org/tracker/source-package/expat) la clasifica como vulnerable en las siguientes incidencias:

| CVE | Trivy | Naturaleza y observación |
| --- | --- | --- |
| `CVE-2026-113351` | HIGH | DoS al reinicializar el parser con `XML_ParserReset` |
| `CVE-2026-115506` | HIGH | DoS por conteo tardío de amplificación de entidades XML |
| `CVE-2026-117610` | HIGH | Desreferencia NULL en el parser |
| `CVE-2026-118370` | HIGH | Overflow aritmético |
| `CVE-2026-124317` | UNKNOWN | Lectura fuera de límites con codificaciones desconocidas |
| `CVE-2026-128241` | UNKNOWN | Seguimiento de symlinks en la herramienta `xmlwf` |

Se verificó `xmlwf_present=no` en la imagen experimental. Esa observación **no convierte automáticamente** `CVE-2026-128241` en `not_affected`: faltan prueba de alcance de código, evaluación formal, aprobador y revisión. Los demás avisos afectan funciones de análisis de Expat y no se resuelven retirando `xmlwf`. El salto a paquetes `sid` o una compilación no parcheada está prohibido. La [evaluación posterior R1.8](ADR-026-expat-parser-environment-isolation.md) verificó que las correcciones faltantes de `CVE-2026-124317` y `CVE-2026-128241` están en la rama de desarrollo de Expat 2.11.0, no en un paquete estable Trixie. Mientras se espera una actualización aprobada, los motores reciben una allowlist de entorno que impide pasarles secretos y overrides de configuración XML; **no se han eliminado los CVE del gate**. El contenedor ya impone límites de recursos y filesystem de solo lectura, medidas que **mitigan consecuencias pero no eliminan las vulnerabilidades**.

Debian publicó previamente el update `2.9.0-1~deb13u1` ([DSA 6566-1](https://lists.debian.org/debian-security-announce/2026/msg00480.html)), pero ese parche corrige **otros** CVE históricos y no demuestra que los seis anteriores estén resueltos. Continuar seguimiento del paquete oficial estable.

### Poppler desde fuente: cobertura que no puede inferirse de Trivy

El experimento compila `poppler=25.03.0-5+deb13u4` de las fuentes Debian firmadas, aplica su serie de parches y deshabilita `ENABLE_LIBCURL`, `ENABLE_GPGME` y `ENABLE_NSS3`. Esto permite retirar la cadena Kerberos **del filesystem final de ejecución**, conservando el procesamiento de PDF nativo y escaneado. La imagen se basa en capas de `ocr-integrated` y puede conservar archivos históricos de paquetes purgados en capas OCI inferiores, motivo adicional para no promoverla.

[Debian Security Tracker — Poppler](https://security-tracker.debian.org/tracker/source-package/poppler) mantiene CVE abiertos para Trixie, por ejemplo `CVE-2026-107705` (desbordamiento en procesamiento) y `CVE-2026-93653` (denegación de servicio en Splash). El paquete fuente con backports de Debian **no garantiza** que todos esos avisos recientes estén corregidos. Deben identificarse los parches de cada versión con código y alcance en los binarios locales. No se interpretará la desaparición del paquete `libpoppler147` de Trivy como un cierre de estos CVE.

## Nuevo guardrail de cobertura de componentes locales

Archivos relevantes: `apps/inspector/source_inventory.py`, `audit_image.py`, `triage_image.py`, `advisory_inventory.py` y `audit_image.sh`.

- `source_inventory.py` se ejecuta **dentro del ID de imagen obtenido antes del escaneo**, en modo offline, solo lectura, sin capacidades Linux y sin montajes de documentos. Exige manifiesto de procedencia consistente, versión **observable** de los binarios y cabecera ELF; calcula hash SHA-256 del ejecutable, biblioteca y manifiesto. Para Poppler comprueba las cinco herramientas `pdfinfo`, `pdftotext`, `pdftoppm`, `pdfdetach`, `pdfattach` y verifica el `ldd` de todos los ejecutables y bibliotecas frente a dependencias prohibidas o ausentes.
- El gate verifica correspondencia de clase de imagen: `validation` puede no incorporar custom source; `ocr-integrated` **debe** contener Tesseract 5.5.4; `poppler-experiment` **debe** contener también Poppler Debian 25.03.0-5+deb13u4. Fingerprints, flags o fuentes inconsistentes provocan error **3** (fail closed).
- **Incluso con cero CVE de Trivy**, si hay motores compilados y su cobertura de CVE está pendiente, `audit_image.py` conserva **exit 2** y `source_advisory_coverage=pending_review`. No se ha implementado un botón de aceptación ni una VEX automática. El informe añade `native_components` con hashes medidos y `source_components_unassessed` sin modificar el conteo CycloneDX de Trivy.
- Los informes secundarios de advisories y triaje reciben el **mismo inventario y la misma evaluación**, cotejando su exit code con el original. No se crea una ruta alternativa que permita convertir `blocked` en `passed`.
- Un hash ELF prueba la identidad del artefacto medido, **no** su seguridad ni correspondencia criptográfica con el tarball fuente. `ldd` no observa `dlopen`, plugins, código estático ni todas las rutas de entrada; los hallazgos siguen abiertos.

Huellas de referencia **de la imagen experimental local** al 19-11-2026:

| Componente | Ejecutable SHA-256 | Biblioteca SHA-256 |
| --- | --- | --- |
| Tesseract 5.5.4 | `229e33c23fdbfdcb08ea58fcdcf2d91ded744325d79ed2726a1c746a8629a732` | `7ee12c44e33afa46e6e7b5eca176090a63309ba06a69167d7a383d8634384f79` |
| Poppler 25.03.0-5+deb13u4 | `888221ae778e7bc97261c743cf779d4a982c94afa70e91b2ef49eeef7897ebed` | `3ca61c1d42c8a040e47f01524d0bc3d45d73bc3e7981fe79a46b9cf9cb8dfe3b` |

Estos hashes corresponden al runtime local observado, no a un digest OCI de registro publicado. Los hashes de los restantes cuatro CLI de Poppler están presentes en el JSON de auditoría y se actualizan al reconstruir.

## Criterios que siguen impidiendo la integración

1. Evaluar **cada CVE** detectado y no detectado por Trivy en componentes nativos; priorizar Expat y Poppler expuestos al contenido PDF y formalizar la discrepancia ClamAV con evidencias reproducibles.
2. No activar ningún VEX o excepción sin análisis de rutas, responsable, aprobación, vencimiento y seguimiento. Los 70 HIGH/19 UNKNOWN continúan bloqueando.
3. Sustituir la arquitectura experimental en capas por una imagen multi-stage limpia *si* se aprueba el diseño de Poppler mínimo, sin generar paquetes purgados recuperables de capas inferiores.
4. Ejecutar pruebas PDF/OCR representativas; los cuatro fixtures sintéticos solo prueban esos casos particulares.
5. Validar rotación automatizada de imagen/firmas, digest inmutable y rollback **solo en Preview expresamente autorizado**. No existe despliegue.

**Comandos locales:**

```sh
bash apps/inspector/audit_image.sh --experiment --triage --advisories # exit 2
bash apps/inspector/audit_image.sh --candidate --advisories          # exit 2
sh scripts/ci.sh
```

La revisión técnica R1.5 no alteró la imagen `validation` ni Cloudflare. La integración posterior del **código** en `main` se rige por [ADR-023](ADR-023-main-code-integration-runtime-release-gate.md) y no cambia la prohibición de desplegar el inspector.
