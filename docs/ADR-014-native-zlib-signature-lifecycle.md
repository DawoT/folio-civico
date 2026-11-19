# ADR-014 · Corrección zlib y ciclo de vida de firmas ClamAV

**Fecha:** 2026-11-19 (America/Lima)  
**Estado:** corrección implementada, imagen local reconstruida, smokes reales y scanner CVE ejecutados. **El gate de vulnerabilidades de la imagen continúa bloqueado; sin despliegue Cloudflare.**

## Evidencia de partida

El escaneo Trivy de la ADR-013 sobre la imagen Debian Trixie multi-stage detectó **1 CRITICAL, 150 HIGH, 19 UNKNOWN y 636 hallazgos** en total. Se revisó la evidencia del reporte y las fuentes oficiales de Debian:

- **CVE-2026-6653 / libxml2:** la versión `2.12.7+dfsg+really2.9.14-2.1+deb13u3` se registra como **vulnerable en Trixie, sin paquete corregido para esa rama**. El ejecutable real de Tesseract carga `libxml2.so.2` de forma transitiva (verificado con `ldd`). No se puede declarar `not_affected` por falta de análisis de rutas y del procesamiento de XML.
- **CVE-2026-85091 / zlib:** Debian publica y marca como corregida la versión de seguridad **`1:1.3.dfsg+really1.3.1-1+deb13u1`** para Trixie.

Fuentes oficiales: [Debian CVE-2026-6653](https://security-tracker.debian.org/tracker/CVE-2026-6653), [Debian CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091).

**Decisión:** actualizar únicamente la dependencia nativa con corrección verificada, sin mezclar bibliotecas `unstable` con Debian Trixie, ignorar CVEs o declarar VEX por intuición.

## Cambios reales

### Versión mínima de zlib en el build

`apps/inspector/Dockerfile` instala explícitamente `zlib1g` desde los repositorios Trixie actualizados y bloquea el build si `dpkg --compare-versions` no alcanza la revisión `deb13u1`. Una reconstrucción no puede admitir por accidente la versión antigua desde una caché o mirror desactualizado.

Versión verificada **dentro del contenedor final**:

```text
clamav=1.5.5-1
libxml2=2.12.7+dfsg+really2.9.14-2.1+deb13u3
zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1
```

### Inventario y caducidad de firmas, fail-closed

`require_fresh_signatures()` ahora exige, en cada admisión de PDF y cada comprobación `/health`:

- Las **tres bases core** `daily`, `main`, `bytecode`, exactamente una `.cvd` o `.cld` por nombre.
- Fichero regular no vacío, sin symlinks, sin versiones duplicadas o bases core desconocidas.
- `mtime` no mayor de **72 horas** ni más de cinco minutos en el futuro.
- Cualquier ausencia, antigüedad, duplicación o fallo de acceso provoca `ScannerUnavailable` (respuesta HTTP 503), **nunca** `clean`.

El contenedor permanece con `--network none`, sistema de archivos de solo lectura y firmas descargadas/probadas por `freshclam` **durante el build**. Un `mtime` reciente no prueba por sí solo autenticidad ni actualidad frente a amenazas nuevas: debe conservarse la validación de firma oficial por ClamAV y reconstruirse/reemplazarse la imagen antes de vencer el plazo. **No se ha habilitado ningún cron ni existe rotación remota automática.**

## Verificación reproducida

- **TDD:** pruebas que fallaron antes de los cambios y pasaron después (bases ausentes, firma caducada/futura, symlink, duplicados, salud HTTP 503 tras expiración, Dockerfile que obliga a zlib corregido).
- **Imagen Docker real:** compilada con paquete zlib corregido, ClamAV 1.5.5 verificado por GPG y tres bases oficiales presentes.
- **Smokes auténticos aislados:** **6/6** (PDF nativo, OCR, rechazo dañado/cifrado/adjunto, EICAR) y **4/4 HTTP** (salud, rechazo de credencial, manifiesto, rechazo de hash), exit code 0.
- **Trivy/CycloneDX en imagen final:** **1 CRITICAL, 149 HIGH, 19 UNKNOWN; 634 hallazgos totales; 186 componentes**. `pnpm audit:inspector:image` devolvió **exit code 2, status blocked**. `fixable_high_critical=0` según la base utilizada; no significa que no exista mitigación ni que el sistema sea seguro.
- Las pruebas de `pnpm check`, `workerd` y seguridad de código siguen separadas del escaneo de imagen: aprobar las primeras no levanta el bloqueo de la última.

## Bloqueos y acciones pendientes

1. **CVE-2026-6653 / libxml2:** vigilar paquete oficial corregido de Debian Trixie o preparar evaluación formal VEX basada en rutas de ejecución, evidencia reproducible y aprobación humana. **No** utilizar paquetes `sid`/`unstable` ni eliminar `libxml2` porque está enlazada al motor OCR.
2. Evaluar los **149 HIGH y 19 UNKNOWN** restantes con evidencias y remediaciones priorizadas, especialmente parsers nativos que reciben documentos controlados por usuarios.
3. Diseñar y probar una **rotación de imagen/firmas** antes de 72 h con firma, digest, disponibilidad y rollback seguro en Preview, una vez exista autorización de entorno. La expiración local con `503` está cubierta; la entrega automatizada no.
4. Mantener **desactivado Preview**, Queues, DLQ, Container, cron y cualquier procesamiento institucional hasta cerrar los controles de seguridad y los permisos.

**Evolución:** [ADR-012](ADR-012-patched-clamav-supply-chain.md) · [ADR-013](ADR-013-inspector-sbom-cve-gate.md) · [ROADMAP](ROADMAP.md) · [PREVIEW_CHECKLIST](PREVIEW_CHECKLIST.md).
