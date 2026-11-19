# ADR-023 · Integración de código de seguridad en main sin liberar el inspector

**Fecha:** 2026-11-19 (America/Lima)
**Estado:** decisión de integración de código **sin desplegar**; **NO** autorización de ejecución remota, Preview ni producción.

## Contexto

Los cambios R1.2–R1.5 del inspector ya tienen pruebas de motores, OCR, HTTP, firma de ClamAV y cobertura de procedencia, pero el escaneo Trivy sobre las imágenes locales continúa **bloqueado, exit 2**: la candidata OCR tiene 0 CRITICAL / 128 HIGH / 19 UNKNOWN y la variante experimental Poppler 0 / 70 / 19. Además, Tesseract y Poppler compilados desde fuente no disponen de cobertura CVE completa. No existe VEX formal aprobado. El usuario solicita integrar el código de esta investigación en `main` sin dejar de preservar las condiciones de seguridad.

## Decisión

**Se permite fusionar el código, las pruebas, las utilidades de auditoría y la documentación en `main`** tras la aprobación del CI, únicamente como base de trabajo y trazabilidad de ingeniería. Esta acción **no autoriza**:

- Construir/publicar una imagen aprobada de inspector, sustituir la etiqueta local `validation` ni declarar un digest listo para operar.
- Crear o modificar recursos, rutas, Workers, Containers, Queues, D1, R2 o secretos de **Cloudflare**, ni realizar migraciones remotas.
- Activar **Preview**, procesar PDFs institucionales reales, omitir el gate de CVE, emitir VEX sin aprobación o desplegar en producción.
- Confundir `sh scripts/ci.sh` con autorización para liberar el runtime: **el test de CI general no ejecuta el gate pesado Trivy**.

El único workflow GitHub Actions del repositorio (`.github/workflows/ci.yml`) usa permiso `contents: read` y ejecuta `sh scripts/ci.sh`. Los scripts `build` de los cuatro Workers usan exclusivamente `wrangler deploy --dry-run --outdir dist`; las migraciones de ese CI usan `--local`. No hay automatización de despliegue en ese workflow verificado. No se asume que sistemas externos no inventariados tengan el mismo comportamiento.

El `Dockerfile` principal conserva su carácter de candidato no aprobado. `Dockerfile.poppler-experiment` sigue siendo un **experimento no desplegable**, requiere una imagen candidata local para compilar y no modifica ninguna configuración de Cloudflare. El escaneo `apps/inspector/audit_image.sh` debe devolver **exit 2** ante HIGH/CRITICAL/UNKNOWN o motores nativos sin cobertura de advisories aprobada, y **exit 3** si faltan los informes o falla el inventario.

## Criterios obligatorios para un futuro lanzamiento del inspector

1. CVE del runtime resueltos mediante versiones corregidas verificadas, o evaluación individual/VEX de alcance probado, propiedad y vigencia aprobadas; nunca exenciones automáticas.
2. Cobertura de advisories para Tesseract y Poppler construidos desde fuente, incluyendo sus hashes ELF y dependencias. Cerrar la brecha entre identidad del componente y cobertura de CVE.
3. Imagen final limpia y mínima (sin paquetes descartados conservados en capas anteriores), con SBOM verificable y el gate estricto aprobado.
4. Pruebas PDF/OCR con corpus representativo y casos adversarios, además de la paridad sintética. Mantener 6/6 motores, 4/4 HTTP, tests unitarios, typecheck, builds y CI.
5. Firma de proveedor, actualización automática de firmas ClamAV antes de 72 h, recuperación ante fallos, rollback, artefacto por digest y aprobación explícita del entorno remoto.
6. Autorización independiente para cualquier despliegue, migración remota, gasto o uso de datos institucionales.

La decisión mantiene el bloqueo de publicación, pero permite la **integración en main de la investigación y herramientas de seguridad**. El PR y sus checks de integración no deben presentarse como autorización de release.

## Verificación y referencias

```sh
sh scripts/ci.sh
bash apps/inspector/audit_image.sh --candidate
bash apps/inspector/audit_image.sh --experiment --triage --advisories
```

El primer comando es un control de integración; las otras dos órdenes son controles de release y deben seguir devolviendo exit 2 hasta resolver sus condiciones. Ninguna orden publica un artefacto.

Véase [ADR-013](ADR-013-inspector-sbom-cve-gate.md), [ADR-022](ADR-022-ocr-cve-and-signature-renewal.md), [dossier CVE R1.5](SECURITY_CVE_REVIEW_2026-11-19.md), [investigación Poppler](RESEARCH-poppler-minimal-offline.md) y [checklist de Preview](PREVIEW_CHECKLIST.md).
