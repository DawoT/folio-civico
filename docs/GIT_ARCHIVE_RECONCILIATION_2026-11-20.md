# Reconciliación de referencias históricas · Folio Cívico

**Corte de clasificación:** 2026-11-20 (America/Lima), sobre `main@79425d47c691`.
**Objeto:** consolidar contenido aún útil, evitar reintroducir implementaciones antiguas y retirar worktrees/ramas redundantes sin perder trazabilidad.
**Contrato de integración:** `sh scripts/ci.sh` local con exit 0, independiente de GitHub Actions. No hay aprobación de Preview ni de ejecución de imágenes del inspector.

## Criterio

Se inspeccionaron las 14 referencias locales de archivo en `refs/archive/folio-hygiene-2026-11-20/` con comparación de commits y rutas presentes en `main`. La no equivalencia de SHA no prueba funcionalidades pendientes: muchos cambios se integraron en versiones posteriores o mediante otra topología. No se fusionan ramas completas con conflictos antiguos, ni se sustituyen implementaciones actuales por versiones archivadas.

| Referencia histórica (SHA abreviado) | Resultado de reconciliación |
| --- | --- |
| `feat/dlq-manual-triage` (`9cb2b25`) | Módulos, prueba y runbook DLQ ya presentes en `main`; mantener la implementación más reciente |
| `feat/manual-redrive-one-shot` (`981ed89`) | Módulo y migración 0019 ya presentes; no restaurar lógica anterior de redrive |
| `feat/manual-redrive-signed-authorization` (`68726f3`) | Código de autorización y migración 0020 presentes; preservar el contrato actualizado |
| `feat/private-operator-host-r29` (`01a63e3`) | Adaptador aislado y pruebas presentes; sin activación de host remoto |
| `feat/recovery-review-attestation` (`27bba82`) | Módulo de revisión y migración 0018 presentes |
| `feat/revocation-registration-approval` (`1da0405`) | Autorización y migración 0022 presentes; conservar controles posteriores |
| `feat/s01-03-operator-readiness` (`94b0a46`) | Prototipo de ruta `/api/internal/readiness` **no integrado** por duplicar `/api/readiness/core`. Se incorpora solamente su requisito de tablas `checklist_items` y `observations` al gate existente |
| `fix/ci-task-scroll-diagnostics` (`de5ba1e`) | Telemetría y pruebas de navegación presentes en `main`; evita restaurar código o workflow antiguos |
| `fix/s01-api-storage-readiness` (`870b1da`) | Prototipo de readiness R2 independiente, no incorporado al gate `api-core`: este último **no** certifica R2/Queue/Container ni Preview |
| `fix/s01-upload-replay-status` (`e60d3f6`) | Respuesta de idempotencia con estado `processingStatus` actual ya presente |
| `fix/s05-ocr-media-preflight` (`407548a`) | Preflight MediaBox ya presente con validación más extensa en `apps/inspector/inspector.py`; no reemplazarlo |
| `research/ocr-minimal-cve` (`bf1efef`) | Candidato de investigación Tesseract antiguo, no desplegable y no integrado; fuente preservada en recuperación Git |
| `security/poppler-full-overlay-r120` (`c32e8ea`) | Experimento de sexto overlay y corrección de rutas de manifiestos, no integrado: pruebas focalizadas del orquestador no prueban la paridad PDF completa ni remediación CVE |
| `test/browser-accessibility-pilot` (`21d7116`) | Pruebas de piloto Playwright/accesibilidad y CI shell ya presentes, con implementaciones evolucionadas |

**Nueva consolidación de código:** `GET /api/readiness/core` continúa siendo la única sonda privada autorizada por identidad Access y operador configurado. Su verificación D1 requiere ahora **13** objetos, incluyendo `checklist_items` y `observations`. Si falta cualquiera, responde `503` genérico y no divulga datos de SQL. El endpoint alternativo del archivo permanece inexistente. No se cambia la definición pública de `GET /health`.

## Custodia y limpieza

- Antes de retirar ramas y worktrees se verificaron los bundles Git históricos del repositorio. Las referencias de archivo locales son un paso temporal de custodia, **no ramas activas**.
- Los cuatro trabajos históricos con remotos divergentes se conservaron mediante tags anotados en GitHub: `archive/folio-civico/2026-11-20/{ci-task-scroll-diagnostics,s01-api-storage-readiness,s05-ocr-media-preflight,ocr-minimal-cve}`. Un tag de archivo conserva el commit, pero **no implica que su código esté integrado en main**.
- **Respaldo consolidado verificado:** `.git/folio-civico-recovery-2026-11-20.bundle`, que cubre los 150 commits raíz identificados entre los dos bundles históricos. Se retiraron las 14 referencias locales de archivo solo después de verificar sus SHA contra el respaldo; los bundles antiguos redundantes se eliminaron tras verificar la cobertura completa. El archivo no se publica y debe conservarse como respaldo operativo; su pérdida junto con `.git` podría volver irrecuperables los prototipos sin tag remoto.
- No confundir eliminación de dependencias/artifacts de CI regenerables con borrado de D1 local, secretos, archivos institucionales o datos de investigación no publicados. La limpieza no toca `.mcp-gpt`, repositorios vecinos ni el almacén global pnpm.

## Puertas de calidad y riesgos que permanecen

Las pruebas de integración son locales y sintéticas. El gate CVE del inspector, la cobertura de advisories de binarios compilados, el análisis de paridad PDF adversaria, la configuración real de Access/D1/Queue y la autorización institucional siguen independientes y bloqueantes para desplegar o procesar documentos reales. La integración de un requisito de readiness no equivale a certificación de disponibilidad en Cloudflare.
