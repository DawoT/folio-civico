# Folio Cívico

**Evidencia para una transferencia ordenada.**

Folio Cívico es una mesa de revisión documental asistida por IA para comisiones de transferencia de gestión en Perú. La comisión constata y valida; la aplicación conserva referencias verificables. **No constituye el aplicativo ni el acta oficial de la Contraloría.**

## Estado real (19 de noviembre de 2026)

- **Implementado:** monorepo TypeScript, reglas de evidencia y permisos, observaciones humanas idempotentes con revisión interna de dos personas, checklist por comisión, migraciones D1, API protegida, ingesta PDF a R2 en cuarentena con SHA-256 e idempotencia, auditoría no destructiva de objetos R2 huérfanos, **outbox D1 y consumidor Queue preparado sin activación**, **inspector aislado de ClamAV/Poppler/Tesseract y gateway privado de Cloudflare Containers, ambos sin desplegar**, **puerta de admisión de texto por páginas con manifiesto HMAC firmado y rehash del original R2**, consulta React de texto autorizado y borradores con citas exactas de versión+SHA-256+página, descubrimiento de comisiones/lotes por membresía y servidor MCP de **solo lectura**.
- **Verificado:** pruebas unitarias y de integración con SQLite real, JWT firmados con JWKS local simulado, llamadas JSON-RPC MCP y aislamiento de comisiones, integración Vitest dentro de workerd (D1/R2 locales), typecheck, compilación React, dry-run de API, MCP, Processor y gateway y migraciones D1 locales. **Smoke real local: 6/6 comprobaciones con ClamAV 1.5.5 firmado, qpdf, Poppler y Tesseract, más 4/4 pruebas HTTP reales.** El inventario CycloneDX y Trivy detectaron **1 crítico, 149 altos y 19 desconocidos** en la imagen final; se aplicó el parche de seguridad de `zlib1g` y se verificó el bloqueo HTTP 503 cuando expiran las tres bases de firmas antivirus. **La imagen sigue bloqueada para Preview y producción**.
- **No implementado todavía:** **resolución o evaluación formal de los CVE críticos/altos de la imagen, procesamiento documental remoto en Cloudflare Containers/Queues, integración E2E con Access/MFA y verificación antimalware/OCR sobre el pipeline real; el smoke local de motores sí pasó**, visor visual del PDF, aprovisionamiento/activación de Queues/cron/DLQ/Workflows, borrado/retención automatizados en R2, verificación sistemática de todos los originales (solo se rehashea el original en la puerta de admisión), firma o aprobación oficial de observaciones, actualización del checklist, exportación DOCX, activación de identidad operadora y alta real de usuarios en Cloudflare Access, OAuth/Access remoto configurado, herramientas MCP de escritura ni despliegue. La interfaz web inicial solo lista y registra PDFs; no permite ver originales de cuarentena.
- **Seguridad de arranque:** los endpoints protegidos deniegan acceso si faltan las variables de Cloudflare Access o la membresía activa de la comisión. No se aceptan identidades enviadas por el navegador.

Ver [plan de ejecución e integración](docs/EXECUTION_PLAN.md), [roadmap](docs/ROADMAP.md), [arquitectura](docs/ADR-001-cloudflare-mcp.md), [decisión de ingesta](docs/ADR-002-r2-intake.md), [autorización y descubrimiento](docs/ADR-003-auth-discovery.md), [borradores con evidencia](docs/ADR-004-human-review.md), [idempotencia y revisión humana](docs/ADR-005-human-decisions.md), [conciliación R2–D1](docs/ADR-006-quarantine-reconciliation.md), [admisión firmada y consulta por página](docs/ADR-007-inspected-text-gate.md), [inspector aislado y colas](docs/ADR-008-isolated-inspector-queues.md), [gateway privado de Containers](docs/ADR-009-private-container-gateway.md), [validación real del inspector](docs/ADR-010-real-inspector-smoke-gates.md), [diagnóstico de cola documental](docs/ADR-011-processing-backlog-audit.md), [actualización de ClamAV y firma del proveedor](docs/ADR-012-patched-clamav-supply-chain.md), [SBOM y gate de vulnerabilidades](docs/ADR-013-inspector-sbom-cve-gate.md), [parche zlib y caducidad de firmas](docs/ADR-014-native-zlib-signature-lifecycle.md), [triaje de CVE nativos](docs/ADR-015-runtime-cve-triage.md), [proyección de checklist validada](docs/ADR-016-validated-search-checklist-projection.md), [detalle y navegación de observaciones](docs/ADR-017-observation-detail-navigation.md), [historial paginado y navegación a evidencia](docs/F2_OBSERVATION_HISTORY.md), [exportación íntegra de revisión interna](docs/ADR-018-finalized-review-export.md), [altas de lotes y checklist por presidentes](docs/ADR-019-president-provisioning.md), [identidad inicial y administración de miembros](docs/ADR-020-commission-identity-membership-lifecycle.md), [E2E funcional local del piloto](docs/F5_LOCAL_PILOT_E2E.md), [navegador real y accesibilidad](docs/F5_BROWSER_E2E_ACCESSIBILITY.md), [cadena documental E2E local](docs/R2_LOCAL_DOCUMENT_PIPELINE_E2E.md), [outbox D1 con reserva atómica](docs/ADR-024-atomic-processing-outbox-leases.md), [triaje y runbook de DLQ](docs/R2_DLQ_TRIAGE_RUNBOOK.md), [conformidad de recuperación en D1](docs/R2_RECOVERY_REVIEW_ATTESTATION.md), [redrive manual individual aislado](docs/R2_MANUAL_ONE_SHOT_REDRIVE.md), [autorización firmada del operador](docs/R2_OPERATOR_SIGNED_AUTHORIZATION.md), [Tesseract mínimo sin libxml2](docs/ADR-021-minimal-tesseract-ocr.md), [CVE y renovación de firmas del OCR](docs/ADR-022-ocr-cve-and-signature-renewal.md), [experimento Poppler sin red](docs/RESEARCH-poppler-minimal-offline.md), [regresión de fuentes PDF sin Fontconfig](docs/RESEARCH-poppler-fontconfig-regression.md), [dossier CVE y componentes fuente](docs/SECURITY_CVE_REVIEW_2026-11-19.md), [registro CVE fuente por huella ELF](docs/SECURITY_NATIVE_ADVISORY_LEDGER_2026-11-19.md), [evidencia de parches y modelos OCR](docs/SECURITY_TESSERACT_SOURCE_AND_MODELS_2026-11-19.md), [integración en main sin habilitar runtime](docs/ADR-023-main-code-integration-runtime-release-gate.md), [rechazo temprano de PDFs cifrados](docs/ADR-025-qpdf-early-encryption-rejection.md), [aislamiento de entorno de parsers y Expat](docs/ADR-026-expat-parser-environment-isolation.md), [guía de Preview](docs/PREVIEW_CHECKLIST.md) y [modelo de evidencias](docs/EVIDENCE.md).

## Demo local guiada (sin Cloudflare)

Para mostrar el recorrido funcional con **API real**, JWT sintéticos firmados, D1 SQLite en memoria y R2 simulado, ejecuta `pnpm install --frozen-lockfile` y `pnpm demo:local` en el equipo de presentación. Abre `http://127.0.0.1:4176/__demo` y cambia entre autor y revisor para demostrar la doble revisión y exportación JSON. El servidor solo escucha en loopback; **no ejecuta OCR/antivirus ni trata datos institucionales**. La verificación automatizada es `pnpm test:demo` y forma parte del CI local. Guion y límites: [demo local guiada](docs/LOCAL_GUIDED_DEMO.md).

## Requisitos

Node 24+ y pnpm 12. Versiones verificadas localmente: Node 26 y pnpm 12.21.

```sh
pnpm install
pnpm test
pnpm typecheck
pnpm build
pnpm test:workers
pnpm test:inspector

# Ensayo E2E funcional sintético: JWT RS256, D1 real local y R2 simulado:
pnpm exec vitest run apps/api/src/pilot-functional.e2e.test.ts

# Ensayo R2 completo con Worker API, outbox, Queue/R2 simulados y gateway real:
pnpm exec vitest run apps/api/src/processing-pipeline.e2e.test.ts

# Instala Chromium una vez en cada host y verifica UI + axe WCAG 2.2 AA:
pnpm exec playwright install chromium
pnpm test:browser

# Gate único de integración local (sin GitHub Actions ni recursos remotos):
sh scripts/ci.sh

# Solo en host local aislado con ≥8 GiB de disco libre, 4 GiB RAM y Docker:
# pnpm test:inspector:docker
# Requisito adicional antes de Preview; salida 2 = CVEs bloqueantes, no éxito:
# pnpm audit:inspector:image
```

El [ensayo documental R2](docs/R2_LOCAL_DOCUMENT_PIPELINE_E2E.md) ejecuta las rutas API reales con JWT firmados, D1 local, Queue/R2 simulados y el gateway de firmado HMAC. **El parser de PDF es sintético**: no equivale a escaneo/OCR real ni aprueba el inspector para despliegue.\n\n`pnpm test:browser` inicia un servidor Vite temporal local, usa Chromium real con API sintética interceptada y revisa tres tamaños de pantalla (1366 px, Pixel 7 y 320 px). **Es obligatorio en `sh scripts/ci.sh`**: si no está instalado Chromium, el gate falla. Ver [límites y metodología](docs/F5_BROWSER_E2E_ACCESSIBILITY.md).\n\n`pnpm test:workers` usa `@cloudflare/vitest-plugin` y requiere que el frontend esté compilado (`pnpm build`). Los objetos R2 y consultas D1 de estas pruebas son totalmente locales, sin acceso a recursos Cloudflare remotos.

La compilación primero construye React con Vite y después ejecuta `wrangler deploy --dry-run` para API, MCP, Processor y gateway privado: **no publica Workers**. El frontend se sirve como Static Assets del Worker API, preservando el mismo origen y evitando CORS entre la aplicación y su API.

### Verificar exportaciones de revisión interna

Tras descargar el JSON desde la comisión, guarda su SHA-256 en un registro independiente y ejecuta:

```sh
node scripts/verify-review-export.mjs folio-civico-COMISION-revision-interna.json
# Exit 0: payload íntegro y estructura reconocida; exit 2: no verificado.
```

La huella **no es una firma digital ni prueba autoría**: la aplicación sigue siendo un insumo de revisión interna. No se generan actas oficiales y se rechazan reportes superiores a 500 decisiones finalizadas u 8 MiB, en vez de truncarlos.

## Cloudflare

La cuenta Cloudflare está compartida con otros proyectos: **no reutilizar D1, R2 ni credenciales de otros proyectos**.

**Bloqueos comprobados:** la auditoría real de la imagen del inspector informa hallazgos críticos/altos sin resolver; además, el operador de `mcp-folio-civico` no tiene configurado Cloudflare Preview. No se ha creado ni desplegado ningún recurso remoto para Folio Cívico. Es necesaria esa configuración para ejecutar pruebas E2E contra recursos reales de Preview.

Los archivos `apps/api/wrangler.jsonc` y `apps/mcp/wrangler.jsonc` tienen el UUID D1 ficticio `00000000-0000-0000-0000-000000000000` y Access sin configurar. Son deliberadamente **no publicables para datos reales**. Antes del primer despliegue de preview:

1. Crear recursos exclusivos `folio-civico-*` (D1 y R2 privado). El nombre de R2 en Wrangler es todavía un placeholder, no un bucket creado.
2. Reemplazar la referencia D1 en ambas configuraciones, con el mismo UUID y nombre.
3. Crear aplicaciones Cloudflare Access protegidas, con IdP y MFA. Habilitar **Managed OAuth para MCP**; definir el dominio de destino y el AUD correcto.
4. Configurar `ACCESS_TEAM_DOMAIN` y `ACCESS_AUD` de cada aplicación, restringir rutas y deshabilitar rutas `workers.dev`/Preview URL hasta disponer de protección.
5. Validar el control de membresía en D1, registrar y auditar el acceso. No insertar datos reales hasta resolver condiciones de residencia, consentimiento y retención.

Para una base local descartable:

```sh
pnpm exec wrangler d1 migrations apply folio-civico-preview --local --config apps/api/wrangler.jsonc
```

**Importante:** los datos locales de API y MCP pueden usar directorios Wrangler distintos. En producción ambos Workers deben enlazar explícitamente a la misma D1 piloto, no a los datos locales.

## Endpoints de la primera iteración

- `GET /health` en la API, sin información institucional.
- `GET /api/commissions`, lista de comisiones según membresía activa del sujeto verificado.
- `GET /api/commissions/{id}/batches`, lista de lotes de una comisión autorizada.
- `POST /api/commissions/{id}/batches`, alta auditada e idempotente de un lote por el presidente de una comisión activa; máximo 100 lotes.
- `GET /api/session`, identidad JWT Access verificada y capacidad de bootstrap sin enumerar otras identidades.
- `POST /api/commissions`, alta inicial por **operador explícitamente configurado**, con primera presidencia, auditoría e idempotencia (denegado por defecto).
- `GET /api/commissions/{id}/members`, listado de miembros activos e inactivos, solo presidencia.
- `POST /api/commissions/{id}/members`, alta/cambio/rehabilitación con `expectedRevision` para concurrencia optimista, auditoría e idempotencia.
- `POST /api/commissions/{id}/members/revoke`, revocación de un tercero por presidencia, sin borrar historial y con control de versión.
- `GET /api/commissions/{id}/summary`, sujeto a JWT de Access y membresía activa.
- `GET /api/commissions/{id}/batches/{batchId}/documents`, listado autorizado sin claves privadas de R2.
- `GET /api/commissions/{id}/checklist`, ítems por comisión, filtrados por membresía.
- `POST /api/commissions/{id}/checklist/items`, alta auditada e idempotente de un ítem pendiente por el presidente, máximo 100 por comisión.
- `GET /api/commissions/{id}/observations`, últimas 50 observaciones y su evidencia por comisión (contrato heredado, sin cambios).
- `GET /api/commissions/{id}/observations/history?limit=25&cursor=...`, historial completo por páginas de hasta 50 observaciones, cursor ligado a la comisión, sin omitir evidencias ni exponer credenciales.
- `GET /api/commissions/{id}/observations/{observationId}`, detalle autorizado del registro exacto, incluso fuera de las 50 recientes, sin exponer claves de idempotencia.
- `GET /api/commissions/{id}/observations/export`, descarga JSON completa de **hasta 500 decisiones internas finalizadas**, con evidencias, revisor y SHA-256 verificable; devuelve error si la exportación quedaría incompleta. No incluye borradores, PDFs ni firma oficial.
- `POST /api/commissions/{id}/observations/drafts`, registro humano de búsqueda no ubicada; JSON con `title`, `description`, `checklistItemId`, `batchId`, máximo 16 KiB y **cabecera obligatoria `Idempotency-Key`**. Se deduplica por comisión+autor+clave y se rechazan reintentos con payload diferente.
- `GET /api/commissions/{id}/documents/{versionId}/pages`, consulta JSON de **texto previamente admitido por un inspector externo**, solo para miembros de comisión autorizados. Nunca sirve los bytes del PDF original.
- `POST /api/commissions/{id}/observations/page-drafts`, borrador humano con `title`, `description`, `documentVersionId`, `page` e `Idempotency-Key`. El SHA-256 y el sujeto revisor provienen de D1/JWT, no del navegador; únicamente permite citar páginas listas.
- `POST /api/commissions/{id}/observations/{observationId}/actions`, transición humana con `Idempotency-Key` y JSON `{action:"submit"}` o `{action:"validate"|"dismiss",note:"justificación"}` (máximo 2 KiB). El autor presenta la propuesta; solo otro miembro/presidente puede decidir, con justificación de 15–1000 caracteres. Auditoría y estados son verificados por D1.
- `POST /api/commissions/{id}/batches/{batchId}/documents` con `Content-Type: application/pdf`, `X-Document-Filename: <filename-URI-encoded>` e `Idempotency-Key`: almacena PDF en cuarentena (máximo 8 MiB) y registra un original con hash SHA-256. Aún no hay descarga ni visor para estos originales.
- `POST /mcp` (Streamable HTTP), con herramientas de solo lectura `list_my_commissions`, `list_commission_batches`, `get_commission_summary` y `get_checklist_status`, sujetas a la misma identidad y membresía.

El presidente de una comisión activa puede **crear lotes, incorporar ítems pendientes, administrar identidades, delegar roles y revocar miembros desde React**, con actor verificado, idempotencia y auditoría atómica. Una identidad operadora Access configurada por separado puede crear la comisión y designar a su primera presidencia; por defecto esa operación está deshabilitada. El aprovisionamiento de cuentas y las políticas de Cloudflare Access siguen siendo administrativos externos. La mesa inicial de React está en `apps/web` y se construye como Static Assets dentro del Worker API. Obtiene comisiones y lotes según la identidad autenticada, lista archivos, recibe cargas (si el rol y estado lo permiten), muestra metadatos y permite registrar un borrador de búsqueda de un ítem del checklist con declaración explícita del revisor. Ahora incluye el envío a revisión y una **decisión interna de un segundo miembro/presidente**, con justificación y auditoría. Tras validar una búsqueda `SEARCH_SCOPE`, la lectura autorizada del checklist presenta **«No ubicado · validación interna»** con observación y revisor verificables: es una proyección informativa de evidencia persistente, **no una modificación del checklist institucional almacenado**. La mesa permite cargar **páginas anteriores de historial**, abrir cada observación mediante **Ver detalle** y consultar una página documental únicamente si está inspeccionada (versión, SHA-256 y página). La opción **Ver validación** abre el expediente de la observación, incluso si ya no figura entre las 50 recientes. **Exportar revisión interna (JSON)** descarga exclusivamente decisiones finalizadas con huella SHA-256; el navegador comprueba la integridad antes de guardar. El panel de evidencia incluye un lector **solo de texto** para páginas previamente admitidas, con citas de versión+SHA-256+página y registro manual de borradores. No produce actas oficiales ni afirma que el OCR o la inspección PDF estén operativos.

La **auditoría interna del procesamiento** clasifica tareas pendientes, reintentos vencidos, agotamiento, rechazos, inconsistencias y registros ausentes; publica únicamente cantidades agregadas cuando un cron autorizado la invoque. No ofrece endpoint público ni reenvía mensajes, y se documenta en la [ADR-011](docs/ADR-011-processing-backlog-audit.md).

La carga PDF crea en D1 un trabajo de procesamiento persistente (outbox). El consumidor Cloudflare Queues vive en `apps/processor`; el inspector Python de ClamAV/Poppler/Tesseract está en `apps/inspector`; el nuevo gateway `apps/inspector-gateway` usa la API moderna de Cloudflare Containers con Durable Objects. **En Cloudflare, el contenedor recibe solo el token de servicio, nunca la clave HMAC**: el gateway firma el manifiesto validado antes de entregarlo al consumidor. **Ninguna Queue, cron, instancia Container, secreto ni servicio externo se ha desplegado**. El modo activo del gateway carece de Container binding; la configuración propuesta está en `wrangler.container.example.jsonc`. Las pruebas regulares de Python usan motores simulados. **El smoke `pnpm test:inspector:docker` sí se ejecutó con ClamAV 1.5.5, qpdf, Poppler, Tesseract y firmas oficiales sobre PDFs sintéticos: 6/6 comprobaciones aprobadas, exit code 0.** La imagen exige y valida el paquete firmado por Cisco Talos mediante GPG antes de instalarlo, y rechaza motores antiguos en salud y admisión. Incluye extracción PDF nativo, OCR de un PDF puramente raster, rechazo de PDF dañado/cifrado/con adjunto y detección EICAR. El preflight originalmente impidió el build por disco insuficiente; cuando el almacenamiento volvió a estar disponible se construyó y ejecutó una imagen local aislada, sin red en tiempo de inspección. La validación local adicional ejercita el HTTP real del inspector sin red: salud, token inválido, manifiesto sin HMAC y hash forjado. **No incluye un deploy ni la cadena real Queue → Container → D1**. Ver [ADR-010](docs/ADR-010-real-inspector-smoke-gates.md) y [ADR-012](docs/ADR-012-patched-clamav-supply-chain.md).

El contrato `publishInspectedText` **no es un endpoint HTTP ni una herramienta MCP**. Requiere un manifiesto externo `clean` firmado con HMAC, reabre el PDF original privado en R2 solo para verificar su SHA-256, y publica texto de hasta 100 páginas en D1 con auditoría y transacción atómica. **Los motores reales aprobaron el smoke local con datos sintéticos, pero no se han desplegado ni vinculado a Queue/gateway en Cloudflare**; los archivos entrantes permanecen en cuarentena.

El Worker API incluye un manejador interno de conciliación programada de cuarentena. **Sin cron configurado, permanece desactivado**: nunca responde por HTTP ni MCP, no elimina objetos y solo registra métricas agregadas. Sus resultados son diagnósticos de metadatos, no un análisis físico de los PDFs; ver [ADR-006](docs/ADR-006-quarantine-reconciliation.md).

El MCP acepta llamadas stateless en el protocolo moderno (cabeceras y sobre `_meta` pertinentes), no expone CORS y deniega solicitudes con `Origin`. Las pruebas JSON-RPC se realizan con una identidad de prueba inyectada y **no acreditan una sesión OAuth real**.

El MCP **no** admite acciones de aprobación, eliminación, firma, envío a la Contraloría ni acceso directo a SQL/R2.

## Entrega

No se despliega a producción desde este repositorio sin autorización expresa. Los workflows de CI deben compilar, probar y comprobar migraciones locales. El piloto inicia exclusivamente con documentación ficticia o anonimizada.
