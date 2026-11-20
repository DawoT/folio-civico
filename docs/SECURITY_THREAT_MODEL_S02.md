# S02-01 · Modelo de amenazas y matriz de pruebas negativas — Folio Cívico

**Corte:** 2026-11-20 (America/Lima). **Código base de auditoría:** `origin/main@d275a99c8ac235b336cdb107c4026054374893c4`. **Reconciliación posterior:** rama sincronizada con `origin/main@17e06fe4f0981158cc0b0554d7c2ed8e37b5fc19` (PR #77 de procedencia util-linux fusionado; sigue siendo investigación sin autorización de runtime). Las pruebas y certificaciones se atribuyen a cada SHA, no a una versión genérica. **Objeto:** revisión transversal del código y plan de pruebas de seguridad por confianza. **Estado:** `analyzed / tests-to-execute`, no certificación ni habilitación de Preview. **Coordinación:** `docs/AGENT_TDD_SPRINT_ROADMAP.md` S02/G2/G3/G4; ADR-023 y `docs/PREVIEW_CHECKLIST.md` prevalecen para liberaciones.

## 1. Premisas verificadas

- **API real:** `apps/api/src/index.ts` exige `authenticateAccess` para toda ruta `/api/**` reconocida. `GET /health` es liveness pública que devuelve `{"status":"ok"}` independientemente de D1/R2/Queue; **no es readiness operativa**. Wrangler activo tiene `ACCESS_TEAM_DOMAIN` y `ACCESS_AUD` vacíos y un ID D1 placeholder, por lo que falla cerrado hasta configuración aprobada.
- **Identidad:** `packages/auth/src/access.ts` obtiene JWKS del issuer HTTPS `*.cloudflareaccess.com` y exige JWT verificable con issuer y audiencia específicos. Ser titular de un token Access no confiere membresía o rol; la autorización fina vive en consultas D1 por `subject`, comisión, membresía activa, rol y estado.
- **Dominio:** `packages/domain/src/permissions.ts` distingue president/member/advisor/observer. `packages/data/src/transitions.ts` exige autor distinto de revisor para decisiones; triggers `migrations/0006*`, `0007*`, `0009*` y posteriores conservan reglas de transición/evidencia aun si el Worker intenta SQL incorrecto.
- **Cuarentena:** `apps/api/src/document-routes.ts` guarda PDF en una clave aleatoria privada `quarantine/*` y reintenta idempotentemente. `packages/data/src/inspected-text.ts` solo admite páginas tras verificación de HMAC, rehash del original R2, manifiesto `clean` y atomicidad SQL. No se sirve el PDF original en navegador.
- **Pipeline:** `apps/processor/src/consumer.ts` valida mensaje de cola, identidad de versión/hash, estado de comisión, autorización de redrive, bytes R2 y veredicto; `apps/inspector-gateway/src/route.ts` limita cuerpo y respuesta, exige token de servicio, firma HMAC fuera del Container y no reenvía detalles privados. `apps/inspector/inspector.py` ejecuta ClamAV, qpdf, Poppler y Tesseract en un recinto aislado (candidato, no liberado).
- **Operador privilegiado:** `apps/operator/src/isolated-host.ts` es un adaptador **solo sintético** sin `default ExportedHandler`, `wrangler.jsonc` ni hostname remoto. Revocaciones y redrive requieren autorización, firmas y registros institucionales independientes; **no existe un host real aprobado**.
- **MCP:** `apps/mcp/src/index.ts` expone cuatro herramientas de lectura limitadas por miembro, rechaza `Origin` y no habilita CORS. **OAuth remoto no está verificado**.
- **Exportación:** JSON SHA-256 comprueba integridad del payload, **no prueba la autenticidad del emisor**, validez jurídica ni firma. Los PR #67 y #58 reforzaron la forma del payload; se requieren nuevas pruebas contra identidad y datos de otra comisión si se amplía el formato.
- **Despliegue:** no hay contenedor/Queue/cron habilitados en Wrangler activo; CI actual ejecuta builds `--dry-run` y migraciones `--local`. GitHub `main` no estaba protegido al consultar el API de branch protection; issue #72. Imagen inspector bloqueada por CVE/procedencia pendiente; issue #75 y ADR-023. No se ha realizado ensayo remoto end-to-end.

**Disciplina de evidencia:** el código observado se marca `C`; una prueba local realmente ejecutada se marca `L`; `R` solo tras prueba en recursos Preview exclusivos; `H` solo tras aprobación humana. Nunca convertir `C/L` en `R/H` por inferencia.

## 2. Activos, actores y límite de confianza

| Activo | Integridad / confidencialidad buscada | Autoridad que decide |
| --- | --- | --- |
| Identidad y membresía de comisión | Ninguna elevación por headers del navegador ni mezcla de tenants | Access para identidad; D1 para rol y comisión |
| PDF original y hash SHA-256 | Solo R2 privado, contenido inmutable para admisión | API de ingesta; inspector externo seguro |
| Texto extraído y cita por página | Solo `clean`, versión/hash/página exactos | Gateway HMAC y D1 admission gate; persona revisora |
| Observación, checklist y decisión | Separación autor/revisor, auditoría y no autovalidación | D1/triggers + humano distinto |
| Cola, outbox y redrive | At-least-once sin perder ni inventar `ready` | Processor + D1 + autoridad de redrive |
| Exportación interna | Completa, no truncada ni falsamente autenticada | Worker; cliente/verificador independiente |
| HMAC, token inspector, claves de aprobación | Secretos fuera de cliente, PDF y logs | Operator/Cloudflare secrets; firmas externas aprobadas |
| Métricas, logs, backups | No filtrar nombres/identidades/bytes del expediente | Operador designado y política institucional |

### Flujo resumido con fronteras

`Browser (no confiable) → Cloudflare Access (IdP externo) → API Worker (JWT validado) → D1 (tenancy/roles/triggers)`

`Browser → API Worker → R2 quarantine (PDF no confiable) → outbox D1 / Queue → Processor → Gateway privado (HMAC) → Container aislado (parser no confiable) → Gateway (manifiesto) → D1 admission gate → páginas inspeccionadas / revisión humana`

`MCP client server-to-server → Access JWT / [OAuth futuro] → MCP read-only → D1 scoped`

`Host operador futuro (NO existe) → autoridades humanas/firma independiente → D1 journal de aprobación/revocación → redrive opcional Queue`

Una ruta no adquiere confianza porque un componente previo la autorizó: revalidar `subject`, scope, estado y firma **en el punto de uso**. En pruebas de carrera, inspeccionar la atomicidad de las decisiones críticas en D1.

## 3. Registro de amenazas STRIDE y controles verificables

| ID / clase | Ruta o abuso | Control implementado / evidencia | Riesgo residual y criterio RED | Estado |
| --- | --- | --- | --- | --- |
| **T01 / Spoofing** | Header `Cf-Access-Authenticated-User-Email` forjado, JWT expirado, JWKS rotado, issuer/audiencia cruzados | `auth/access.ts`; `apps/api/src/index.test.ts`; `packages/auth/src/access.test.ts` | Probar Access/IdP reales y rotación; no aceptar identidad de body/header no verificado | C+L; R pendiente |
| **T02 / Elevation** | Llamar ruta de otro tenant, comisión cerrada, miembro revocado o rol observer que intenta mutar | Consultas D1 y `assertMemberPermission`; pruebas de acceso de rutas y PR de miembro | Matriz de roles completa y revocación concurrente; `403/404/409` sin filtrar metadatos | C+L parcial; R pendiente |
| **T03 / Tampering** | Editar observaciones/evidencia después del envío, autovalidarse, crear aprobación sin revisión independiente | `transitions.ts` + triggers D1 `0006–0007`; pruebas E2E de revisión | Inyección SQL directa de mantenimiento, corrupción de estado, carrera entre permisos/validación: siempre denegar | C+L; R pendiente |
| **T04 / Repudiation** | Doble `POST` mismo idempotency key, evento de auditoría duplicado o perdido | Request key, índices SQL y audit events; pipeline real local | Pruebas concurrentes reales D1/Queue y consistencia de conteos; estado `uncertain` no equivale a éxito | C+L parcial; R pendiente |
| **T05 / Information disclosure** | Leer objeto de cuarentena, nombre/clave en JSON o log, XSS por texto OCR, exportar otro tenant | R2 privado, respuesta mínima, React renderiza texto sin HTML, hash/version/page, headers `no-store` | Probar CSP, URLs públicas R2, política de bucket, logs y tecnología asistiva en Cloudflare real | C+L; R pendiente |
| **T06 / DoS** | PDF muy grande, zip/attachments, páginas de coste extremo, CPU/memoria, raster gigante, retorno inspector desmesurado | Límites 8 MiB/100 páginas, timeout, qpdf/ClamAV, response cap 2 MiB | Gate de geometría raster (issue #68), corpus adversarial y cuotas/costo; no certificar límite de memoria solo por tamaño de bytes | C+L parcial; G2 bloqueado |
| **T07 / Tampering** | Simular `clean`, cambiar R2 bytes, HMAC inválido, repetir verdict de otra solicitud | HMAC firmado por Gateway, rehash, nonce / manifests, SQL admission + checks de identidad | Probar en Preview con service binding real y certificados/secrets rotados; 0 falsos `ready` | C+L; R pendiente |
| **T08 / Elevation** | Parser subvertido intenta acceder a HMAC, red externa, privilegios o datos de otro documento | Contenedor separado sin HMAC, configuración sin Internet, no root, seccomp/read-only en pruebas Docker | Repetir smoke en imagen y Cloudflare Container EXACTOS; seguridad CVE/DSO/native advisory abierta | C+L histórica; G2 bloqueado |
| **T09 / DoS/Repudiation** | Queue duplicada, crash después de reservar, DLQ sin operador, redrive vencido/revocado | Outbox D1 CAS/lease, expiración y revocación, journaling SQL, `consumer.ts` | Reconciliación real, observabilidad de 4 días DLQ y aprobaciones independientes. No redrive automático | C+L; R/H pendiente |
| **T10 / Spoofing/Elevation** | Host de operador con privilegio implícito, consentimiento simulado, autoaprobación de redrive | `isolated-host.ts` modo sintético; JWS + comprobación de distintas identidades y estado | No habilitar endpoint real sin IdP/MFA, segregación, autoridades y plan de respuesta a revocación | C+L; HOST ausente |
| **T11 / Tampering** | Reporte con SHA-256 válido pero evidencia falsificada de otro tenant o revisor igual a autor | Export offline y navegador con validador compartido (PR #67) | Corroborar identidad del emisor por mecanismo distinto de hash; test de semántica de firma si se integra DOCX | C+L; R/H pendiente |
| **T12 / Spoofing/Disclosure** | Cliente MCP intenta contexto de otra comisión, OAuth omitido o browser usa cookies contra MCP | Solo lectura con `subject` Access, sin CORS y `Origin` denegado | OAuth 2.0 y scopes en Preview, cliente no-browser autenticado, revocación y tenant leak bajo fuzzing | C+L; R pendiente |
| **T13 / Supply chain** | Dependencia o binario fuente con CVE desconocido, imagen escaneada distinta de desplegada, firmas AV caducadas | SBOM/Trivy, hashes ELF, firmas ClamAV, gate separado | `pnpm audit:inspector:image` y `test:inspector:docker` sobre mismo digest, CVE/VEX avalado; 72h y rollback | C+L parcial; G2 bloqueado |
| **T14 / Information disclosure** | Logs y métricas contienen sujetos, PDF, clave R2, hashes o JWT | Auditorías agregadas de `maintenance.ts`, resultantes mínimos del Gateway | Captura de logs de error/stack y trazas de proveedores reales con corpus sintético marcable; cero detalles en salida | C+L parcial; R pendiente |
| **T15 / SSRF/route abuse** | Inspección HTTP a destino suministrado por usuario o exposición de Container DO | Gateway usa forwarder interno fijado y Service Binding opcional; sin Container binding en Wrangler activo | Confirmar ausencia de `workers.dev`, rutas públicas, redirects y puertos inseguros en el deployment real | C+L; R pendiente |
| **T16 / Confusión operacional** | `/health` devuelve OK con D1/Queue/Container ausentes; un reintento PDF reporta `pending` tras estar `ready` | `/health` es liveness; corrección de estado del PR #73 **fusionada en `main`**; PR #76 agrega regresiones de carrera y aislamiento | Diseñar readiness interno por capacidad, no proclamar «operativo» a partir de liveness; pruebas de estados e integridad | Brecha registrada S01 |

La clase STRIDE es una heurística de investigación; **no** es un informe de explotación ni una clasificación CVSS. La falta de prueba remota no implica que se haya vulnerado un control, solo que **no está demostrada** su efectividad en ese entorno.

## 4. Matriz de pruebas negativas ejecutable por agentes (RED → GREEN)

Para cada fila, crear un test reproducible que primero falle por el comportamiento no cubierto, añadir corrección mínima solo si se descubre defecto y preservar controles actuales. Los tests que ya existen se conservan: no duplicar aserciones por cantidad.

| ID | Fixture / recorrido mínimo | Resultado exigido | Pruebas iniciales |
| --- | --- | --- | --- |
| N01 | JWT RS256 con `aud` ajeno, `iss` ajeno, vencido, firma errónea, `kid` rotado | `401`, sin D1 ni cuerpo sensible | `packages/auth/src/access.test.ts`, `apps/api/src/index.test.ts` |
| N02 | Acceso mismo documento de comisión B desde sujeto miembro solo de A; acceso revocado durante lectura | `404` uniforme, sin datos/clave privada | `apps/api/src/document-routes.test.ts`, `packages/data/src/inspected-text.test.ts` |
| N03 | Autor intenta aprobar su registro, advisor/observer modifican, comisión cerrada entre consulta y UPDATE | Prohibido en API y en trigger SQL | `packages/data/src/transitions.test.ts`, `apps/api/src/pilot-functional.e2e.test.ts` |
| N04 | Upload repetido `pending → processing → ready/needs_review/failed`, mismo key con hash diferente | Sin duplicado, estado informado real, hash alterado `409` | PR #73 fusionado: `document-routes.test.ts`, `processing-pipeline.e2e.test.ts`; PR #76 amplía colisiones |
| N05 | Queue reentrega 2 veces, DLQ, cron sin binding, fallo antes/después del envío y revocación de redrive | Una sola admisión/auditoría y estados no falsos | `apps/api/src/processing-pipeline.e2e.test.ts`, `apps/processor/src/consumer.test.ts` |
| N06 | Respuesta inspector alterada, `clean` sin HMAC, hash R2 distinto, nonce replay, 422 sin firma | No `ready` ni `needs_review` sin veredicto autenticado | `apps/inspector-gateway/src/route.test.ts`, `packages/data/src/inspected-text.test.ts` |
| N07 | PDF cifrado, adjunto, EICAR, truncado, raster enorme, página mixta, fuentes/Unicode adversarios | Denegación/abstención segura o texto completo verificable | `apps/inspector/tests`, `smoke_real_engines.py`, R1.33 investigación integrada en código (PR #74), bloqueo de imagen #75 |
| N08 | Export con hash recalculado, revisor igual a autor, evidencia cruzada, versión incorrecta, >500 | No descargar ni decir «verificado»; no truncar | `tests/verify-review-export.test.ts`, `tests/browser/review-export-receipt.spec.ts` |
| N09 | Captura de logs durante D1/R2 offline, token inválido, PDF corrupto, scanner 503 | No JWT, `sub`, nombres, claves, contenido ni tracebacks | `apps/api/src/maintenance.test.ts`, `apps/inspector-gateway/src/route.test.ts` |
| N10 | MCP cliente browser con `Origin`, sin JWT, sin membresía, comisión ajena | `403/401`, error mínimo, sin herramientas de escritura | `apps/mcp/src/index.test.ts` |
| N11 | Operador sin privilegio, JWS alterado/expirado, aprobación del propio actor, revocación concurrente, Queue ambigua | 403/409/503 y diario `uncertain` sin segundo send | `apps/operator/src/*.test.ts`, `migrations/0029*` |
| N12 | Simular la falta de un binding en deployment de Preview / imagen CVE no aprobada | Readiness no operativo, **no** habilitar ingesta/Container | Nuevo test R3 pendiente; gate inspector separado |

### Orden de implementación y criterios de salida

1. **G0 primero:** branch protection/ruleset con PR/check/2º revisor; issue #72. Hasta entonces la gobernanza por PR es una disciplina, **no una garantía de servidor Git**.
2. **G1 APP:** cerrar N01–N04 y N08–N10 que no requieren cloud remoto; mantener `sh scripts/ci.sh` y Playwright. Reportar líneas ejecutadas y casos ausentes; no usar porcentaje de cobertura global inventado.
3. **G2 INSPECTOR:** cerrar N06–N07, N13 con imagen exacta, SBOM/CVE, motores reales y aprobación VEX responsable; issue #75. Todo `exit 2` sigue bloqueando.
4. **G3 PREVIEW:** aprobar infraestructura y ejecutar N01–N12 sobre recursos privados aislados, incluyendo condiciones de carrera y revocación reales; no compartir recursos con otros productos.
5. **G4–G6:** comprobar fidelidad de página y lectura, usabilidad, autorización institucional, retención y incidentes antes de datos reales o IA generativa.

### Métricas sin incentivos perversos

- **Tolerancia cero** en pruebas: admisión de PDF sin inspección limpia firmada, acceso a otro tenant, autovalidación, evento duplicado por reintento, versión/listado contradictorio, filtración en logs, export falsamente autenticado, redrive sin autoridad.
- **No forzar cero CVE escaneado** mediante desactivar escáner, saltar fuentes compiladas, ocultar `UNKNOWN` o aceptar VEX inventado. Medir CVE por digest/veredicto y decisión humana.
- **No prometer** conformidad ASVS completa: el checklist objetivo es ASVS 5.0 nivel L2 y controles L3 pertinentes a autenticación, autorización, integridad y secretos, con evidencia para cada requisito aplicable. Sin auditoría control por control, marcar `not_assessed`.
- **No inferir** métricas de usuarios o disponibilidad remota desde Playwright sobre datos sintéticos.

## 5. Política de cambios y trazabilidad

Un agente debe adjuntar por cada hallazgo: `threat_id`, `scenario`, `SHA`, `affected_trust_boundary`, `negative_test`, salida RED, evidencia GREEN, resultado de `sh scripts/ci.sh`, CI GitHub, riesgo residual, decisión y rollback. Solo el titular y autoridades competentes aprueban infraestructura, VEX, procesamiento de datos reales, cambios legales o release.

**Validación de documento:** rutas de código contrastadas con la fuente del snapshot; el documento es un artefacto de **análisis de riesgos** y una lista de pruebas futuras, no un registro de que N01–N12 se ejecutaron en Preview. Antes de iniciar cada ticket, comparar contra el HEAD actual y los PR/branches concurridos; preservar PR #73 ya fusionado, coordinar PR #76 y no duplicar investigación del inspector. Mantener la marca y la distinción entre validación interna y aprobación oficial.

**Referencias internas:** `docs/AGENT_TDD_SPRINT_ROADMAP.md` · `docs/EXECUTION_PLAN.md` · `docs/ADR-023-main-code-integration-runtime-release-gate.md` · `docs/PREVIEW_CHECKLIST.md` · `docs/R2_ISOLATED_OPERATOR_HOST.md` · `docs/R2_ATOMIC_INSPECTION_AUDIT.md` · `docs/F5_BROWSER_E2E_ACCESSIBILITY.md`.
