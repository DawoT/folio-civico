# Roadmap de ingeniería · Folio Cívico

Actualizado: 2026-11-18. Alcance de piloto: municipalidad distrital, obras y contrataciones, PDF nativo/escaneado.

| Fase | Resultado | Dependencias | Estado |
| --- | --- | --- | --- |
| P0 | Monorepo, TypeScript, vitest, CI y documentación | Acceso al repositorio | **Completado como fundación** |
| P1 | D1, autorización, evidencia, auditoría y contratos | P0; matriz de roles | **Parcial: evidencia persistente, idempotencia, auditoría y validación interna de dos personas; entorno real pendiente** |
| P2 | Mesa React, PDF, R2 en cuarentena, checklist y borradores | P1 | **Parcial: mesa, R2, decisiones y lector de texto inspeccionado; smoke antivirus/OCR local aprobado, pero pipeline remoto y visor PDF pendientes** |
| P3 | Queues/Workflows, extracción, OCR por página e IA supervisada | P2; dataset anónimo | **Parcial: outbox/Queues, inspector y gateway preparados; ClamAV 1.5.5 firmado y smoke local 6/6 + HTTP real aprobados, pero escaneo CVEs integral, despliegue, operación y E2E remotos pendientes** |
| P4 | MCP OAuth y herramientas de lectura/escritura controladas | P1 y Cloudflare Access | **Parcial: servidor de lectura sin despliegue** |
| P5 | DOCX, E2E, seguridad, retención, medición del ahorro | P2–P4; aprobación legal | Pendiente |

## Método TDD

Cada incremento: (1) caso de aceptación y prueba fallida; (2) implementación mínima; (3) refactorización; (4) tests + typecheck + dry-run build; (5) registro de resultados y riesgos. Las migraciones se verifican en D1 local antes de cualquier aplicación remota.

## Entrega actual: P0/P1i + P2f + P3f + P4b

- [x] Tests que rechazan permisos entre comisiones, sujetos incorrectos e inactivos.
- [x] Dos clases de evidencia documental diferenciadas: página existente y alcance de búsqueda sin resultado; soporte para fuente oficial.
- [x] Borrador de observación sin autovalidación ni evidencia cruzada.
- [x] Repositorio D1 de resumen con condición de comisión y sujeto.
- [x] Verificación JWT de Cloudflare Access con firma, audiencia y emisor.
- [x] API protegida y MCP con una herramienta de solo lectura.
- [x] Migración inicial en D1 local.
- [x] Compilación dry-run de los Workers API, MCP, Processor y gateway, sin despliegue.
- [x] Recepción de PDF a R2 privado bajo `quarantine/`, límite 8 MiB, firma, hash y nombre saneado.
- [x] Claves de idempotencia por comisión; transacción D1 para documento/versión/auditoría y limpieza compensatoria de R2.
- [x] Listado autorizado de documentos del lote sin exponer las claves de objetos.
- [x] Mesa React inicial con consulta y carga, empaquetada como Static Assets del mismo Worker API.
- [x] Pruebas de roles, idempotencia y fallo de almacenamiento con SQLite real y R2 simulado.
- [x] Descubrimiento de comisiones y lotes filtrado por identidad y membresía activa, sin rutas de mutación.
- [x] Interfaz de selección de comisión/lote por listado autorizado; carga inhibida para rol observador/comisiones cerradas.
- [x] JWT firmado con JWKS simulado: emisor, audiencia y expiración; caché de claves por Worker.
- [x] MCP JSON-RPC moderno probado: `tools/list`, catálogo de comisiones, consulta autorizada y acceso cruzado rechazado; CORS deshabilitado y `Origin` bloqueado.
- [x] Herramientas MCP de solo lectura `list_my_commissions`, `list_commission_batches` y `get_commission_summary`.
- [x] Suite de integración con `@cloudflare/vitest-plugin` usando runtime workerd local, R2 y D1 locales.
- [x] Lectura del checklist y de observaciones vinculadas a una comisión, con estado y evidencia en JSON.
- [x] Registro humano de búsquedas no ubicadas como **borrador**, con marca temporal, sujeto firmado y alcance de búsqueda en lote.
- [x] Migraciones D1 `0003`/`0004` que rechazan referencias cruzadas, cambios a evidencias guardadas, páginas sin extraer, fuentes oficiales sin respaldo y búsquedas sobre ítems ya ubicados/observados.
- [x] Confirmación humana explícita de alcance en la pantalla React; estados del checklist siguen sin mutación automática.
- [x] MCP agrega `get_checklist_status` de solo lectura con pruebas de aislamiento.
- [x] Borradores con `Idempotency-Key`: reintentos repetidos o concurrentes generan una sola observación, evidencia y auditoría por comisión/autor/clave; distinto payload = 409.
- [x] Flujo `draft → in_review → validated|dismissed`, sin autovalidación ni firma oficial. Decisiones de miembro/presidente diferentes del autor, con justificación registrada.
- [x] Transiciones optimistas e idempotentes: reintentos idénticos son seguros; carreras, claves distintas o estados inválidos generan 409.
- [x] Triggers D1 `0005`–`0007`: origen solo draft, autenticación y rol válidos en cada transición, auditoría atómica, evidencia inmutable y revalidación antes de aceptar.
- [x] Controles de envío y decisión interna en React habilitados desde capacidades calculadas por API y confirmación humana.
- [ ] Validar protocolo MCP end-to-end con OAuth real en preview protegido.
- [ ] Probar D1/R2 con recursos de preview exclusivos y Access configurado (ningún recurso remoto creado todavía).
- [x] Admisión **interna** de texto inspeccionado mediante manifiesto HMAC firmado: certificado externo `clean`, verificación física SHA-256 del PDF original en R2 y registro transaccional de páginas/auditoría, idempotente.
- [x] Migraciones D1 `0009` y `0010` con informe de inspección inmutable, páginas completas y referencias de versión/cita protegidas; originales permanecen en `quarantine/`.
- [x] API autorizada y React para **lectura de texto** por página; no renderiza PDF ni HTML no confiable. Borradores de citas exactas de versión+SHA-256+página con revisor humano.
- [x] Outbox D1 transaccional por versión con migraciones `0011`/`0012`, estados protegidos por triggers, reintentos limitados, mensajes sin contenido documental y marcado atómico de `completed` al admitir inspección.
- [x] Código de consumidor independiente `apps/processor` con verificación de R2 físico, paso a Service Binding privado, firma HMAC, idempotencia, auditoría de rechazos y reintentos por mensaje; **sin bindings de Queue habilitados**.
- [x] Implementación ejecutable del servicio de inspección aislado `apps/inspector`: flujo obligatorio ClamAV, qpdf, Poppler y OCR Tesseract cuando es necesario; rechaza cifrado/adjuntos, límites estrictos, firma y contenedor sin privilegios. **Motores reales aprobados en smoke Docker local, no desplegados en Cloudflare**.
- [x] Gateway privado `apps/inspector-gateway` con Durable Object Container API actual, autenticación de servicio, validación de SHA-256, límites de bytes y firma HMAC en Worker fuera del contenedor; sin binding activo ni rutas públicas.
- [x] Python en modo Cloudflare `unsigned` sin clave HMAC; pruebas de salud del scanner y de la separación de secretos; firmas ClamAV exigidas en la construcción del Dockerfile (imagen local **construida y probada**, no desplegada).
- [x] Pruebas sintéticas locales de flujo Processor → Gateway → manifiesto firmado → D1 listo, más gate que bloquea activación accidental de Containers/Queues en los Wrangler activos.
- [x] Generación con stdlib de PDFs sintéticos nativos/escaneados/dañados, smoke real ClamAV+Poppler+Tesseract+EICAR y preflight de disco/memoria/Docker local; sin mocks en modo real (ADR-010).
- [x] El smoke Docker exige privilegios mínimos, red desconectada, RAM ≥4 GiB, firmas frescas y aborta cuando falta capacidad; comprobado bloqueo inicial por falta de disco y posterior ejecución satisfactoria tras liberarse capacidad.
- [x] Refuerzo del inspector: stdout de motores en archivo temporal privado con máximo 2 MiB leídos a memoria; prueba de rechazo de salida excesiva o inválida.
- [x] Diagnóstico de backlog/outbox (ADR-011) de solo lectura y sin endpoints públicos: pendientes, reintentos vencidos, envíos agotados, rechazos, comisiones cerradas, inconsistencias y versiones sin trabajo; métricas agregadas, límite de lectura, resultado incompleto explícito.
- [x] Integración del diagnóstico al mantenimiento `scheduled` **sin activar cron**, con índice local D1 `0013` para orden de auditoría; ningún reenvío ni borrado automático.
- [x] **Ejecutado y aprobado** build + smoke local con motores reales: PDF nativo, OCR de PDF exclusivamente rasterizado (sin capa de texto), rechazo estructural, PDF cifrado y con adjunto rechazados, y detección EICAR; 6/6, exit code 0 (ADR-010).
- [x] Primer smoke histórico con ClamAV 1.4.6, qpdf 11.3.0, Poppler 22.12.0, Tesseract 5.3.0 y firmas daily/main/bytecode; imagen local aislada sin red. **Sustituido por versión parchada del incremento siguiente.**
- [x] **ClamAV actualizado a 1.5.5** desde paquete oficial Linux firmado por Cisco Talos y verificado con GPG + huella principal de la clave antes de instalar; corrige riesgos de 1.4.6/1.5.4 de noviembre de 2026 (ADR-012).
- [x] Doble gate de versión de ClamAV >=1.5.5 en la serie 1.5, tanto para `GET /health` como para `inspect_pdf`; el build también verifica la versión. Bloquea admission con scanners antiguos o no identificados.
- [x] Smoke real HTTP interno del inspector con token sintético y sin red: salud 200, credencial errónea 403, documento autorizado clean sin firma en el parser y SHA-256 falsificado 422 (ADR-012).
- [ ] Completar escaneo de CVEs/SBOM de la imagen nativa y política verificable de renovación de firmas <=72 h, revisar superficie de herramientas del build, ampliar muestras OCR antes de piloto.
- [ ] Aprovisionar Service Binding y Cloudflare Container en entorno autorizado.
- [ ] Desplegar y verificar DLQ, Queues, cron, Access/MFA y E2E reales de Preview con solo datos sintéticos.
- [ ] Integrar motor de Workflows y políticas de recuperación de tareas prolongadas; IA supervisada con dataset sintético/anonimizado.
- [ ] Visor visual de documentos saneados y descargas controladas, solo tras inspección y aprobación normativa.
- [x] Conciliación diagnóstica R2–D1: candidatos huérfanos con antigüedad ≥48 h, referencias ausentes, metadatos SHA-256 incompatibles, paginación/límites explícitos y cero borrados.
- [x] Restricción SQL de unicidad de claves físicas R2 por versión (`0008`).
- [x] Manejador `scheduled` interno que solo publica conteos agregados; **sin cron habilitado**.
- [ ] Plan de reconciliación a escala y corrección aprobada de huérfanos; política institucional de retención y borrado; verificación del SHA-256 real de los bytes.
- [x] Identificación guiada de comisiones y lotes mediante catálogo autenticado (provisionamiento administrativo de identidades y lotes todavía pendiente).
- [ ] Acordar entidad y checklist/anexo, con revisión normativa y de privacidad.
- [ ] Ensayar exportación DOCX y reapertura de referencias.

## Gates obligatorios para datos reales

1. Entidad responsable autoriza finalidad, almacenamiento, tratamiento por terceros, retención y borrado, incluida transferencia internacional si corresponde.
2. MFA y política Cloudflare Access probados, rutas no protegidas cerradas y acceso por comisión probado de extremo a extremo (web y MCP).
3. Se verifica identidad del revisor; no se permite introducir el subject de forma arbitraria.
4. 100 % de observaciones documentales exportadas tienen versión+SHA256+página localizable; ausencias tienen búsqueda+revisor+fecha.
5. La IA solo propone: un miembro de comisión confirma o descarta.
6. Documento de gestión de incidentes, backup, cierre y eliminación verificados.

## No objetivos de MVP

Chat libre, búsqueda vectorial, DOCX/XLSX como entrada, multi-comisión autoservicio, conectores automáticos a cuatro portales, reportes oficiales directos, decisiones autónomas de IA.
