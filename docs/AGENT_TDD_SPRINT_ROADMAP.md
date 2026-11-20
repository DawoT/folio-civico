# Folio Cívico — Roadmap integral TDD para ejecución por agentes de IA

**Fecha y huso:** 2026-11-20, America/Lima. **Snapshot inicial de auditoría:** `origin/main@e2026647fb69acca211466ffa149f048d81115ee`. **Reconciliación al integrar:** rama sincronizada con `origin/main@2ba6baeb3c1b176f9bafa5d3bec60a065b720fc9`; mantener el SHA de cada validación por separado. **Tipo:** plan de entrega y aceptación; NO autorización de Preview, procesamiento de datos reales, gastos ni despliegue. **Identidad de producto:** «Evidencia para una transferencia ordenada». No es el sistema ni el acta oficial de la Contraloría.

## 0. Regla de uso y realidad comprobada

Este documento complementa (no reemplaza ni reescribe sin revisión) `docs/EXECUTION_PLAN.md`, `docs/ROADMAP.md`, `docs/UX_FRONTEND_PREMIUM_ROADMAP.md`, `docs/PREVIEW_CHECKLIST.md` y ADR de seguridad. Si un hecho cambia tras el snapshot, cada agente debe volver a verificar HEAD, PR abiertos, CI, Wrangler y gates institucionales, anotar el delta y actualizar el plan. No usar porcentajes de avance arbitrarios.

**Implementado y reproducido en el snapshot:**
- React, API protegida, D1/SQLite, R2 simulado, gestión de comisiones/miembros, checklist, PDF en cuarentena, observaciones, validación humana por un revisor distinto, exportación interna JSON y MCP de lectura. La cadena documental incluye outbox, Processor, Gateway y Container/inspector como código; bindings remotos intencionadamente inactivos.
- `pnpm test`: **515/515** Vitest en 82 archivos (snapshot de este plan). `pnpm test:demo`: **1/1** Chromium con UI real, API de aplicación real, JWKS/JWT RS256 de pruebas y SQLite/R2 simulados. La prueba de navegador con API ficticia también existe; NO se debe confundir ninguna con E2E de Access/D1/R2/Queue/Container remotos.
- En revisiones anteriores auditadas: `pnpm typecheck`, `pnpm build` (Workers dry-run), 119 pruebas de Python y 5 workerd aprobados; GitHub Actions sobre `main` con CI verde en al menos la ejecución #44767516827. Estos números son instantáneas, no un certificado permanente.
- `main` **no cuenta con protección de rama en GitHub** al corte (API respondió HTTP 404 para branch protection). El PR **#65** (PERF-004) y el PR **#67** (validación estructural de exportación rehasheada en React) ya se encuentran **fusionados en `main`** al reconciliar esta planificación. No duplicar ni sobreescribir sus cambios.
- Ausentes en Wrangler activo: Access real (vars vacías), UUID D1 real, Queue+cron, Container binding; el conector Preview no está configurado. Workers Folio Cívico consultados no existen en la cuenta inspeccionada. `/health` es liveness, no readiness.
- Scanner ClamAV/qpdf/Poppler/Tesseract **sí implementado** y ensayado localmente; imagen final **NO aprobada** por gate de CVE/procedencia. OCR solo se invoca si `pdftotext` devuelve texto vacío en la página; hay riesgo de perder partes de páginas mixtas. El visor actual muestra texto inspeccionado, NO PDF saneado. No se encontró integración productiva LLM/RAG. Exportación JSON SHA-256 no demuestra autenticidad institucional y no hay DOCX oficial.

**Riesgos de interpretación prohibidos:** CI local verde ≠ autorización de imagen; UI probada con API simulada ≠ autenticación remota; SHA-256 ≠ firma; «validación interna» ≠ hallazgo certificado; prueba automatizada ≠ investigación con personas; ausencia de CVE en un escáner ≠ ausencia de vulnerabilidad.

## 1. Alcance de producto y entregas parciales

**Release A — Piloto manual técnico en Preview aislado (solo datos sintéticos):** acceso autorizado con MFA, comisión/lotes/miembros, registro de búsqueda manual, doble revisión, checklist derivado, historial y JSON verificado. No necesita habilitar PDF/OCR real. No servir ni solicitar PDFs institucionales; la carga debe permanecer impedida o restringida a fixtures sintéticos verificados.

**Release B — Piloto documental integral en Preview aislado:** PDF en cuarentena privada → inspección aprobada de motores reales → texto y vista saneada → evidencia por página → revisión humana → informe íntegro; DLQ/retención/observabilidad verificadas. No autorizar mientras R1/Preview no pasen.

**Release C — Piloto asistido por IA y expediente verificable:** IA únicamente propone citas/hallazgos supervisados con evaluación independiente, sin actualizar automáticamente decisiones; DOCX u otro formato solo si su uso y base legal están aprobados. Firma/autenticidad institucional requiere autoridad/servicio externo competente, no un SHA-256.

**Producción:** decisión posterior a un piloto autorizado y medido, con controles legales, operativos, seguridad, usabilidad y presupuesto; no es consecuencia automática de C.

## 2. Protocolo obligatorio de trabajo de cada agente

**Un coordinador** divide trabajo en tickets acotados; agentes de ejecución o ejecuciones sucesivas usan worktrees aislados. No simular aprobadores humanos ni inventar evidencia. Un ticket = una responsabilidad + criterio verificable + PR revisable; no múltiples agentes editando simultáneamente los mismos archivos.

1. **Descubrir (READ):** registrar commit SHA, archivos fuente, llamadas, migraciones, tests, ADR, PR abiertos y estado de cambios. Confirmar si ya está implementado en otra rama.
2. **Contratar (RED):** escribir prueba que **falla por la brecha real**; guardar nombre exacto, salida/exit y fixture. Incluir éxito, rechazo, carrera, idempotencia, revocación, aislamiento entre comisiones y fallos de dependencia según aplique. Si se modifica un test preexistente, justificar por qué su oráculo era incorrecto.
3. **Implementar (GREEN):** cambio mínimo, tipado estricto, sin relajar gates o controles de acceso, sin abstraer prematuramente; jamás añadir fallbacks que conviertan 403/422/503 en éxito.
4. **Refactorizar:** eliminar duplicados solo del alcance; preservar API, contratos, respuesta de error, semántica legal y estados.
5. **Verificar:** suite dirigida + `sh scripts/ci.sh` sin saltarse etapas; para imagen, gate separado Trivy/SBOM + smoke de motores reales; para Preview, E2E remoto autorizado con datos sintéticos. Guardar resultados, negativos y evidencias sanitizadas. No agregar secretos, PDFs reales, identificadores personales ni screenshots sensibles al Git.
6. **Entregar:** PR pequeño con objetivo, evidencia RED→GREEN, archivos, riesgo, plan de reversión, salida de test, bloqueo restante y clasificación `implemented_local` / `verified_preview` / `accepted_human` / `released`. Nunca etiquetar «done» sin su gate.

**Plantilla obligatoria por ticket:** `ID`, `Outcome`, `Evidence@SHA`, `Dependencies`, `Owner/context`, `Touched paths`, `RED command and expected failure`, `GREEN minimum`, `Acceptance/negative cases`, `Proof links`, `Rollback`, `External approval`, `Status`. Campos desconocidos: `not_verified`, no suposiciones.

**Concurrencia:** máximo un escritor por superficie de dominio/SQL/migración. Toda PR se revalida tras actualizar con el último `main`. No cherry-pick de experimentos CVE al runtime sin análisis independiente. Los PR #65 y #67 ya fueron integrados; preservar sus tests y verificar que siguen verdes en el último `main`.

## 3. Gates de calidad que bloquean progresión

| Gate | Qué debe demostrarse | Evidencia mínima / bloqueo |
| --- | --- | --- |
| G0 · Integración | Protección de `main`; PR obligatorio, CI requerido, revisión y checks sin bypass; estrategia de rama/worktree aislados | Estado real de branch ruleset/protection + PR + CI SHA; no merge con rojo |
| G1 · Local | RED→GREEN documentado, suites unit/integración, Python, Workerd, Playwright (real API demo y UI sintética), axe, typecheck, build, presupuesto JS/CSS, Lighthouse y migraciones D1 locales | `sh scripts/ci.sh` exit 0 sobre SHA del PR; reportes sin P0/P1 conocido |
| G2 · Seguridad runtime | Imagen por digest, SBOM, procedencia nativa y dependencias, motores reales y corpus adversarial, CVE cerrados o VEX aprobado por responsable humano; firmas antivirus frescas y renovación/rollback | `pnpm audit:inspector:image` exit 0 más `pnpm test:inspector:docker` exit 0 de la **misma imagen candidata**. Nunca reemplazar hallazgos desconocidos por passes |
| G3 · Preview/identidad | Autorización expresa de infraestructura/costos, D1/R2/Workers/Queues segregados, Access MFA, OAuth MCP, secretos y hostname privado, backup; no datos reales | Inventario Cloudflare, JWT reales y expirados, cross-tenant, snapshot migración, pruebas de revocación, E2E real |
| G4 · Evidencia documental | No se accede al original desde navegador; todo texto/cita verifica versión+SHA-256+página, escaneo+OCR aprobado, no omisiones silenciosas, cierre ante corrupción/error | Corpus etiquetado, casos mixtos y adversarios, originales y artefactos equivalentes, comparación humana |
| G5 · IA | No hay decisiones automáticas. Proveedores y transferencia de datos autorizados; prompt injection, fuga entre comisiones y alucinaciones probadas; trazas y evidencia reproducibles | Evaluación versionada y ciega por expertos; 100% propuestas factuales con citas verificables; 0 propuestas sin soporte elevadas automáticamente |
| G6 · Humano/operación | Accesibilidad manual WCAG 2.2 AA, NVDA/VoiceOver, usabilidad moderada, privacidad Perú, runbooks, backup-restauración, SLA/SLO acordados, aceptación institucional | Actas de prueba/revisión humana realmente obtenidas; aprobación legal y operador; rollback ensayado; go/no-go explícito |

**Seguridad externa de referencia:** OWASP ASVS 5.0.0 como checklist con nivel objetivo L2 y controles L3 adicionales para evidencia, autorización, secreto y operación privilegiada; WCAG 2.2 AA más auditoría manual; NIST AI RMF/Generative AI Profile para IA. La Ley 29733 y su Reglamento DS 016-2024-JUS vigentes se verifican con asesoría local para roles, base jurídica, tratamientos, transferencias, contratos, retención y derechos. Los estándares orientan pruebas, **no son certificaciones automáticas**.

## 4. Secuencia de sprints (timeboxes orientativos de 1–2 semanas, no promesas)

Las dependencias son gates, no fechas. Si falta aprobación externa o el runtime sigue inseguro, el sprint se queda bloqueado mientras se adelantan tareas puramente locales independientes. Separar prioridades `P0 = condición de seguridad / desbloqueo`, `P1 = experiencia central`, `P2 = ampliación`.

| Sprint | Objetivo demostrable | Dependencias | Resultado/gate |
| --- | --- | --- | --- |
| S00 | Congelar baseline, normalizar PR y protección `main` | Ninguna | G0 y G1 en SHA base |
| S01 | Cerrar contratos y defectos de integridad en producto actual | S00, contrato export ya integrado | Regresiones de autorización/export/idempotencia |
| S02 | Threat model, seguridad app/supply chain y gates CI | S00 | Inventario ASVS, seguridad automatizada sin falsos passes |
| S03 | Inspector: CVE/procedencia, motores y firmas, parte A | S02 | G2 **pendiente hasta aprobar** |
| S04 | Preview aislado para piloto **manual y sintético** | S01, S02, autorización externa | Release A, G3 parcial |
| S05 | Inspector: seguridad final, OCR mixto y prueba adversarial, parte B | S03 | G2 + calidad documental local |
| S06 | Queue/cron/Gateway/Container y recuperación remota | S04, S05 | Pipeline real G3+G4; Release B base |
| S07 | Artefacto PDF saneado + navegación de evidencias | S05, S06 | Vista segura, fidelidad y accesibilidad |
| S08 | Datos de evaluación, búsqueda documental y procedencia | S06, S07 | Índice por comisión y corpus aprobado |
| S09 | IA supervisada, explicaciones trazables y control de costos | S08, autorización de proveedor | G5, Release C parcial |
| S10 | Expediente exportable DOCX/JSON, autenticidad y firma diferenciadas | S07, S09 si IA incluida, decisión legal | Export determinista verificable |
| S11 | Resiliencia, retención, privacidad y recuperación operativa | S04, S06 | G6 operacional |
| S12 | UX humana, accesibilidad y rendimiento de recorrido real | S04–S11 según funcionalidad | G6 UX |
| S13 | Piloto institucional controlado, correcciones y go/no-go | S06–S12 + autorizaciones | Release B/C aceptada o NO-GO |

### S00 — Fundamento verificable y coordinación (P0)

- **S00-01:** fijar SHA, inventario de módulos/rutas, matriz implementado/probado-local/probado-remoto y ADR vigentes; detectar docs obsoletas sin borrar su historial. Prueba RED: contraejemplos de estado declarado «deployed» cuando Wrangler/Cloudflare no muestran recursos; GREEN: informe de estado referenciado a SHA.
- **S00-02:** configurar branch protection/ruleset para `main`: status check real, PR obligatorio, aprobación sin self-bypass, protección de force push y configuración de mínimo privilegio. Requiere autorización de administrador del repositorio; prueba con PR deliberadamente rojo que **no puede** fusionarse.
- **S00-03:** verificar que PR #67 (export client structural gate) y #65 (PERF-004) permanecen integrados y probados tras sincronizar `main`. No volver a implementar su alcance. RED: export rehasheado inválido no debe descargar ni afirmar integridad; GREEN: tests de contrato y CI tras sincronización.
- **Salida:** base reproducible, rama protegida, backlog sin duplicidades ni discrepancias de estado.

### S01 — Confiabilidad del núcleo institucional (P0/P1)

- **S01-01:** revisar respuesta de reintentos PDF: `documentResult` fija `processingStatus=pending` incluso al reproducir una carga de versión ya procesada. RED: reintentar después de `ready` conserva id y SHA pero refleja estado correcto; GREEN: leer estado autorizado o declarar claramente contrato de `intakeStatus` versus estado actual, manteniendo compatibilidad.
- **S01-02:** auditar exhaustivamente matrices de permisos por estado (president/member/advisor/observer; activo/revocado; cierre de comisión; autor/revisor; Access expirado/cambio JWKS) con pruebas de propiedades y carreras D1. Foco en SQL triggers y restauración de integridad, no solo UI.
- **S01-03:** separar `/health` liveness de readiness autenticado y diagnóstico interno sin PII, y asegurar que dependencia fallida no produzca `ok` operativo.
- **S01-04:** export/consulta/miembros y paginación: contratos adversariales (JSON rehasheado, tampering, >=500, mismo cursor, revocación durante operaciones), límites explícitos y respuestas genéricas.
- **Salida:** contratos reales completos y negativos verificables; ninguna ampliación de superficie de datos sin autorización.

### S02 — Assurance de aplicación y cadena de suministro (P0)

- **S02-01:** threat model STRIDE por límites de confianza: Browser↔Access↔Worker↔D1/R2↔Queue↔Gateway↔Container, MCP OAuth y host operador sintético; abuso/CSRF, tenant isolation, replay, datos falsos, SSRF y supply chain. Trazar controles ASVS L2/L3 selectivos a tests, no marcar «cumple» sin ensayo.
- **S02-02:** fortalecer CI sin bloquear por una métrica vacía: SAST, dependency audit, secrets detect, licencias/SBOM, validación de migraciones y test de reversión local. Evitar cambio masivo de librerías; conservar Node/pnpm lockfile. Establecer Code Owners/revisión de ADR y branch check.
- **S02-03:** construir matriz negative security tests y revisión manual: encabezados, Origin/CSRF, caché, redirección de Access, JWKS rotación, JWT expirado, idempotencia en carreras; DAST solo contra entorno sintético autorizado.
- **Salida:** findings priorizados con PoC reproducible y corrección Red→Green; 0 hallazgos P0/P1 abiertos para la siguiente liberación.

### S03 — Inspector seguro: remediación y evidencias de procedencia (P0, sin atajo)

- **S03-01:** tomar inventario/digests de imagen EXACTA candidata; agrupar CVE por paquete, DSO alcanzable/no alcanzable, fuente compilada y advisory; no asumir que ausencia de vínculo dinámico elimina riesgo. Mantener VEX excepcional solo firmado por persona competente.
- **S03-02:** parchear/retirar superficies con pruebas diferenciales ASAN/UBSAN, corpus PDF adversarial, EICAR, cifrado, adjuntos, caracteres inválidos, XML/fonts y parser isolation; comparar resultado OCR/texto/píxeles contra imagen base.
- **S03-03:** demostrar ciclo ClamAV `daily/main/bytecode`: construcción y rotación menores a 72 h, arranque con base corrupta/vencida = 503, sin red o secretos expuestos; diagramar rollback pinneado a digest.
- **Salida:** solo código y evidencia local si el scanner aún devuelve exit 2. **Jamás** activar Containers ni cambiar la semántica de gate para obtener verde.

### S04 — Primer Preview manual privado (P0, externo autorizado)

- **S04-01:** preflight cuenta/allowlist/costos/autoridades, recursos `folio-civico-*` exclusivos; D1/migraciones con bookmark, R2 privado, backups y rollback. Evitar editar otros proyectos de la cuenta.
- **S04-02:** Access IdP+MFA, apps separadas API/MCP, validación issuer/audiencia, enroll/revoke, hostname privado; OAuth 2.0 para MCP remoto con pruebas de descubrimiento, scope, refresh/revocación, bloqueo cross-tenant y no CORS.
- **S04-03:** E2E **manual sintético** con navegador↔Worker real↔D1/R2 reales; export interno/revocación/cierre. Si G2 no aprobado, **bloquear ingesta documental incluso si el API web se habilita**; no enviar PDFs no sintéticos. Pruebas de denegación a no miembros.
- **Salida Release A:** acceso real protegido a flujo manual sintético, con artefactos de restore y registro de autorización. Sin inferir aprobación para documentos reales.

### S05 — Inspector documental: calidad y release gate (P0/P1)

- **S05-01:** corpus en español y tipologías: PDF nativo, raster, mixto en misma página, tablas, hojas rotadas, sellos, páginas vacías, expediente largo, cifrado, adjuntos, PDF truncado, PDF adversarial. Solo fixtures sintéticos/licenciados; corpus real únicamente con base jurídica.
- **S05-02:** RED específica a página mixta con texto digital más raster para evitar omisión silenciosa: medir cobertura texto+OCR o emitir `needs_review` explícito, nunca declarar `ready` si hay regiones sin evidencia; validar que la normalización no destruye números, fechas ni tablas.
- **S05-03:** presupuestos de CPU/memoria, timeout, página y tamaño, cancelación, fallo seguro y fixtures de calidad. Reportar CER/WER por estrato y tasa de rechazos; umbrales acordados tras obtener baseline y coste (no inventarlos).
- **Salida:** motor funcional y seguro sobre corpus representativo, G2 aprobado explícitamente. El microservicio solo recibe original desde Service Binding protegido.

### S06 — Pipeline remoto confiable, observabilidad y recuperación (P0)

- **S06-01:** Queue + DLQ + cron + bindings declarativos exclusivos de Preview; controles de gasto y red; mensajes mínimos. Primer RED: no se marca `completed` sin firma limpia ni se reenvía si comisión cerró/revocó o texto fue aprobado; simular fallos 422/503, crash entre claim/send, entrega doble y outbox agotado.
- **S06-02:** Container privado con health real, HMAC solo en gateway, secreto/token con rotación y separación; smoke de imagen por digest y compromiso cero de originales. Probar firmas forjadas y bytes R2 alterados.
- **S06-03:** herramientas de diagnóstico y DLQ solo lectura primero; redrive manual requiere autoridades independientes, revocación y aprobación externa. Verificar recuperabilidad sin inventar un `sent`; sin retries ilimitados.
- **S06-04:** E2E con Cloudflare reales y datos sintéticos: upload → outbox → Queue → Container antivirus/OCR → D1 páginas → cita → validación → JSON; aplicar caos controlado y comprobar ausencia de filtración.
- **Salida Release B base:** 100% casos críticos del happy path + negativos verdes; alarmas y reconciliación auditables, jamás sin G2.

### S07 — Visor documental seguro y fiabilidad de citas (P1)

- **S07-01:** diseñar un derivado **saneado** y versionado del documento, no servir el original `quarantine/`. Elegir sanitizador/renderizador y revisar amenaza active content, firmas/adjuntos, fuente, CORS, CSP, caché, límites y transcodificación. Si no puede demostrarse saneamiento, mantener solo texto.
- **S07-02:** vista de página e imagen/PDF derivado con par `versionId + sourceSha256 + page`; confirmación visual humana, OCR overlay solo con confianza; tamaño, zoom, teclado y lector de pantalla sin exponer bytes de cuarentena.
- **S07-03:** citas robustas y revocación: objeto eliminado, cambio de sesión, misma página otra versión, hash divergente, PDF manipulado, vínculo profundo, origen externo. Asegurar que el borrador conserva procedencia.
- **Salida:** inspección visual autorizada y trazable; no renderizar PDF activo en API o navegador.

### S08 — Datos, búsqueda y calidad de recuperación (P1)

- **S08-01:** definir taxonomía de expedientes por obras/contrataciones, unidad de evidencia, páginas, criterios de estado «ubicado/no ubicado» y etiquetas de evaluación. No inventar «irregularidades» a partir de ausencia.
- **S08-02:** búsqueda determinista por comisión sobre **solo texto inspeccionado**, indexación versionada y revocable, filtros y controles de procedencia. No crear vector store externo antes de justificar necesidad con prueba de recuperación y tratamiento de datos.
- **S08-03:** dataset sintético y autorizado con gold annotations, mezcla de páginas, falsos positivos/negativos, casos cross-tenant y correspondencia exacta; medir recall/precision y coste. Preservar abstención ante ausencia/ambigüedad.
- **Salida:** recuperación reproducible y útil antes de RAG; cero cruzamiento de comisiones en pruebas.

### S09 — IA documental supervisada y evaluada (P1/P2)

- **S09-01:** ADR decisión de proveedor / modelo local frente a remoto, privacidad/residencia, entrenamiento con datos, coste por expediente, retención, modelos/versiones, incertidumbre. Si no hay autorización de transferencia, solo ejecución local con corpus sintético.
- **S09-02:** construir propuesta sin poder de escritura en decisiones: retrieval → fragmentos trazables → respuesta estructurada validada → enlace a fuente exacta → humano confirma/descarta. No afirmar que un LLM es prueba ni que decide conformidad jurídica.
- **S09-03:** ataques: instrucciones ocultas en PDF, inyección en texto de OCR, citas inventadas, documentos de otra comisión, solicitudes de revelar datos, respuestas con confianza injustificada, truncamiento y modelo indisponible. Fail closed, sin propuestas no trazables aceptadas.
- **S09-04:** evaluación ciega con matriz versionada: 100% de cada afirmación factual propuesta apunta a evidencia existente; 0 decisiones finales automáticas; calidad, precisión/recall, abstención y costes por tipo de expediente medidos. Umbral de aceptación aprobado por humanos tras baseline, nunca definido retroactivamente para pasar.
- **Salida:** asistente propositivo con reproducibilidad, límites y supervisión; G5.

### S10 — Informe, procedencia y expediente (P1)

- **S10-01:** no reimplementar PR #67. Alinear validador estructural compartido con verificador offline; hash demuestra integridad interna, no procedencia. Exportación completa sin truncado; manejo de >500 según contrato y paginación firmada si se requiere.
- **S10-02:** generar DOCX reproducible y accesible, con índice, autor/revisor/fechas, evidencia exacta o alcance de búsqueda, revisión interna, advertencias legales y prueba de reapertura/estructura; sin datos ajenos ni PDF en cuarentena.
- **S10-03:** si la institución exige firma/autenticidad, integrar **solo** autoridad y servicio de firma aprobado; pruebas de tampering, cadena de custodia, revocación, timestamp y verificación independiente. Mantener informe «interno» sin tal autorización.
- **Salida:** expediente comprobable, no confundir formato DOCX con acta oficial.

### S11 — Protección de datos y operación sostenible (P0/P1)

- **S11-01:** evaluación jurídica Perú: responsable/encargado, base y finalidad, datos personales/sensibles, encargos cloud, transferencias, retención, ejercicio de derechos y posible registro; decidir política por tipo de documento. Aprobación de asesoría y titular requerida antes de datos reales.
- **S11-02:** backup/restore D1, objetos y auditoría; pruebas de RPO/RTO acordados, integridad de snapshot, migración adelante/rollback, incidente de revocación, claves/certificados vencidos y compromiso de secretos. Nunca autoeliminar cuarentena sin política.
- **S11-03:** observabilidad sin PII, alertas por Queue/DLQ, expiración de firmas, lag, errores OCR, desajuste D1/R2, costes y disponibilidad; on-call/runbook y respuesta a incidentes con roles humanos.
- **Salida:** G6 operacional aprobado. Documentar quién puede suspender el tratamiento.

### S12 — UX, accesibilidad y rendimiento reales (P1)

- **S12-01:** preservar el trabajo UX-0..UX-5 y PR #65; no duplicar design system ni medir solo shell vacío. Medir tareas de presidente/autor/revisor/observador sobre Preview autorizado con backend real y consentimientos.
- **S12-02:** auditoría WCAG 2.2 AA **manual y automatizada**, NVDA, VoiceOver, zoom nativo 200–400 %, lectores, teclado, 320 px, alto contraste, errores y descargas. Red→Green por hallazgo real; cero bloqueos críticos de accesibilidad.
- **S12-03:** estudio moderado con 5–8 representantes autorizados si es factible; evidencia de confusión sobre «cuarentena», «no ubicado», «validación interna» o «no oficial» = bloqueo. No convertir telemetría sintética en satisfacción humana.
- **S12-04:** presupuestos actuales de bundle JS <=100 KiB gzip, CSS <=10 KiB gzip, más latencia p95 y CWV de usuarios **con baselines y SLO acordados**, prueba de carga sintética y validación de costo.
- **Salida:** tareas completables, sin confusión semántica crítica; G6 UX.

### S13 — Aceptación integral y go/no-go (P0)

- **S13-01:** ejecutar matriz E2E real sobre el mismo digest de release: Identity/Access/MFA→frontend→API→D1/R2→Queue→Container→export. Abuso de cross-tenant, revocación durante hashing/descarga, concurrencia, 422, 503, manipulación, crash, DLQ y restauración.
- **S13-02:** piloto con participantes y datos **solo** autorizados; verificar límites del estudio, tiempos reales, reducción de errores, utilidad de búsqueda e IA, falsos negativos documentales y coste por expediente; aprobación formal por autoridad competente.
- **S13-03:** revisión independiente de seguridad, legal, accesibilidad, resiliencia y proveedor. Resultado firmado `GO` / `NO-GO`, hallazgos residuales, condiciones, fecha, rollback y responsable. Sin firma/aceptación: NO-GO. Producción en decisión futura separada.
- **Salida:** expediente de evidencias de producto; aceptación de release B/C según alcance elegido y presupuesto, nunca despliegue automático.

## 5. Matriz de dependencia, paralelismo y ruta crítica

- **Ruta crítica documental:** S00 → S02 → S03 → S05 → S06 → S07 → S08 → S09 (si aplica) → S10 → S13.
- **Ruta crítica Preview manual:** S00 → S01/S02 → S04 → S12 → aceptación humana de Release A; puede arrancar antes del inspector SOLO con datos sintéticos y PDF real inhabilitado.
- **Paralelizables con worktrees exclusivos:** S01 (API/SQL), S02–S03 (seguridad, sin tocar producción), S12 (UX de fixtures), S11 (análisis/operación). Sin compartir migración/contrato. Si los mismos archivos cambian, serializar.
- **Bloqueos humanos:** autorización costos/dominio/cloud; Access/MFA/OAuth; aprobación jurídica y roles de tratamiento; decisión de VEX o remediación; dataset legal; firma y uso oficial; usabilidad con humanos; GO/NO-GO. Un agente puede preparar evidencia, **no otorgar estas aprobaciones**.

## 6. Scorecard y políticas de parada

Registrar por sprint y SHA: CI local verde, tipo de E2E (mock/local-real/Preview-real), todos los casos negativos de autorización, deuda P0/P1, CVEs por digest/VEX, exactitud y cobertura documental por estrato, pruebas de IA evaluadas, Lighthouse/INP/p95 de flujo autorizado, éxito/tarea de personas reales, RTO/RPO ensayados, incidentes, costo por expediente y aceptación humana.

**Stop-the-line inmediato:** acceso cruzado, exposición del original R2, evidencia/cita forjada, autovalidación, false clean antimalware, datos personales en logs/training, rollback no viable, PDF visual inseguro, hallazgo crítico de acceso, CVE bloqueante no aceptado, confusión que equipare resultado interno con acta oficial. Se abre issue reproducible y no se despliega.

**Despliegue permitido solo con aprobación explícita.** Ningún agente debe activar recursos, subir PDFs institucionales, hacer migraciones remotas, cambiar retención, actualizar snapshots visuales a ciegas, crear secretos reales ni corregir tests para ocultar errores sin responsable autorizado.

## 7. Primer paquete listo para delegar

- **TICKET S00-01 (docs/CI):** inventario a HEAD, cierre de divergencias de estado y mapa de pruebas, sin tocar runtime; adjuntar SHA + outputs. Primer entregable del roadmap.
- **TICKET S00-02 (GitHub/admin, requiere titular):** proteger `main`; verificar con PR rojo no fusionable; no forzar políticas desde conectores sin autorización.
- **TICKET S00-03 (integración):** verificar la integración ya realizada de #65 y #67, evitar duplicación y comprobar CI tras cambios nuevos.
- **TICKET S01-01 (API):** TDD sobre respuesta idempotente después de `ready`; conservar identidad/hash y contrato de estado.
- **TICKET S02-01 (seguridad):** threat model sobre código y matriz ASVS 5.0 con pruebas negativas, sin forzar activación del inspector.
- **TICKET S03-01 (imagen):** reconciliar SBOM/CVE real de imagen candidata, procedencia, modelos OCR y gate, con estado `blocked` mientras no se apruebe.

## 8. Referencias y evidencia de auditoría

**Código:** `apps/api/src/index.ts`, `apps/api/src/document-routes.ts`, `apps/web/src/ReviewWorkspace.tsx`, `apps/web/src/InspectedTextViewer.tsx`, `apps/web/src/ui/ReviewExportPanel.tsx`, `packages/data/src/`, `packages/auth/src/`, `migrations/0001–0030`, `apps/processor/src/`, `apps/inspector/inspector.py`, `apps/inspector-gateway/src/`, `apps/operator/src/isolated-host.ts`, `scripts/ci.sh`, `.github/workflows/ci.yml`.

**Fuente normativa a revisar en cumplimiento:** https://asvs.owasp.org/ · https://www.w3.org/TR/WCAG22/ · https://www.nist.gov/itl/ai-risk-management-framework · https://www.gob.pe/institucion/anpd/campa%C3%B1as/128319-nuevo-reglamento-de-proteccion-de-datos-personales

**Trazabilidad de plan:** ver `docs/EXECUTION_PLAN.md` para el historial R0–R8; `docs/UX_FRONTEND_PREMIUM_ROADMAP.md` para UX; `docs/PREVIEW_CHECKLIST.md` para autorización; ADR-023 para integración de código sin liberar imagen. Si hay conflicto entre una afirmación de documento y el runtime observado, gana la evidencia comprobada y se abre issue de reconciliación.
