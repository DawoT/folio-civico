# Plan de ejecución e integración incremental · Folio Cívico

**Corte verificado:** 2026-11-19 (America/Lima). **Alcance:** piloto distrital con evidencia ficticia/anonimizada; no despliegue autorizado.  
**Fuente de verdad de las capacidades:** [ROADMAP](ROADMAP.md), ADR-001–014 y [PREVIEW_CHECKLIST](PREVIEW_CHECKLIST.md).

## Política de entrega

- **Troncal `main`:** crearla desde el último commit lineal verificado porque el remoto originalmente solo publicó ramas `feat/*`. No reescribir historial, no hacer `force push`. Conservar las ramas históricas. El cambio de rama predeterminada de GitHub es una operación administrativa separada.
- **Incrementos verticales:** una rama `feat/*` o `fix/*` por cambio acotado, con pruebas que fallan antes de implementar (Red), implementación mínima (Green), refactor y revisión de regresiones. Integrar por avance rápido (*fast-forward*) en `main` exclusivamente tras los gates verdes y verificación de árbol limpio. Cambios incompatibles o bloqueados permanecen fuera de `main`.
- **CI sin GitHub Actions:** el contrato reproducible es `sh scripts/ci.sh`. Ejecuta instalación congelada, pruebas del CI, Vitest, pruebas Python, typecheck, build web + dry-runs de Workers, integración `workerd` y migraciones D1 **locales** de API/MCP/Processor. Cualquier código distinto de cero bloquea integración. El workflow GitHub, si vuelve a estar disponible, únicamente invoca este mismo script.
- **Gate de seguridad independiente y bloqueante para publicación:** `pnpm audit:inspector:image` (Trivy/SBOM, Docker local) y `pnpm test:inspector:docker` (motores reales). **No** se interpreta su omisión del CI ligero como aprobación de despliegue. Exit 2 de CVEs = bloqueado. Sin VEX aprobado ni imagen remediada, no habilitar Cloudflare Containers.
- **Separación de autorizaciones:** fusionar código en `main` no autoriza crear recursos, asumir gastos, registrar secretos, migrar D1 remota, procesar documentación institucional ni desplegar. Estas acciones exigen autorización expresa y gates legales/técnicos de [Preview](PREVIEW_CHECKLIST.md).
- **Evidencia por incremento:** registrar commit, casos Red/Green, salidas de tests, resultados del CI local, riesgos residuales y rollback. No afirmar E2E remotos a partir de pruebas locales.

## Vía funcional paralela (sin tocar el trabajo de seguridad)

| ID | Valor de producto | Criterio medible | Estado |
| --- | --- | --- | --- |
| **F1** | Búsqueda documentada → dos revisores → resultado visible en checklist | Solo observaciones `SEARCH_SCOPE` validadas proyectan ausencia; se muestra revisor y referencia; sin mutar checklist original; pruebas API/UI y tenant isolation | **Completado: integrado en `main` (commit `33fb29d`) y CI local aprobado** |
| **F2** | Historial y navegación entre checklist, observaciones y documento | Localizar siempre una observación aunque tenga más de 50 registros; permisos y paginación verificadas | **Parcial:** acceso exacto por ID con permisos y UI; paginación y vínculo documental pendientes |
| **F3** | Exportación verificable de hallazgos manuales | Informe con fuentes, estado humano, identidad y fecha; prueba de integridad sin afirmar carácter oficial | **Completado en `main` (`8026d49`):** JSON de decisiones finalizadas con verificador SHA-256; DOCX, firma oficial y lotes >500 pendientes |
| **F4** | Onboarding y administración básica de piloto | Comisiones, lotes, permisos y checklist en flujo administrativo auditable | **Parcial, integrada en `main` (`d08a80d`):** alta de lotes e ítems del checklist por presidente con JWT, idempotencia, auditoría y D1 (ADR-019). Creación de comisiones y permisos/membresías pendientes |
| **F5** | E2E funcional de uso con datos sintéticos | Alta → carga en cuarentena → búsqueda → envío → segunda revisión → consulta/exportación, sin requerir scanner en una búsqueda de ausencia | Pendiente |

La vía de seguridad del inspector continúa con su responsable separado. F1–F5 no habilitan PDF de cuarentena, procesamiento remoto, Preview ni datos reales.

## Secuencia y criterios de aceptación

| ID | Incremento entregable | Dependencias | Criterio de aceptación para integrarse | Estado al corte |
| --- | --- | --- | --- | --- |
| **R0** | Troncal `main`, CI shell independiente del proveedor, contrato de pruebas, roadmap y controles de integración | Historia lineal existente | `sh scripts/ci.sh` con exit 0; pruebas de orden, fail-fast, local-only y rechazo de flags; árbol limpio, push no forzado | **Completado:** `main` publicada; CI local verde |
| **R1** | Remediación del inspector, CVE triage y cadena de suministro | R0, ADR-013/014/015 | Imagen reproducible con SBOM/digest; hallazgos CRITICAL/HIGH/UNKNOWN remediados o VEX granular formalmente aprobado; `audit:inspector:image` y smoke Docker aprobados; prueba de caducidad/renovación `< 72h` | **Parcial y bloqueado:** imagen histórica 1 CRITICAL/149 HIGH/19 UNKNOWN; candidata 0 CRITICAL/128 HIGH/19 UNKNOWN, gate Trivy exit 2; falta cobertura de CVE de Tesseract compilado, evaluación OCR ampliada y rotación de firmas |
| **R2** | Cadena documental resiliente y comprobaciones E2E locales | R0, R1 para validar imagen final | Escenarios sintéticos R2 → outbox D1 → Queue simulada → Processor → Gateway → inspector → D1; éxito, duplicados, errores 422/503, reintentos, agotamiento, HMAC inválido, caída temporal y reconciliación. Sin exposición de original | **Parcial:** contratos y pruebas unitarias/integración locales existentes |
| **R3** | Preview Cloudflare aislado, identidad y OAuth MCP | R1, R2 y aprobación de recursos/costes | D1/R2/Queues/DLQ/Containers exclusivamente `folio-civico-*`; Access/MFA, OAuth real, mínimo privilegio, prohibición de rutas públicas, revocación, backup/rollback y E2E con datos sintéticos | **Pendiente; operador Preview no configurado** |
| **R4** | Visor PDF saneado, navegación de citas y experiencia accesible | R2, R3 y reglas institucionales | El original en cuarentena nunca se sirve; solo artefacto inspeccionado; correspondencia versión+SHA256+página y errores de permisos probados; accesibilidad de teclado y estados de carga/error | **Pendiente** |
| **R5** | IA supervisada para propuestas de hallazgos | R2–R4, dataset anónimo, evaluación de calidad | Evidencia obligatoria para cada cita; propuestas no autoaprobadas; pruebas de alucinación/cita inexistente, aislamiento entre comisiones, trazas auditables y conjunto de evaluación versionado | **Pendiente** |
| **R6** | Exportación DOCX y expediente verificable | R4–R5, aprobación de formato | DOCX reproducible; 100 % de citas resueltas a versión/hash/página o declaración de búsqueda; validación humana, fixture de reapertura, sin afirmar carácter oficial | **Pendiente** |
| **R7** | Administración, retención y observabilidad | R3 + aprobación jurídica | Alta/baja de miembros, ACL por comisión, auditoría, backups/restores ensayados, reconciliación no destructiva y borrado solo con política aprobada; alertas sin datos sensibles | **Pendiente** |
| **R8** | Piloto controlado y endurecimiento operativo | R3–R7, autorización de entidad | Ensayo E2E y recuperación, pruebas de seguridad, accesibilidad, rendimiento, incidentes, manuales, métricas de precisión/tiempo ahorrado y checklist de salida firmado | **Pendiente** |

### Primeras unidades de trabajo para avanzar tras R0

1. **R1.1 — inventario verificable (parcial validado):** el triaje real agrupa 169 hallazgos bloqueantes y observa enlace dinámico en 105; quedan 64 sin enlace observado y 2 propietarios de biblioteca sin resolver. **No confundir ausencia en `ldd` con ausencia de riesgo.** Conservar evidencia granular fuera de Git, priorizar `libxml2` y completar las rutas faltantes (ADR-015).
2. **R1.2 — remediación o VEX formal:** buscar correcciones oficiales y probar imagen candidata con los mismos fixtures; documentar bloqueos no corregibles y la decisión humana correspondiente.
3. **R1.3 — ciclo de firmas:** diseñar renovación de imágenes/digests antes del límite de 72 h; probar arranque/rechazo, corte de disponibilidad, reversión y no admisión con firmas caducadas.
4. **R2.1 — contrato E2E sintético:** cubrir idempotencia y fallos del pipeline sin depender todavía de Cloudflare remoto; asegurar que el job no se marca completo sin manifiesto firmado.

## Definición de completado por incremento

- **Funcionalidad:** criterios de aceptación medibles y alcance preciso, no solo tests de implementación.
- **Calidad:** Red → Green → Refactor registrado; tests de regresión para errores y autorizaciones negativas; sin degradación de tipado o compilación.
- **Integración:** `sh scripts/ci.sh` verde, migraciones D1 locales reproducibles, sin cambios ajenos, `main` actualizado solo por avance rápido.
- **Seguridad:** ninguna excepción silenciosa, ningún secreto registrado, no publicación de PDF en cuarentena, segregación de funciones.
- **Operación:** documentar lo que está implementado, probado localmente, pendiente de E2E y bloqueado. Para Preview/producción, los gates adicionales y las autorizaciones prevalecen sobre el resultado de CI.

## Registro de avances

Registrar aquí los commits de cada entrega, las pruebas efectivamente ejecutadas y los bloqueos remanentes. No considerar completada una fase por haberla descrito en este documento.

| Fecha | Incremento | Resultado |
| --- | --- | --- |
| 2026-11-19 | R0 | `main` creada y publicada mediante avance lineal sin force-push desde el commit `bc5dd86`; `sh scripts/ci.sh` exit 0: 4 tests del runner, 173 Vitest, 58 Python y 5 workerd, typecheck, build y 13 migraciones D1 locales verificadas en API/MCP/Processor. Auditoría CVE sigue bloqueada; no se desplegó. |
| 2026-11-19 | R1.1 | Reaplicado sobre `main` el triaje de CVE de la rama independiente y ejecutado `sh scripts/ci.sh` (4+173+69+5 pruebas y build/migraciones, exit 0); `bash apps/inspector/audit_image.sh --triage` devolvió **exit 2 esperado** por 1 CRITICAL, 149 HIGH y 19 UNKNOWN. Sin autorización de despliegue. |
| 2026-11-19 | F1 | Búsqueda manual validada por segundo revisor visible como ausencia confirmada internamente, con revisor y observación exacta; ninguna escritura al checklist institucional ni activación del scanner. TDD Red/Green documentado, CI local con 178 Vitest + 69 Python + 5 workerd + 4 contrato, typecheck, build y D1 local: exit 0. Integración fast-forward `33fb29d`. |
| 2026-11-19 | F2 | Detalle autorizado de observación por ID, navegación desde checklist y manejo de errores, aunque el registro no esté entre las 50 observaciones recientes; tests de permisos y regresión de rutas, `sh scripts/ci.sh` aprobado. Integración fast-forward `c315526`. Paginación histórica aún pendiente. |
| 2026-11-19 | F4.1 | Alta de lotes e ítems del checklist por presidente de comisión activa, con identidad Access firmada (simulada en pruebas), idempotencia inmutable, aislamiento por comisión, auditoría atómica y máximo de 100 recursos por tipo. Migración local `0014` aplicada en API/MCP/Processor. TDD Red/Green, `sh scripts/ci.sh` exit 0: **206 Vitest + 69 Python + 5 workerd + 4 contrato** (284), typecheck y build/dry-run; fast-forward `d08a80d`. No crea comisiones ni miembros. |
| 2026-11-19 | F3 | Informe JSON completo de decisiones internas finalizadas (hasta 500 y 8 MiB) con huella SHA-256, descarga desde React y verificador CLI independiente; casos de integridad alterada, aislamiento, límites y archivo real cubiertos. TDD Red/Green; `sh scripts/ci.sh`: **195 Vitest + 69 Python + 5 workerd + 4 contrato** (273), typecheck, builds y migraciones D1 locales, exit 0. Integración fast-forward `8026d49`. Sin despliegue ni firma oficial. |
| 2026-11-19 | R1.2 candidato Tesseract | Rama `fix/tesseract-5.5.4-archive-free`, primer commit `bc68cd7`, publicada para revisión. Dockerfile compiló Tesseract 5.5.4 desde tarball SHA-256 fijado, eliminó la cadena libarchive/libxml2 y corrigió carga de modelos mediante `TESSDATA_PREFIX`. Imagen `ocr-integrated`: 6/6 motores reales, 4/4 HTTP y `sh scripts/ci.sh` exit 0 (4 CI, 72 Python, Vitest, 5 workerd, typecheck/build/migraciones). Trivy/CycloneDX: 0 CRITICAL, **128 HIGH**, 19 UNKNOWN, exit 2 **bloqueado**; Tesseract compilado exige revisión de advisories independiente. Paridad OCR ampliada, rotación de firmas y aprobación de seguridad pendientes. Sin cambios en `main`, `validation` ni Cloudflare. Ver [ADR-020](ADR-020-minimal-tesseract-ocr.md). |
