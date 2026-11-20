# UX-5.1 — Evidencia de aceptación y preparación controlada del piloto

**Corte:** 19 de noviembre de 2026.  
**Proyecto:** Folio Cívico — Mesa documental de transferencia de gestión.  
**Alcance:** prueba local con API sintética en Chromium. No utiliza expedientes reales ni recursos Cloudflare remotos.

## Dictamen y condiciones

**Estado de este incremento: aceptación automatizada local verificable; preparación institucional aún NO APROBADA.**

La finalización de un recorrido Playwright **no** equivale a:
- una sesión observada con personas de la comisión;
- una auditoría manual WCAG 2.2 AA / NVDA / VoiceOver;
- una firma o certificación oficial de expedientes;
- la liberación de los gates del inspector (R1/R3) ni el consentimiento para Preview/producción.

No se calcularán porcentajes de éxito de personas, tiempos medios o satisfacción a partir de clics de automatización: serían métricas de naturaleza distinta.

## 1. Matriz de aceptación automatizada de extremo a extremo

Un mismo `SyntheticPilotApi` sirve a **cuatro páginas con identidades separadas** durante un recorrido continuo y determinista en `tests/browser/pilot-acceptance.spec.ts`.

| ID de evidencia | Rol / tarea | Prueba verificable |
| --- | --- | --- |
| `scope_opened` | Presidencia abre comisión y lote autorizados | Resumen y checklist visibles; acceso administrativo disponible |
| `pdf_quarantined` | Autor carga PDF mínimo ficticio | API sintética registra versión con SHA-256, estado `pending` y aviso de cuarentena; jamás se renderiza PDF original |
| `draft_registered` | Autor describe búsqueda en lote | Borrador persistido con `SEARCH_SCOPE` sintético y estado `draft`, sin inferir irregularidad |
| `submitted_for_review` | Autor envía borrador | Estado `in_review`; el autor carece de acción de autorrevisión |
| `independent_decision` | Segundo miembro distinto justifica y valida | El botón exige justificación y atestación, API registra `reviewedBy` distinto, checklist muestra **validación interna** |
| `observer_read_only` | Observador consulta el detalle revisado | Sin alta PDF, administración, creación o revisión; ninguna solicitud mutante; axe-core y ancho sin overflow |
| `sha256_export_verified` | Observador exporta informe interno | Descarga JSON con una decisión validada, `completeness.truncated=false`, SHA-256 calculado sobre el **payload** coincide con el recibido |

**Implementación y trazabilidad:** `tests/pilot-evidence.ts` define la lista exacta de siete tareas; `tests/pilot-evidence.test.ts` prueba unicidad, estados incompletos, rechazo de tareas desconocidas y ausencia de campos sensibles. El E2E adjunta `synthetic-pilot-acceptance.json` al resultado Playwright de cada formato, con tareas `passed` o `not_evidenced`.

El JSON de aceptación **solo** contiene IDs fijos de tareas y estados; no incluye identidades, archivos, hashes, texto documental, timestamps ni mediciones de personas. Fija expresamente: `humanUsability=not_conducted`, `manualAssistiveTechnology=not_conducted` y `productionAuthorization=not_granted`.

**Importante:** el API de este escenario es un doble sintético de navegador, no el Worker firmado real. Las verificaciones de autorización de Workers se ejecutan en el gate independiente de Vitest/workerd. Ninguna conclusión de seguridad depende únicamente de este E2E.

## 2. Regresión visual versionada

`tests/browser/pilot-visual.spec.ts` verifica regiones estables de UI contra **12 PNG de referencia** en `tests/browser/pilot-visual.spec.ts-snapshots/`:

| Región | Escritorio 1366×900 | Pixel 7 | Reflujo 320×640 |
| --- | --- | --- | --- |
| Orientación antes de seleccionar lote | Captura de referencia | Captura de referencia | Captura de referencia |
| Resumen de comisión autorizada | Captura de referencia | Captura de referencia | Captura de referencia |
| Lote realmente vacío | Captura de referencia | Captura de referencia | Captura de referencia |
| Servicio no disponible (503) | Captura de referencia | Captura de referencia | Captura de referencia |

**Reproducibilidad:** las capturas se generaron sobre Chromium Linux de Playwright, con datos sintéticos, sin recursos remotos y con animaciones desactivadas. Se comparan píxeles con `threshold:0.2` y `maxDiffPixelRatio:0.012`. El tamaño total de las doce referencias es aproximadamente **269 KiB**.

Comandos:

```sh
# Contrato y matriz visual de UX-5.1 — sin modificar referencias
pnpm exec vitest run tests/pilot-evidence.test.ts
pnpm exec playwright test --config=playwright.config.ts \
  tests/browser/pilot-acceptance.spec.ts tests/browser/pilot-visual.spec.ts

# Solo tras inspección y aprobación explícita de un cambio de diseño:
pnpm exec playwright test --config=playwright.config.ts \
  tests/browser/pilot-visual.spec.ts --update-snapshots

# Gate real antes de integrar a main
sh scripts/ci.sh
```

La CI no usa `--update-snapshots`: ante cambios de diseño no revisados, la prueba debe fallar. La comparación visual **no** sustituye criterios de contenido, contraste, lector de pantalla o experiencia humana. Si cambian sistema operativo, fuentes o versión Chromium, revisar la compatibilidad de las referencias en vez de aceptar automáticamente diffs masivos.

## 3. Protocolo de investigación de usabilidad pendiente

**Objetivo:** medir si personas que representan los cuatro perfiles completan las mismas tareas **sin asistencia** y comprenden correctamente los estados jurídicos y técnicos.

**Reclutamiento previsto (no ejecutado):** 5–8 personas autorizadas de perfiles presidencia/administración, integrante autor, revisor distinto y observador; usar sujetos y documentos sintéticos. La cifra es orientativa para detección cualitativa de defectos, **no** para extrapolar estadísticamente resultados municipales.

**Antes de cada sesión:** consentimiento informado, condiciones de accesibilidad/preferencias, entorno local autorizado, tareas previamente preparadas, cero expedientes reales, sin grabación ni subida a servicios externos sin autorización. No pedir credenciales reales; proteger datos de participantes.

**Tareas observables:**
1. Identificar comisión y lote y explicar el alcance.
2. Diferenciar «lote vacío» de «listado no disponible» al introducir un error 503.
3. Incorporar un PDF de prueba y explicar qué significa «En cuarentena».
4. Registrar una búsqueda sin resultado, describiendo evidencia y alcance.
5. Enviar al segundo revisor y explicar por qué el autor no puede autovalidarla.
6. Como revisor distinto, identificar la evidencia, justificar la decisión y explicar el significado de «validación interna».
7. Como observador, localizar la validación y exportar el JSON; diferenciar SHA-256 de firma digital o acta oficial.

**Registrar por tarea:** `completed_without_assistance` (sí/no), `navigation_errors` (recuento), `state_interpretation` (correcta/incorrecta), `elapsed_seconds` (tiempo de una persona real, no Playwright), incidencias y comentarios espontáneos. Si la sesión no se ejecutó, el campo queda **pendiente**, nunca cero.

### Plantilla para una sesión autorizada

| Campo | Valor a completar durante la sesión |
| --- | --- |
| Referencia seudónima de participante | PENDIENTE |
| Perfil y versión del producto | PENDIENTE |
| OS/navegador/tecnología de asistencia | PENDIENTE |
| Zoom y tamaño de texto | PENDIENTE |
| Consentimiento y entorno sintético confirmado | PENDIENTE |
| Tarea (1–7) y criterio observable | PENDIENTE |
| Éxito sin ayuda / errores / interpretación | PENDIENTE |
| Tiempo humano medido y comentarios | PENDIENTE |
| Defecto, severidad, reproducción e issue | PENDIENTE |
| Decisión del equipo responsable | PENDIENTE |

**Condición de bloqueo:** cualquier confusión que convierta un error de lectura en «ausencia comprobada», un PDF en cuarentena en «revisado», o una validación interna en «acta oficial» se trata como hallazgo crítico y se corrige antes del piloto. No maquillar los resultados mediante texto o puntuaciones inventadas.

## 4. Gates de salida y pendientes

| Gate | Evidencia disponible | Estado |
| --- | --- | --- |
| Integridad de recorrido sintético por roles | Playwright + JSON de tareas, tres formatos | Verificado cuando CI local pase |
| Cambios visuales inesperados en cuatro estados clave | 12 PNG versionados y comparados | Verificado cuando CI local pase |
| WCAG automatizado y reflujo | axe-core y pruebas de teclado/320 px existentes | Limitado a cobertura automatizada |
| Prueba humana 5–8 perfiles / métricas reales | Aún sin sesiones ni métricas | **PENDIENTE** |
| NVDA / VoiceOver y zoom nativo 200–400 % | Protocolo en `docs/UX4_ADVANCED_ACCESSIBILITY.md` | **PENDIENTE** |
| Inspector firmado, CVEs, R1/R3 y despliegue | Proceso de seguridad independiente | **BLOQUEADO hasta autorización** |

**Próximo incremento:** UX-5.2 — ejecutar o facilitar sesiones moderadas con personas autorizadas, registrar incidentes reales y corregir solo defectos reproducidos. Si no hay participantes disponibles, preparar el entorno y el formulario de registro **sin afirmar investigación realizada**.

**No se cambia API, permisos, Cloudflare, D1/R2 ni se despliega software.** La preparación de experiencia no concede autorización de producción.
