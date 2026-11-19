# F5.1 · Pruebas de navegador y accesibilidad del piloto

**Corte:** 2026-11-19 (America/Lima). **Tipo:** Playwright con Chromium real y axe-core; API sustituida exclusivamente en las pruebas por respuestas sintéticas controladas. **No utiliza Cloudflare remoto ni procesa documentos reales.**

## Propósito y límites de confianza

Esta suite comprueba el comportamiento del frontend renderizado en navegador real, que antes solo se verificaba parcialmente con renderizado React estático. Sus escenarios no verifican JWT, D1, R2 ni reglas internas del Worker, porque interceptan `/api/**`. Esos contratos se prueban **por separado** en `apps/api/src/pilot-functional.e2e.test.ts` con JWT RS256 reales y D1 local. La suma de ambas suites mejora la cobertura, pero no sustituye una prueba integrada de navegador + Worker + Access en Preview.

## Ejecución

```sh
pnpm install --frozen-lockfile
pnpm exec playwright install chromium # una vez por equipo; no se descarga en CI
pnpm test:browser                  # solo navegador / API sintética
sh scripts/ci.sh                   # gate completo, incluido Chromium
```

La suite usa `playwright.config.ts`, arranca temporalmente Vite en `127.0.0.1:4175` y cierra el servidor al terminar. `tests/browser/synthetic-api.ts` intercepta íntegramente las rutas `/api/**`: ningún request API va a Cloudflare ni al proxy por defecto. El `Idempotency-Key` enviado por React puede comprobarse desde el fixture. Chromium y axe están fijados en `pnpm-lock.yaml`. El artefacto `test-results/` (capturas y trazas **solo en error**) está excluido de Git.

**La presencia de Chromium es obligatoria para `sh scripts/ci.sh`; si falta, el gate falla.** La instalación del navegador es un paso explícito de preparación del host, no un despliegue.

## Cobertura automatizada

Se ejecutan seis recorridos independientes en tres tamaños de navegador: **escritorio 1366×900, móvil Pixel 7 y reflujo WCAG a 320×640**.

1. Interfaz de comisión vacía y presidencia: encabezados, selección de comisión, alta de miembro y lote, retorno de servidor e idempotencia.
2. Dos páginas de navegador para autor y segundo revisor: búsqueda documentada → borrador → envío → validación humana → `No ubicado · validación interna` → detalle → descarga JSON cuya huella SHA-256 valida el navegador.
3. Rol observador: historial de más de 25 observaciones y carga de páginas anteriores, detalle exacto e inexistencia de controles de modificación.
4. **Solo teclado:** orden de foco, selección de comisión/lote y apertura con `Tab`, flechas y `Enter`.
5. Archivo inválido rechazado localmente antes de enviarlo; PDF sintético llega a `quarantined/pending`, sin `iframe`, `embed` ni `object` del original.
6. Exportación alterada: se muestra un error de integridad y **no se dispara una descarga**.

Las comprobaciones de accesibilidad inspeccionan el árbol DOM efectivo con `@axe-core/playwright` y las reglas **WCAG 2.0 A/AA, 2.1 A/AA y 2.2 AA** disponibles en axe-core. Las vistas examinadas deben tener **cero infracciones automáticas** y **ningún elemento que sobresalga horizontalmente** de la ventana. Se retuvieron pruebas específicas para pantalla de 320 px.

## Correcciones de producto detectadas y aplicadas

- Contraste del pie de página: `.page-footer` usa `#455761` en lugar del color más tenue.
- Contraste del estado del PDF en la lista: `.document-details small` usa `#40575b`.
- Cabecera de administración de miembros: título y botón **Actualizar miembros** se distribuyen en varias filas cuando falta espacio, evitando desplazamiento horizontal a 320 px.

Estos defectos se descubrieron en la primera ejecución real del navegador y su corrección fue comprobada contra las mismas pruebas.

## Condiciones todavía pendientes

- **No es una auditoría completa de accesibilidad:** quedan revisión humana WCAG 2.2, tecnologías de asistencia/lectores de pantalla, contraste en todos los estados y pruebas con usuarios reales.
- La API de las pruebas es un doble sintético; el gate no autoriza activar Preview ni demuestra que Cloudflare Access/MFA, D1/R2 remotos o el scanner funcionen juntos.
- Solo Chromium está configurado. Firefox y WebKit requieren instalación y validación por separado; no se afirma compatibilidad probada.
- Ningún informe es una firma ni acta oficial. Los PDF originales permanecen en cuarentena y no se visualizan en el navegador.
