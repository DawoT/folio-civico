# UX-3.4 — Comprobante de exportación e integridad del informe interno

**Fecha:** noviembre de 2026. **Tipo:** incremento frontend aislado, compatible con contratos existentes.

## Objetivo

Elevar la calidad de la exportación de informes internos sin convertir un archivo JSON en una certificación oficial. Reducir el riesgo de descargar contenido alterado, confundir una huella con una firma digital o interpretar el inicio de descarga como almacenamiento confirmado.

## Comportamiento

Se incorpora `ReviewExportPanel` en la región `#informes`, con estados discriminados y accesibles:

| Estado | Acción y feedback |
| --- | --- |
| `idle` | Explica el contenido, exclusiones y carácter no oficial. Botón «Exportar revisión interna (JSON)». |
| `verifying` | Anuncia verificación previa, marca `aria-busy` y deshabilita la exportación concurrente. |
| `verified` | Presenta el SHA-256, cantidad de decisiones internas incluidas, nombre del archivo solicitado y copia de huella. |
| `error` | Anuncia error, omite recibo/digest anterior y ofrece «Reintentar exportación» sin desbloquear contenido fallido. |

El servidor y la función `loadVerifiedReviewReport` existente siguen validando identidad de comisión, integridad SHA-256 del payload, esquema, `completeness.truncated === false`, conteo y estados de las observaciones. **El frontend crea el Blob solamente después de esa validación**. No se incorporan endpoints ni bibliotecas nuevas.

### Precisión documental

- La huella mostrada y copiable es SHA-256 **del contenido (`payload`) del informe**, **no del envoltorio JSON descargado**.
- «Integridad verificada» describe la comprobación técnica del payload recibido frente al digest proporcionado. **No es una firma digital ni certifica la autenticidad o aprobación institucional**.
- «La descarga se inició» significa que se pidió al navegador guardar un archivo; la aplicación **no puede certificar que el archivo se haya almacenado exitosamente**.
- El recuento 0 es un informe vacío válido, no un error; la singularización distingue `1 decisión` y `N decisiones`.
- La copia al portapapeles no expone el contenido del informe. Un fallo de permisos muestra instrucciones de selección manual del digest sin invalidar la integridad ya verificada.

### Robustez y contexto

- Un `ref` de operación en curso bloquea clics duplicados **antes** de que React procese el siguiente render.
- Un contador de intento invalida respuestas atrasadas después de cambiar de lote o desmontar la vista; así no se genera una descarga no solicitada sobre un contexto abandonado.
- El comprobante anterior desaparece en el inicio del siguiente intento o cuando falla la verificación. La interfaz nunca conserva una huella «verde» de una solicitud fallida.
- La revocación del `ObjectURL` queda programada después de permitir al navegador comenzar el manejo de la descarga; se conserva el comportamiento existente.

## TDD

**Red:** `ReviewExportPanel.test.tsx` falló al importar el componente inexistente.

**Green:** seis pruebas unitarias del contrato de estados, recibo, conteos 0/1/N, lenguaje de integridad, errores y no retención de huellas.

**Chromium:** cinco recorridos nuevos por viewport:
1. Descarga y comparación real SHA-256 de `payload` extraído del JSON, copia del digest y axe/overflow.
2. Exportación alterada rechazada sin descarga; reintento posterior correcto.
3. Informe vacío verificable y denegación del portapapeles recuperable.
4. Doble clic inmediato produce exactamente una solicitud y una descarga.
5. Respuesta atrasada de un lote anterior no descarga al cambiar de contexto.

**Gate de integración:** `sh scripts/ci.sh` en un worktree actualizado desde `origin/main`, puerto `FOLIO_E2E_PORT` aislado para Playwright. Incluye Vitest, Python, Workerd, typecheck, builds, Chromium desktop/móvil/320 con axe y migraciones D1 locales. El resultado debe ser **exit 0** antes de fusionar. GitHub Actions no se utiliza como criterio de aprobación.

## Archivos previstos

- `apps/web/src/ui/ReviewExportPanel.tsx` — componente de estados accesible.
- `apps/web/src/ui/ReviewExportPanel.test.tsx` — seis contratos de TDD.
- `apps/web/src/ReviewWorkspace.tsx` — integración, protección ante doble clic/contexto obsoleto.
- `apps/web/src/styles.css` — presentación con tokens, responsive y digest copiable.
- `tests/browser/review-export-receipt.spec.ts` — cinco recorridos verificables.
- `docs/UX3_REVIEW_EXPORT_RECEIPT.md` — este contrato.

## Restricciones

Sin cambios a Workers, D1/R2, Cloudflare Access, autorización, cuarentena, OCR, antivirus, integridad del backend ni procesos de revisión institucional. Estas pruebas locales **no constituyen aprobación de despliegue ni liberan el gate de seguridad del inspector**.

## Próximo corte

UX-4 — consistencia editorial y visual, jerarquía de páginas, responsive avanzado y validación manual con lector de pantalla y usuarios de comisión. Requiere separar los cambios cosméticos de los flujos críticos de seguridad.
