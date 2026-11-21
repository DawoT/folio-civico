# F5 · Ensayo funcional integrado del piloto con identidades y datos sintéticos

**Fecha de corte:** 2026-11-19 (America/Lima). **Tipo:** E2E lógico local a través del enrutador real del Worker, D1 SQLite, R2 simulado y JWT Access RS256 firmados; no es una ejecución remota ni una prueba de navegador real.

## Objetivo verificable

Demostrar que se puede preparar una comisión sintética, cargar un PDF sin inspeccionarlo, documentar una búsqueda manual, obtener una segunda decisión humana y exportar el resultado de forma íntegra sin exponer originales PDF ni conceder autoridad a una identidad ajena.

## Ejecución reproducible

```sh
pnpm exec vitest run apps/api/src/pilot-functional.e2e.test.ts
sh scripts/ci.sh
```

**Fixture:** `apps/api/src/pilot-functional.e2e.test.ts`. Los datos no salen de memoria ni contienen documentos institucionales: D1 en memoria creado por `makeD1`, bucket R2 sustituido por un `Map` y un PDF mínimo artificial. El fixture fija explícitamente `DOCUMENT_UPLOADS_ENABLED:"true"` para probar cuarentena sintética; en el despliegue manual Release A el backend conserva `DOCUMENT_UPLOADS_ENABLED:"false"` y rechaza POST de PDF con 503. Este opt-in de laboratorio no es aprobación del scanner ni autorización de ingesta real. Los tokens de operador, presidencia, autor, revisor y externo se firman con la **misma** clave temporal RS256; el endpoint JWKS de prueba anuncia esa clave, conservando la verificación real de firma, emisor y audiencia. No se usa mock de `authenticateAccess`.

## Criterios de aceptación cubiertos

| Etapa | Verificación |
| --- | --- |
| Identidad y autorización | JWT de usuario ordinario no puede iniciar una comisión; operador explícitamente autorizado crea y reintenta con idempotencia |
| Alta y permisos | Presidencia crea dos miembros, lote e ítem esperado; actor y comisión derivan del JWT y del enrutamiento autenticado |
| Entrada PDF | Se almacena una única vez en un R2 de memoria, estado `quarantined/pending`, mismo SHA-256 ante reintento, sin claves internas en el listado |
| Gate de texto | Ninguna página inspeccionada disponible y la propuesta de cita a página de PDF no verificado recibe 422 |
| Evidencia humana | Autor crea una observación `SEARCH_SCOPE` con ítem/lote; no puede validarse a sí mismo |
| Segunda revisión | Tras envío a revisión el checklist sigue `pending`; un miembro distinto valida con justificación y pasa a `not_located / validated_search` |
| Trazabilidad | Se recupera el registro por ID exacto; estado, revisor, evidencia y eventos de auditoría persisten, mientras la versión PDF permanece `pending` |
| Exportación íntegra | Un miembro autorizado descarga el informe; carga con solo decisiones finalizadas, referencia a búsqueda y advertencia de uso interno, sin claves R2 ni idempotencia |
| Integridad independiente | El archivo generado por la API supera `scripts/verify-review-export.mjs` (exit 0); también supera la verificación SHA-256 del cliente web |
| Segregación de inquilinos | Las consultas de otra comisión y las de un no miembro se niegan sin revelar los recursos ajenos |
| Revocación | Se revoca un miembro y **su mismo JWT aún vigente deja de autorizar** detalle, checklist, exportación y administración |

## Evidencia y límites de esta validación

- Las dos pruebas de F5 comprueban un recorrido positivo largo y uno negativo de aislamiento/revocación.
- Se ejecutan en Vitest contra el handler `handleApiRequest`; no equivalen a una interacción E2E de navegador ni ejercitan el servicio Cloudflare remoto. Las pruebas workerd de `scripts/ci.sh` cubren por separado la integración local con Workers.
- No se inicia OCR, ClamAV, Poppler, gateway, cola ni inspector: una búsqueda manual sin resultado no depende del documento en cuarentena ni inventa texto extraído. La cadena documental R2 → Queue → inspector → D1 mantiene sus propios requisitos R1/R2 y gates independientes.
- No se da de alta un usuario en el IdP; los JWT son sintéticos y la identidad operadora sigue desactivada por defecto en cualquier entorno no configurado.
- Un resultado validado internamente **no es** declaración de irregularidad, acta oficial, firma digital ni validación de una autoridad pública.

La [suite F5.1 de navegador](F5_BROWSER_E2E_ACCESSIBILITY.md) complementa este E2E lógico con Chromium y accesibilidad, pero usa una API sintética interceptada: son dos controles independientes, no un despliegue integrado.\n\n## Siguiente barrera hacia el piloto institucional

Probar la misma secuencia con sesión Access y cuentas sintéticas en **Preview aislado**, después de aprobar infraestructura, gasto, identidad/Access y los gates de seguridad del inspector. Ejecutar pruebas de interfaz con navegador, accesibilidad y recuperación antes de considerar el piloto operativo. Ningún paso de F5 autoriza un despliegue.
