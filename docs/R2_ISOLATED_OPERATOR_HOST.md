# R2.9 · Adaptador HTTP de operador exclusivamente sintético y aislado

**Corte:** 2026-11-19 (America/Lima). **Estado:** módulo de orquestación verificado únicamente con D1 local y Queue simulada. **Sin Worker desplegable, sin Wrangler, sin rutas en API/MCP, sin operador institucional ni secretos reales.**

## Decisión

Se añadió `apps/operator/src/isolated-host.ts`, un **adaptador HTTP funcional de prueba** que conecta los contratos ya auditados:
- `POST https://operator.local/internal/operations/revocations` → JWT Cloudflare Access del actor y del aprobador, JWS de aprobación de incidente de R2.8, capacidad sellada y doble escritura D1 atómica del diario y de la revocación global.
- `POST https://operator.local/internal/operations/redrives` → JWT Access del operador, JWS de aprobación/MFA y de release del inspector de R2.6, digest de imagen fijado por el host, elegibilidad R2.4 y reserva R2.5 con un solo envío mediante **Queue inyectada y simulada**.

Estas direcciones son **rutas lógicas dentro de pruebas de Request/Response**, no URLs publicadas en Internet. **R2.10:** el [flujo asíncrono independiente](R2_ASYNC_REVOCATION_APPROVAL.md) añade dos rutas de prueba nuevas (propuesta y decisión, cada una con un solo JWT Access). La ruta combinada R2.9 queda desactivada por defecto y solo se habilita en fixtures legados mediante `allowLegacyCombinedRevocations:true`. El adaptador **no tiene `default ExportedHandler`**, paquete de despliegue, `wrangler.jsonc`, `main` de Worker, callback cron ni Service Binding. No se han añadido variables de operador a los Workers activos.

## Barreras fail-closed

- **Desactivado por defecto:** sin `mode: "synthetic-offline-only"` y D1 inyectada devuelve `503` **antes de analizar JSON, leer D1 o consultar JWKS**. La cadena de opt-in es solo una barrera de integración accidental, **no un control suficiente para entornos reales**.
- **Origen sintético fijo:** `https://operator.local`. Solo dos rutas cerradas y método `POST`, sin query ni fragmentos. Se rechazan `Origin` de navegador, cookies, handshake WebSocket y CORS. No puede exponerse por una URL real sin modificar el diseño.
- Solo `application/json` con UTF-8 opcional; cuerpo máximo de **8192 bytes**, claves estrictamente limitadas y todas las propiedades cadenas. No se aceptan identidades, permisos, raíces de confianza ni configuración de imagen dentro del JSON de negocio. Las credenciales firmadas viajan únicamente en encabezados.
- La revocación exige `Cf-Access-Jwt-Assertion`, `X-Folio-Approver-Access-Jwt` y `X-Folio-Incident-Approval-Jws`, todos con sintaxis de JWT. Las identidades y su separación se verifican en `@folio/auth`; una identidad declarada por el cliente nunca se usa para registrar el incidente.
- El redrive exige `Cf-Access-Jwt-Assertion`, `X-Folio-Redrive-Approval-Jws`, `X-Folio-Inspector-Release-Jws` y una **imagen real esperada definida por la configuración**. El sujeto operador siempre se extrae de la capacidad firmada, **no del cuerpo**. Si no existe puerto Queue o digest configurado, responde `503`.
- Errores sin stack, secreto, identificadores de cuenta, claims o motivo de incidente. Todas las respuestas llevan `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff` y no emiten `Access-Control-Allow-Origin`.
- No altera originales R2, no desbloquea PDFs y no reinicia el outbox agotado. La ejecución sintética reitera un `send` **como máximo una vez**; respuesta Queue ambigua registra `uncertain`, sin segundo envío. La revocación de imagen registrada con R2.8 bloquea inmediatamente la prevalidación del mismo redrive R2.5.

## Verificación

```sh
pnpm exec vitest run apps/operator/src/isolated-host.test.ts
pnpm typecheck
sh scripts/ci.sh
```

Nueve pruebas nuevas con JWT RS256 y JWKS sintéticos, D1/SQLite migrada y Queue `vi.fn`: deshabilitación por defecto sin efectos, rechazo HTTP/Origin/cookies/métodos/payload, revocación legítima y replay, firmas alteradas, flujo manual completo, idempotencia, falta de Queue/gate de imagen, respuesta ambigua que no reintenta, revocación real de imagen a través del adaptador, y indisponibilidad D1 con respuesta genérica sin secretos.

Las pruebas son de integración lógica `Request/Response`, **no** HTTP sobre un Worker/Access real, no una prueba de infraestructura y no una declaración de aprobación CVE.

## Pendientes y prohibiciones

1. Aprobar explícitamente la creación de un host/hostname privado y los posibles costos. Este archivo no debe convertirse en Worker sin revisión de seguridad y consentimiento.
2. Diseñar un protocolo de autorización que no dependa de que un solo cliente conserve **dos JWT Access de distintas personas**: el adaptador comprueba firmas y diferencias de identidad, pero la posesión de los tokens no prueba independencia humana. Separar aprobación asíncrona del incidente y custodia de token del aprobador.
3. Configurar IdP/Access/MFA reales, emisores independientes aprobados, claves públicas con rotación y revocación, y vincular el release a la imagen y escaneo Trivy/SBOM/firmas **realmente** verificados.
4. Establecer permisos mínimos y segregación real de acceso D1: el trigger R2.8 es una protección contra escrituras accidentales, **no contra un administrador D1 comprometido**.
5. Con autorización de recursos y CVE superados, implementar un host separado, protecciones contra replay de JWT, rate limits, trazas sin PII, pruebas de timeout y concurrencia D1↔Queue sobre servicios reales, conciliación de `reserved/uncertain` y pruebas de denegación E2E en Preview.
6. No habilitar infraestructura real, Queue remota, OCR/inspector, redrive o accesos institucionales como consecuencia de haber pasado los tests locales.

**Rollback:** solo nuevas fuentes y documentación; ninguna migración, modificación de runtime ni recurso remoto.
