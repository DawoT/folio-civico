# ADR-001 · Cloudflare como infraestructura y MCP como interfaz

**Estado:** aceptado para la fundación técnica; pendiente revisión contractual para datos reales.
**Fecha:** 2026-11-18

## Contexto

La propuesta requiere una mesa de constatación con evidencias reabribles, versiones inmutables, separación por comisión y anexos no oficiales. Un agente de IA puede consultar y sugerir, pero no decidir por la comisión. La cuenta Cloudflare alberga otros productos; cada recurso de Folio Cívico debe ser exclusivo.

## Decisión

- **Runtime:** Workers nativos en TypeScript; API y MCP en Workers separados.
- **Datos:** D1 dedicado al piloto, preparado para revaluar PostgreSQL si un requisito contractual exige RLS/residencia específica.
- **Objetos:** R2 privado, sin rutas públicas a originales; hash por versión y control de descargas en la API.
- **Procesamiento futuro:** Queues + Workflows para ingesta idempotente; OCR aislado y métricas por página.
- **IA:** extrae propuestas con evidencia, nunca valida ni decide.
- **MCP:** `agents/mcp/server` (SDK v2 / Streamable HTTP), servidor stateless y solo lectura inicialmente. Cloudflare Access/Managed OAuth protege entrada; servicio verifica JWT y pertenencia a comisión en cada consulta.
- **Núcleo:** paquetes de dominio, autenticación y persistencia compartidos entre API y MCP.

## Reglas invariantes

1. Denegar si no hay identidad verificable o membresía activa.
2. No inferir folios ni evidencia a partir de una respuesta del modelo.
3. No permitir citas de otra comisión o de versiones que no existan.
4. No permitir validaciones automáticas por IA/MCP.
5. No registrar contenido interno ni credenciales en logs ni caché.
6. No desplegar sin Access configurado y sin aprobación de tratamiento de datos.

## Consecuencias

+ Menos infraestructura operativa, mismo lenguaje end-to-end, MCP sin base paralela.
+ Separa interfaz de interacción humana de acceso para agentes.
- D1 no implementa PostgreSQL RLS; aislamiento depende además de consultas y comprobaciones de autorización.
- Configurar Managed OAuth/Cloudflare Access requiere pasos y pruebas reales, no solo código.
- OCR, residencia y retención quedan sujetos a prueba de factibilidad y aprobación institucional.

## Referencias técnicas

- https://developers.cloudflare.com/workers/framework-guides/web-apps/react/
- https://developers.cloudflare.com/agents/model-context-protocol/apis/handler-api/
- https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/
- https://developers.cloudflare.com/d1/
