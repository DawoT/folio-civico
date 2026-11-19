# ADR-017 · Acceso individual trazable a observaciones de comisión

**Fecha:** 2026-11-19 (America/Lima). **Estado:** implementación y pruebas locales; sin despliegue.

## Objetivo

Una validación puede fundamentar un estado del checklist aunque su observación ya no figure entre los últimos 50 registros. Evitar referencias que el usuario no puede consultar.

## Decisión

- Añadir `GET /api/commissions/{commissionId}/observations/{observationId}` en el Worker API. Reutiliza `getObservationForMember`, que exige comisión coincidente y membresía activa.
- La respuesta usa un **allowlist** de campos: autor, decisión, segundo revisor, justificación, evidencias y fechas. No expone claves internas de idempotencia ni metadatos secretos.
- No introduce mutaciones, redirecciones a objetos R2 o acceso directo a PDF. Las solicitudes con método distinto de GET devuelven 405, los registros inaccesibles 404, y la respuesta no se puede cachear.
- Añadir `loadObservationDetail` con credenciales de mismo origen, `no-store`, validación de IDs, correlación entre solicitud y respuesta.
- En el checklist, un resultado `validated_search` muestra **Ver validación**. El panel explica la decisión, quién la adoptó, cuándo y la evidencia precisa. Puede cerrar el panel y gestiona carga y errores.
- El panel consulta por ID, **no depende del límite de 50** de la lista de observaciones recientes. El texto se renderiza mediante React, sin interpretar HTML externo.

## Criterios de aceptación

TDD para lectura autorizada, revocación, aislamiento entre comisiones, 404 en registros ajenos o inexistentes, método GET único y omisión de request keys. Pruebas del cliente API y representación del control en React. CI local sin modificaciones de seguridad ni despliegue.

## Límites

No existe todavía paginación de la lista histórica completa ni búsqueda libre de observaciones. El acceso exacto por ID está disponible desde los ítems que contienen una validación de búsqueda. No habilita el visor PDF, la extracción ni decisiones oficiales.
