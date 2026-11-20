# R2.12b/P1 · Contrato de evidencia institucional vigente (solo preparatorio)

**Estado:** implementación y pruebas de contrato sintéticas, **no** integración institucional ni autorización de publicación. La [issue #19](https://github.com/DawoT/folio-civico/issues/19) continúa abierta. No hay credenciales institucionales, sistema de incidencias designado, host operativo, Worker, Queue real, D1 remoto ni IdP validado.

## Límite de confianza

Una firma JWS y una sesión JWT Access independiente **no acreditan** por sí mismas que una persona haya revisado la incidencia, tenga MFA real vigente o conserve facultades en el IdP. R2.12b/P1 introduce un **puerto de lectura server-to-server** `InstitutionalEvidenceReader` en `apps/operator/src/institutional-authority.ts`, sin implementar ni elegir un proveedor externo.

El puerto recibe desde código ya autenticado una expectativa, calculada **sin usar nuevos parámetros HTTP**: `purpose`, `caseRef`, `requestId`, `actorSubject`, `approverSubject`, SHA-256 del ámbito, SHA-256 del JWS y caducidad de propuesta. Debe devolver el **estado actual obtenido del registro autorizado**, no copiar ciegamente la expectativa. La comprobación rechaza cualquier diferencia, identidad igual o expediente ausente.

El registro institucional debe declarar revisión humana `approved`, expediente `open`, revisor coincidente con el sujeto verificado, revisión de versión positiva, estado observado hace **no más de 15 s**, decisión y MFA de **no más de 5 min**, marca de MFA anterior a la decisión y vigencia activa. Las comprobaciones de tiempo usan segundos para registros institucionales y milisegundos para el vencimiento de la propuesta. Un error del proveedor se convierte en **503**, una respuesta vigente pero no autorizada en **403**; la respuesta HTTP no revela detalles del incidente.

## Puntos de comprobación

- Aprobación R2.10, incluyendo replays: después de verificar el Access del aprobador y el JWS del incidente, **antes** del diario y la denegatoria D1.
- Aprobación R2.11, incluyendo replays: después de verificar Access+JWS, **antes** de escribir la constancia D1.
- Ejecución R2.11: después de revalidar Access+JWS+release del inspector y **antes** de reservar o enviar a Queue. Un expediente cerrado o caída del proveedor impide el envío.
- El gate se activa pasando `institutionalGate: {reader: trustedReader}` al único adaptador `mode: "synthetic-offline-only"`. Con `institutionalGate: {}` la operación protegida se rechaza con **503**. Su ausencia sigue permitiendo las pruebas sintéticas R2.10/R2.11 existentes; **no se debe interpretar esta ruta sin gate como alternativa para producción**.

Las pruebas de contrato usan un puerto falso únicamente para reproducir cambios de expediente, fallos, caducidad, suplantación de ámbito, aprobación y ejecución. No existe conector ni vía de ejecución remota aprobada.

## Limitaciones y condiciones de activación

1. **Fuente institucional no designada:** implantar un lector de solo lectura, autenticado y auditado, con identidad y MFA de un IdP real y versiones comprobables. La salida de un mock o un JWS no es evidencia válida.
2. **TOCTOU entre sistemas:** una consulta externa previa a D1 o Queue **no** es transaccional con su cambio posterior. El refresco antes de ejecutar reduce la ventana, pero no demuestra linealizabilidad con el expediente externo. Se requiere decidir cómo conservar revisión/huella institucional sellada en D1, revocar aprobaciones cuando cambie el caso, restringir writers y conciliar resultados antes de Preview.
3. **Autorización en tiempo real:** la revocación D1 R2.12a sigue vigente, pero **no reemplaza** la revalidación de roles y membresía del IdP. Requiere integración independiente y un procedimiento de retirada inmediata.
4. **Control operacional:** mínimos privilegios de administración D1, custodia JWS, trazabilidad, retención, protección de secretos, revisión humana y checklist Preview con autorización explícita. El gate CVE del inspector sigue bloqueante.

## Verificación local

```sh
pnpm exec vitest run apps/operator/src/institutional-authority.test.ts apps/operator/src/async-approval.test.ts apps/operator/src/async-redrive.test.ts
pnpm typecheck
sh scripts/ci.sh
```

El test de contrato se creó primero en rojo (módulo ausente); dos nuevas pruebas de integración también fallaron inicialmente con respuesta 200 en lugar de la denegación 503. Después de implementar el puerto y sus tres puntos de comprobación, las pruebas focalizadas quedaron en **55/55** y el typecheck en exit 0. El resultado del CI completo se registra en `docs/EXECUTION_PLAN.md`.

**Este código no cumple la condición de cierre de R2.12b: sigue pendiente la evidencia institucional real de la issue #19.**
