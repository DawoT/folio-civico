# R2.6 · Prueba criptográfica de identidad, aprobación y release para redrive

**Corte:** 2026-11-19 (America/Lima). **Estado:** contrato offline validado localmente. **No** se han configurado autoridades reales, identidades de operador, infraestructura Queue/Cloudflare ni despliegues del inspector.

## Riesgo de origen

R2.5 exigía `configuredOperatorSubject` y un booleano `inspectorReleaseApproved === true`. Ambos estaban desconectados del runtime, pero **no constituían evidencias verificables de identidad, MFA, aprobación ni estado de seguridad**. Un futuro host que aceptase ese booleano sin comprobaciones independientes convertiría el redrive en una operación privilegiada basada en afirmaciones manipulables.

R2.6 reemplaza ese contrato por `verifyOneShotOperatorAuthorization` en `packages/auth/src/manual-redrive-authorization.ts`. El valor de salida es una **capacidad efímera e intransferible** sellada internamente mediante `WeakSet` y `Symbol`, no un JSON que pueda construir un caller. `executeOneShotManualRedrive` ahora exige esa capacidad concreta, además de comparar su imagen de inspector con el digest esperado del runtime.

## Tres verificaciones criptográficas independientes

| Origen | Comprobación de software | Obligación externa pendiente |
| --- | --- | --- |
| **Cloudflare Access** | JWT firmado, JWKS, issuer HTTPS `.cloudflareaccess.com`, audiencia y sujeto coincidente con el operador configurado | Instalar política real de Access/MFA y restringir quién puede obtener el JWT |
| **Autoridad de aprobación** | JWS RS256, clave pública/issuer/audience fijados, aprobación `approved` ligada a operador, comisión, revisión, clave idempotente y `OPR_...`; declaración `mfa=verified` y `mfaAt` no anterior a 5 min | Auditar que la autoridad **comprueba realmente** MFA y la aprobación humana/ticket antes de firmar |
| **Autoridad de seguridad del inspector** | Otro JWS RS256 con clave/issuer/audience **distintos**, imagen `sha256:` vinculada al runtime, `cveGate=pass`, huellas de SBOM e informe, auditoría de hasta 24 h, caducidad y vigencia de firmas de hasta 72 h | Garantizar que el firmante emite `pass` **solo** tras ejecutar el gate Trivy/CVE/firmas real y que el runtime corresponde exactamente al digest firmado |

Se rechazan claves privadas como trust roots, ausencia de configuración, mismo certificado o issuer/audience compartidos, tokens caducados/alterados, errores de scope, firmas cruzadas, estado `blocked`, MFA antigua, fechas futuras o incongruentes y artefactos que no coinciden.

**Importante:** una firma comprueba la procedencia de una **declaración**, no demuestra que el emisor ejecutó una auditoría correcta. La presente implementación no declara superados los CVE del inspector; mientras las autoridades reales no estén aprobadas, **ninguna autorización operacional existe**.

## Protección en el ejecutor y auditoría

- `ManualRedriveEnv` elimina `inspectorReleaseApproved` y el operador de texto como habilitadores. Exige `authorization` que haya pasado el verificador, más `requiredInspectorImageDigest` configurado por el host confiable.
- La capacidad está vinculada a `commissionId`, `reviewId`, `requestKey`, `approvalRef`, `operatorSubject` e `imageDigest`. Al copiarla, serializarla o fabricar sus campos, deja de superar el `WeakSet`. Su validez se comprueba al entrar **y otra vez antes de Queue.send**. No se reutiliza entre operaciones.
- La migración **`0020_redrive_signed_attestation_digest.sql`** añade `authorization_sha256` a `processing_manual_redrives`. Requiere el digest para nuevos registros, valida el formato y prohíbe modificarlo. La huella se calcula sobre `JSON.stringify([approvalJwt,releaseJwt])`, codificado UTF-8, y se registra en la **misma transacción** que reserva el intento.
- El sistema **no** almacena las credenciales JWT, ni secretos de firma, ni claves R2. Para auditar un caso se deben custodiar externamente las dos constancias JWS originales y comparar su digest. El digest no sirve por sí solo como firma ni demuestra autorización material.
- La [revocación R2.7](R2_REDRIVE_REVOCATION_LEDGER.md) consulta una lista inmutable D1 y comprueba operador, aprobación, constancia, imagen y dos claves firmantes antes de reservar y antes de Queue. Si la autorización expira o se revoca tras la reserva pero antes del envío, el estado pasa a `halted` y **no se encola**; el intento sigue siendo único y no recuperable por simple replay. Se preservan las salvaguardas de R2.4/R2.5 y los diez intentos originales del outbox.

## Verificación y garantías

```sh
pnpm exec vitest run packages/auth/src/manual-redrive-authorization.test.ts
pnpm exec vitest run packages/data/src/manual-redrive.test.ts
pnpm typecheck
sh scripts/ci.sh
```

Los fixtures producen **tres pares RSA distintos** y JWT firmados de prueba; la identidad Access se verifica mediante JWKS sintético en red interceptada. Casos negativos: ausencia de token, firma adulterada, clave/issuer/audiencia incorrectos, trust roots compartidos, cambio de comisión o solicitud, acceso de operador ajeno, MFA no aprobada o caducada, release `blocked`, SBOM/informe incorrectos, imagen distinta, firmantes cruzados, pérdida de evidencia por clonación, caducidad después de reservar y manipulación del digest SQL. El E2E documental y de navegador sigue siendo independiente.

## Bloqueos previos a un host privado real

1. Aprobar **por separado** los orígenes, claves y ciclos de rotación de los firmantes; validar revocación y compromiso. Las claves RSA en fixtures no se despliegan.
2. Implementar y auditar la autoridad externa de aprobación humana/MFA. Un `mfa=verified` firmado por un emisor mal configurado no equivale a MFA real.
3. Implementar la **generación autenticada del release** desde el pipeline real Trivy/SBOM/firmas de ClamAV, con digest exacto del runtime y no solo un `pass` declarativo. El gate R1 sigue **bloqueante**.
4. Obtener autorización explícita para aprovisionar infraestructura Cloudflare, habilitar políticas Access/MFA, provisionar secretos/keys, publicar Containers e interconectar Queue/D1/R2. No se ha hecho.
5. Validar lifecycle de la capacidad dentro de **un mismo isolate** (no se serializa entre Workers), recuperación de errores, reloj, rotación de claves, límites de red y pruebas con el proveedor real. Sigue sin existir endpoint/cron/MCP habilitado de redrive.

**Este incremento refuerza el código pero no desbloquea un despliegue.**
