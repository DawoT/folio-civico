# R1.40 · Candidata real reconstruida, smoke íntegro y gate CVE bloqueante

**Fecha:** 2026-11-20 (America/Lima). **Seguimiento:** [#68](https://github.com/DawoT/folio-civico/issues/68). **Estado:** ingeniería validada localmente; **NO RELEASE**.

## 1. Construcción y contexto exacto

Se ejecutó el procedimiento del repositorio, sin modificar Dockerfile ni el gate:

    bash apps/inspector/validate_real_engines.sh --candidate

El `apps/inspector/preflight.py --mode build` devolvió **exit 0**, sin problemas; 157,52 GiB libres y 51,98 GiB disponibles de RAM al inicio. El script ejecuta construcción de la etiqueta **exclusivamente local** `folio-civico-inspector:ocr-integrated`, con `CLAMAV_SIGNATURE_REFRESH_EPOCH` nuevo. El build progresó por la etapa verificadora de firma **GPG detached** del paquete oficial ClamAV (huella primaria Talos fijada en Dockerfile), compilación de Tesseract 5.5.4 y `freshclam`. El log de build registra la prueba de las tres bases descargadas:

| Base oficial | Versión observada | Resultado |
|---|---:|---|
| `daily.cvd` | 28189 | Database test passed |
| `main.cvd` | 63 | Database test passed |
| `bytecode.cvd` | 339 | Database test passed |

**Digest local construido y escaneado:** `sha256:b5aadc6c3bfc60471070095c60f756552f83452989017581081e341e0b9adb8a`. Configuración observada: `linux/amd64`, `USER 65534:65534`. Motores ejecutados directamente por ese ID con Docker sin red: **ClamAV 1.5.5**, **Tesseract 5.5.4** y **QPDF 12.2.0**. Se verificó la presencia, tamaño no nulo y edad corta de `main.cvd`, `daily.cvd` y `bytecode.cvd`.

**Procedencia del código del build:** trabajo aislado en commit `ed16913a7b8b1c1a0fd2e3ecc15538b414efaf8a` (R1.39; incorporado a `main` mediante PR #104). Se comparó el texto completo de los **7 artefactos del contexto operativo** (`Dockerfile`, `inspector.py`, `fixtures.py`, `preflight.py`, `smoke_real_engines.py`, `smoke_http_real.py` y `.dockerignore`) con `origin/main` en `353e0d642cb7314df41ad47f60c7ee9a759cc965`: **7/7 idénticos**. Esta comparación acredita identidad de esos **archivos fuente**, no atestación reproducible de todos los paquetes Debian, compiladores o ELF.

No se usó material institucional, no se publicó una imagen y no se activó ningún servicio remoto.

## 2. Smoke del inspector completo con motores reales

**Resultado de `validate_real_engines.sh --candidate`: exit 0**, incluyendo ejecución de `smoke_real_engines.py` y `smoke_http_real.py` dentro de la imagen real, sin red, con filesystem read-only, caps eliminadas, PIDs limitados, cgroup de 4 GiB y fixtures sintéticos temporales.

| Grupo real | Resultado |
|---|---|
| ClamAV: patrón EICAR inocuo | `detected` |
| Extracción PDF nativa | `passed` |
| OCR real | `passed` |
| PDF cifrado antes de Poppler | `passed` |
| PDF cifrado, con adjuntos y malformado | `rejected` en todos |
| Variables/secretos del proceso padre | `isolated` |
| HTTP salud y manifiesto sin firma | `passed` |
| HTTP token no autorizado y hash falsificado | `rejected` en ambos |
| Firmas ClamAV vigentes | `passed` |
| Reloj lógico con firmas >72 h | `blocked` |

Los resultados corresponden al **inspector operativo** y no a la imagen Debian experimental de R1.39. Aun así, los smokes solo cubren el pequeño corpus sintético definido, y **no** demuestran seguridad de documentos hostiles arbitrarios, fidelidad de planos complejos o CVE resueltos.

## 3. Gate estricto Trivy y CycloneDX

Se ejecutó, sin `--ignore-unfixed` ni exclusiones:

    bash apps/inspector/audit_image.sh --candidate --triage --advisories

**Resultado obligatorio: `exit 2 / blocked`**. El script comprueba inmutabilidad de la etiqueta durante el análisis, usa el ID del contenedor para inventariar ELF y cruza Trivy, SBOM, advisories y triage sin permitir que un informe auxiliar convierta un rechazo en aprobación.

| Indicador verificado | Valor |
|---|---:|
| CRITICAL | 0 |
| HIGH | **128** |
| UNKNOWN | **15** |
| Total bloqueantes HIGH + CRITICAL + UNKNOWN | **143** |
| MEDIUM / LOW | 189 / 203 |
| Hallazgos totales | 535 |
| Componentes del SBOM CycloneDX | 166 |
| Paquetes con hallazgos bloqueantes | 41 |
| Bloqueantes con vínculo dinámico observado | 81 |
| Bloqueantes sin vínculo observado en `ldd` | 62 |
| Propietarios Debian de DSO no resueltos | 4 |
| Componentes compilados desde fuente sin cobertura completa de advisories | **1 (Tesseract)** |

`ldd` sin vínculo visible **NO** equivale a no alcanzabilidad ni «not affected». Trivy v**0.76.2**, DB v2 `UpdatedAt=2026-11-20T18:59:53Z`, descargada `2026-11-20T22:41:41Z`. La evolución frente a inventarios anteriores se debe conciliar por ID de advisory y DB, **no** por diferencias de conteos.

**Prioridades de revisión, sin dispensas:** cuatro paquetes Kerberos con **14 HIGH cada uno** (56), observados en bibliotecas de herramientas Poppler; **ClamAV 7 HIGH**; **Expat 4 HIGH + 2 UNKNOWN**, entre otras dependencias. El inventario nativo detecta Tesseract 5.5.4 compilado desde fuente y deja la cobertura CVE **pending_review**; no hay VEX ni equivalencia source→ELF reproducible completa, aunque el inventario contiene huellas observadas de ejecutable, biblioteca y modelos. El gate **permanece bloqueante**, independientemente del smoke.

## 4. Endurecimiento de la cadena de prueba (cambio de código R1.40)

El script `apps/inspector/validate_real_engines.sh` usaba la **etiqueta mutable** como argumento de cuatro `docker run` después del build. Esto podía hacer que un cambio concurrente de tag hiciera probar una imagen distinta.

Se modificó solamente la orquestación de validación:

1. Tras construir, resuelve el `docker image inspect ... .Id` y exige el formato completo `sha256:[a-f0-9]{64}`.
2. Usa **exclusivamente ese ID** y `docker run --pull never` en las cuatro ejecuciones Docker (gates de dependencias, motores/PDF/AV, HTTP y caducidad). No hay consultas implícitas al registro durante las pruebas.
3. Relee el tag tras todos los smokes y rechaza cualquier retargeting con `exit 3, image_changed_during_smoke`. El fracaso en obtener un ID o una ejecución no se convierte en `passed`.
4. No modifica imagen operativa, código del inspector, flags de seguridad, Trivy, ClamAV, documentación de identidad ni condiciones de release.

TDD **Red → Green**. Nuevo contrato en `test_deployment_gates.py` que verifica además los cuatro `docker run --pull never`; prueba ejecutable con Docker y preflight **simulados solo en el test unitario** (`test_inspector_candidate_image_pin.py`), cubriendo: ID estable (4/4 invocaciones), cambio de tag (exit 3) e ID inválido (exit 3 antes de cualquier smoke). Los 3 tests dinámicos también pasan en Python **3.12** dentro de un contenedor sin red, read-only, UID no-root y `/tmp` no ejecutable. El **smoke real descrito en `2` fue ejecutado con el script anterior**; la modificación no altera los comandos internos del contenedor ni su contenido, pero su orquestación debe validarse de nuevo si se desea afirmar equivalencia end-to-end del script endurecido.

**Regresión Python en rama R1.40:** 471/471 tests y 620 subtests, validación sintáctica Bash satisfactoria. La ejecución integral `scripts/ci.sh` y CI remoto del PR se registran por separado; no se confunden con Trivy.

## 5. Gates pendientes y gobierno

- **CVE/Trivy: BLOCKED (exit 2)**, 143 hallazgos bloqueantes más cobertura nativa pendiente. Prohibido relajar, ignorar UNKNOWN o declarar VEX sin evidencia y aprobación.
- **Modelo de amenazas / QA:** ampliar documentos A1/A0 según contrato de producto y PDF/PNG adversarial moderado; los smokes reales no prueban seguridad absoluta.
- **Supply chain:** identidad y firma de ClamAV comprobadas en build; falta cerrar cobertura por advisory y atestación reproducible de la cadena completa fuente→ELF para el artefacto elegido.
- **Ciclo operativo:** imagen nueva con bases actuales está disponible **solo localmente**. Falta automatizar/validar renovación antes de 72 h, rollback, control de digest del artefacto desplegado y permisos/costes del entorno remoto.

**`inspector_full_pipeline_synthetic_verified=true`; `scanner_vendor_signature_build_verified=true`; `trivy_release_gate_passed=false`; `all_source_cve_coverage_verified=false`; `safe_for_untrusted_pdf_verified=false`; `release_authorized=false`.**

**No OCI publicado, Cloudflare, D1 remoto, Preview, producción, datos institucionales ni CVE cerrado. Issue #68 permanece ABIERTO.**
