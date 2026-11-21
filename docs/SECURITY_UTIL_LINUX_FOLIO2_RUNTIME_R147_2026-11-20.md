# R1.47 · Integración experimental de util-linux 2.41.6 folio2 en el runtime (NO RELEASE)

**Investigación:** 20 de noviembre de 2026 (America/Lima); ejecución técnica 21 de noviembre UTC. **Seguimiento:** [G2 · issue #75](https://github.com/DawoT/folio-civico/issues/75). **Objeto:** unir dos líneas previamente aisladas: la imagen plana R1.46 del inspector y los ocho paquetes `util-linux folio2` reproducibles de R1.36–R1.39. **Resultado:** integración binaria y pruebas funcionales reales completas, pero CVE sin resolver formalmente y distribución de fuente sin firma de Debian. Todo permanece no desplegable.

## Punto de partida y evidencia de seguridad

El **Debian Security Tracker** marca Trixie `util-linux 2.41.5-0+deb13u1` como vulnerable para `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409` y `CVE-2026-78410`; Debian `forky/sid 2.42.4-1` aparece corregido, pero una sustitución directa desde esas ramas puede romper el ABI/las dependencias de Trixie. [Estado Debian](https://security-tracker.debian.org/tracker/source-package/util-linux).

El laboratorio reutiliza archivos fuente privados `2.41.6-0+folio2~deb13u1` creados y verificados en R1.36 y **dos compilaciones independientes** R1.37: sus 43 hashes SHA-256 coincidieron previamente; para este experimento se volvieron a contrastar directamente los SHA de **los ocho paquetes necesarios**, idénticos byte a byte entre ambas compilaciones. La **fuente folio2 local no tiene firma Debian propia**; no es un DSA ni actualización oficial.

El gate R1.39 de fuente, ejecutado otra vez contra el descriptor exacto, devolvió **exit 2 informativo** y verificó:

| Aviso | Evidencia estática del código local | Limitación |
|---|---|---|
| CVE-2026-76642 | Guarda de estado del mount helper antes de post-hooks | No se ejecutó regresión de explotación de montaje privilegiado |
| CVE-2026-78408 | Cierre de descriptores `cgroup.procs` antes de cambio de credenciales/exec | No se ejecutaron pruebas de namespaces privilegiados |
| CVE-2026-78409 | Ausencia de fast path detached vulnerable 2.42 y rechazo del usuario restringido en ruta heredada | **Discrepancia con la clasificación Trixie de Debian**; sin VEX |
| CVE-2026-78410 | Resolución de bind source restringido con `RESOLVE_NO_SYMLINKS` | No se ejecutó regresión de explotación |

Estas observaciones **no equivalen** a certificación del binario integrado ni a remediación oficial de los cuatro avisos.

## Integración OCI aislada y reproducible

| Propiedad | Valor |
|---|---|
| Imagen base R1.46 | `folio-civico-inspector:surface-pruned-research-r146` |
| ID base inmutable | `sha256:c0011755a54a4af8c749ef60a2d0f40be5a186dbb071ea19d760e34a7d8360ee` |
| Imagen de investigación R1.47 | `folio-civico-inspector:folio2-runtime-research-r147` |
| ID verificado de la construcción actual | `sha256:c506a8b40953167ee4f6486cb90217298a39ce680f0bdd5fdc3a8b9638ddb92d` |
| Publicación OCI, Preview y producción | **Ninguna** |

`Dockerfile.util-linux-folio2-runtime-research` recibe el origen R1.46 mediante una etiqueta local derivada del SHA y un contexto BuildKit nombrado de solo lectura con los ocho artefactos del directorio privado. Comprueba sus **ocho SHA-256 dentro del builder**, actualiza primero y configura las cinco bibliotecas para respetar `Pre-Depends: libblkid1 (= 2.41.6-0+folio2~deb13u1)` y después instala `bsdutils`, `login` y `util-linux`. No emplea `--force-depends`, descargas de APT ni `autoremove`. Verifica `dpkg --audit`, las ocho versiones completas/epochs, dependencias de motores y ausencia de `mount` instalado.

La imagen final se aplana con `FROM scratch` para no heredar capas con las bibliotecas Debian antiguas. Metadatos del contenedor idénticos a R1.46: `USER 65534:65534`, comando, variables, directorio y puerto; **cero capas OCI no vacías de R1.46 reutilizadas**. Los diez ejecutables SUID/SGID observados son **exactamente los mismos**, con permisos idénticos; no se incorporaron entradas privilegiadas nuevas. Se mantienen los motores ClamAV, QPDF, Poppler, Tesseract, Fontconfig, Expat y modelos OCR sin alterar su inventario de hashes.

El primer ensayo de instalación falló por el orden de configuración de `libblkid1`; el Dockerfile corrigió ese orden y la segunda construcción completó. La reejecución reproducible del wrapper devolvió **exit 2 esperado** tras build y smokes completos. En el contenedor de build, `update-alternatives` advirtió de la página de manual ausente de `more` (consecuencia del runtime minimizado); no afectó a estos smokes, pero exige revisión antes de cualquier hipotética imagen desplegable.

## Comparación Trivy y CycloneDX, sin ocultar CVE

El comparador `util_linux_folio2_runtime_audit.py` exige snapshots Trivy JSON y CycloneDX **sobre ambas imágenes, con la misma base descargada una sola vez**. Verifica la identidad por ID Docker, versión y PURL de ocho paquetes con epoch, paquete a paquete, **cero cambios en cualquier otro componente**, mismo conjunto de CVE y severidades (normalizado únicamente por la versión de esos ocho paquetes), inventarios nativos, SUID/SGID y capas OCI.

| Scanner | Antes R1.46 | Después R1.47 | Cambio |
|---|---:|---:|---:|
| CRITICAL | 0 | 0 | 0 |
| HIGH | **55** | **55** | **0** |
| UNKNOWN | **15** | **15** | **0** |
| HIGH de util-linux | **32** | **32** | **0** |
| HIGH+CRITICAL+UNKNOWN | **70** | **70** | **0** |

**Importante:** los ocho binarios instalados son distintos, pero Debian todavía registra los cuatro CVE en la rama Trixie. Ni el artefacto fuente local ni el cambio de versión permiten descartarlos del scanner. El gate **no** usa excepciones, `--ignore-unfixed`, VEX, filtros de severidad ni suprime advertencias. Evidencia válida: **exit 2** (`status=unsigned_folio2_integrated_runtime_research_release_blocked`); inválida/incompleta: **exit 3**. Se mantienen `cve_remediated=false`, `vendor_release_signed=false` y `release_authorized=false`.

El éxito del gate diferencial acredita **integración y ausencia de cambios ajenos detectables**; **no** la resistencia a los CVE mediante pruebas de explotación, una auditoría de fuente independiente, compatibilidad ABI exhaustiva ni autorización de producción.

## Pruebas reales y reproducción

Dentro de `--network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`, con límites de CPU/RAM/procesos y entradas **únicamente sintéticas**:
- `smoke_real_engines.py`: ClamAV identifica EICAR, PDF válido + OCR pasan, adjuntos/cifrado/malformado se rechazan; aislamiento de parser se conserva.
- `smoke_http_real.py`: salud y manifiesto válido; tokens no autorizados y SHA falsificado se rechazan.
- `smoke_signature_freshness.py`: firma fresca pasa y firma sintéticamente caducada (>72 horas) se bloquea.
- `compare_util_linux_folio2_quality.sh`: **exit 0**, corpus OCR sintético de cuatro muestras, **4/4 hashes de texto idénticos, cero errores de caracteres, cero regresiones** entre R1.46 y R1.47.
- Suites Python, TDD de invariantes de CVE/paquetes/SBOM/capas/privilegios, y CI shell local de web/API/Workers/E2E, antes de integrar vía PR.

Ejecutar exclusivamente en laboratorio local con las fuentes/binaries privados R1.36/R1.37 conservados:

```bash
bash apps/inspector/build_util_linux_folio2_runtime_research.sh \
  --source-dir /ruta/privada/r136-folio2 \
  --binary-dir /ruta/privada/r137-folio2
# exit 2: build y smokes funcionales, release denegado

bash apps/inspector/scan_util_linux_folio2_runtime_research.sh \
  --source-dir /ruta/privada/r136-folio2 \
  --binary-dir /ruta/privada/r137-folio2
# exit 2: evidencia estricta, release denegado
# exit 3: imagen, paquete, fuente, CVE o cadena de pruebas no acreditada

bash apps/inspector/compare_util_linux_folio2_quality.sh
# exit 0: solo si OCR sintético no presenta regresión
```

## Pendientes de seguridad que bloquean G2

1. Obtener versiones/patches oficialmente mantenidos para **Debian Trixie**, o producir una rama fuente reproducible y **firmada/atestada**, con revisión independiente de los cuatro avisos y regressions de casos adversariales; formalizar la discrepancia de `CVE-2026-78409` sin generar VEX por inferencia.
2. Acreditar exhaustivamente seguridad y compatibilidad de `libmount`, `libblkid`, `libuuid`, `util-linux`, `login`, y dependientes, incluidos límites de privilegio/SUID en el contexto exacto. Revisar incidencia del aviso `update-alternatives` antes de release.
3. Remediar **los 23 HIGH ajenos a util-linux, 32 HIGH de esa familia y 15 UNKNOWN** según advisories y reachability; completar inventarios de fuentes Poppler/Tesseract y ClamAV.
4. Construir **otra imagen final autorizada por digest**, escanear Trivy/CycloneDX/ELF, ejecutar corpus adversarial, pruebas de caducidad de firmas, G2 **exit 0** y obtener aprobación humana.

**Decisión formal:** `blocked_runtime_release`. No se ha publicado OCI, modificado Dockerfile operativo, ejecutado deploy/Preview/D1 remoto ni admitido documentos institucionales.
