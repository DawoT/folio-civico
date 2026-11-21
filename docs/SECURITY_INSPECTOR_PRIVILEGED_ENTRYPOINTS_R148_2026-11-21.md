# R1.48 · Supresión física de entrypoints privilegiados en el runtime de investigación (NO RELEASE)

**Fecha:** 21 de noviembre de 2026, America/Lima. **Seguimiento:** [G2 #75](https://github.com/DawoT/folio-civico/issues/75). **Alcance:** endurecer una copia local no desplegable del inspector R1.47 sin cambiar la versión de bibliotecas, fuentes CVE ni política de release.

## Estado vendor y decisión

Revisión del [Debian Security Tracker para util-linux](https://security-tracker.debian.org/tracker/source-package/util-linux) el 21/11/2026: Debian Trixie conserva `2.41.5-0+deb13u1` como vulnerable para `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409` y `CVE-2026-78410`, clasificados `no-dsa`; `forky/sid` tiene `2.42.4-1` corregido. No existe un backport Debian Trixie mantenido para esos avisos en el tracker consultado. **No se mezclaron bibliotecas de forky/sid en Trixie**.

R1.47 usa `util-linux 2.41.6-0+folio2~deb13u1`, compilación fuente local sin firma Debian. La inspección de archivos de esa imagen reveló `nsenter` y `unshare` ejecutables, así como herramientas administrativas SUID/SGID innecesarias para validar documentos; no es una demostración de explotación bajo `UID 65534`, `no-new-privileges` y `cap-drop ALL`. Sin embargo, sus puntos de entrada amplían la superficie del contenedor. **R1.48 elimina físicamente esos binarios, pero no atribuye remediación oficial de CVE ni modifica el escáner**.

## Identidad y construcción

| Objeto | Valor |
|---|---|
| Base inmutable R1.47 | `sha256:c506a8b40953167ee4f6486cb90217298a39ce680f0bdd5fdc3a8b9638ddb92d` |
| Etiqueta experimental | `folio-civico-inspector:privileged-cli-pruned-research-r148` |
| ID de imagen local examinada | `sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a` |
| Dockerfile | `apps/inspector/Dockerfile.privileged-cli-research` |
| Publicación de OCI/Cloudflare/Preview | Ninguna |
| Estado de G2 | **Bloqueado** |

El Dockerfile de investigación verifica los modos exactos de cada ejecutable y del alias `sg` antes de retirarlos, rechaza divergencias y conserva el usuario y el comando del inspector. La etapa final `FROM scratch` elimina la posibilidad de recuperar los bytes de los ejecutables desde capas OCI antiguas. No hay `apt autoremove`, repositorios APT, cambios de paquete, mezclas de distribuciones, modificación de `apps/inspector/Dockerfile` productivo ni instalación en el host.

El conjunto suprimido, **15 rutas físicas exactas**, es:

- Nueve ficheros con SUID/SGID: `/usr/bin/chage`, `chfn`, `chsh`, `expiry`, `gpasswd`, `newgrp`, `passwd`, `su` y `/usr/sbin/unix_chkpwd`.
- Un alias a comando privilegiado: `/usr/bin/sg` (symlink a `newgrp`).
- Cinco comandos de namespaces/identidad: `/usr/bin/nsenter`, `unshare`, `login`, `setpriv` y `/usr/sbin/runuser`.

**Importante:** los paquetes Debian que entregaron esos binarios siguen inventariados como instalados; algunos ahora contienen archivos deliberadamente ausentes en la imagen runtime. Es una técnica de minimización de imagen por capas, **no una actualización Debian mantenida ni una imagen lista para recibir transacciones `dpkg`**.

## Comparador diferencial estricto

`scan_privileged_cli_research.sh` obtiene la base Trivy una sola vez, ejecuta dos escaneos JSON y dos CycloneDX con el **mismo snapshot**, inspecciona identidades Docker y capas OCI, y compara las fuentes nativas/ELF/modelos OCR con su manifiesto SHA-256. Como prueba más fuerte de inexistencia de cambios colaterales, `runtime_executable_surface_inventory.py` calcula hash SHA-256 de **todos los ficheros regulares accesibles** del filesystem persistente desde un contenedor no conectado a red, raíz de solo lectura, UID0 pero sin capacidades ni `new-privileges`, exclusivamente para leer ficheros root-owned sin exportar su contenido. Excluye los pseudo-filesystems `/proc`, `/sys`, `/dev`, `/tmp`, `/run` y los tres ficheros dinámicos que Docker inyecta en `/etc` (`hosts`, `hostname`, `resolv.conf`); los nombres y exclusiones son contratos exactos, no manipulables por CLI.

El verificador rechaza cualquier alta, baja, cambio de permisos, symlink o SHA-256 fuera del conjunto de las 15 rutas autorizadas; también exige que sus modos iniciales sean los observados y que el árbol resultante no tenga ningún archivo regular SUID/SGID. **Inspección real del filesystem:** **6.528 entradas iniciales / 6.513 finales**, **15 rutas eliminadas**, cero altas y cero modificaciones ajenas. El contenedor continúa con `UID 65534`, mismo `Entrypoint`, `Cmd`, `Env`, `ExposedPorts`, `Workdir`, y ninguna capa OCI de contenido histórico reutilizada.

| Trivy (misma DB y misma fuente) | R1.47 | R1.48 |
|---|---:|---:|
| CRITICAL | 0 | 0 |
| HIGH | **55** | **55** |
| UNKNOWN | **15** | **15** |
| HIGH util-linux (4 CVE × 8 paquetes) | **32** | **32** |
| HIGH + CRITICAL + UNKNOWN | **70** | **70** |

**Exit 2** del comparador: prueba completa de reducción física e invariantes de scanner, **no** aprobación. **Exit 3**: evidencia insuficiente o manipulada, también falla. Tests negativos requieren conservación de las 32 entradas HIGH de util-linux y detectan anomalías de filesystem, SBOM, advisory, ELF, ID de imagen, capa, symlink y SUID.

## Funcionalidad y límites

`build_privileged_cli_research.sh` usa exclusivamente el base ID pinneado, build offline `--network=none --pull=false` y smokes del inspector real bajo `--network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges`: ClamAV/EICAR, rechazos PDF cifrado/adjunto/malformado, extracción Poppler, OCR Tesseract, HTTP e identidad de manifiesto, firmas ClamAV vigentes y rechazo sintético al exceder 72 horas. La comparación OCR adicional utilizó cuatro PDFs sintéticos y hashes de texto: **4/4 coincidencias, 0 errores de caracteres, 0 regresiones, exit 0**. La suite Python completa del inspector aprobó **570/570**, incluyendo ocho tests nuevos con mutaciones adversariales; `python3 -m py_compile` y `bash -n` aprobaron.

Comandos de laboratorio (no ejecutar con datos institucionales ni publicar la salida):

```bash
bash apps/inspector/build_privileged_cli_research.sh
# exit 2 esperado: build y smokes reales correctos, pero G2 bloqueado
bash apps/inspector/scan_privileged_cli_research.sh
# exit 2 esperado: evidencia diferencial completa; release bloqueado
bash apps/inspector/compare_privileged_cli_quality.sh
# exit 0 sólo cuando no hay regresiones de los cuatro PDFs sintéticos
```

La supresión de `nsenter` elimina el ejecutable específico al que se refiere `CVE-2026-78408`, pero **no acredita que el código de `libmount`, `libblkid` o los demás paquetes sea invulnerable** ni resuelve automáticamente los tres avisos restantes. Los comandos privilegiados ya estaban sujetos a `no-new-privileges`; su eliminación es defensa en profundidad. No se ejecutaron explotaciones SUID, montajes de host, cambios de `/etc/fstab`, operaciones de namespaces privilegiados ni pruebas con documentos reales.

## Criterio de cierre

**G2 continúa `blocked_runtime_release`**: pendientes 55 HIGH, 15 UNKNOWN, revisión de cuatro CVE util-linux con parches mantenidos por Debian Trixie o atestación de fuente/binario y regressions específicos, ClamAV/Expat y cobertura CVE de Poppler/Tesseract. No VEX, waiver, OCI remoto, deploy ni autorización de release. La integración de código de investigación puede realizarse con su propio CI completo verde, **pero no habilita producto**.
