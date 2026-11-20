# R1.38 — Control de cuatro CVE y consumidores Debian reales (NO RELEASE)

> **Fe de erratas R1.39 (2026-11-20):** la atribución de CVE-2026-78409 a la fuente `folio2` fue un **falso positivo de aplicabilidad**: el verificador R1.38 exigía un parche de una ruta de ejecución introducida en util-linux 2.42, mientras que la rama 2.41.6 bloquea `X-mount.subdir` de usuarios restringidos antes de entrar al montaje temporal. Los avisos upstream/Red Hat consideran no afectada la línea 2.41; Debian aún marca Trixie vulnerable. Los datos de abajo se conservan como registro histórico de la hipótesis inicial, **no como conclusión vigente**. Véase [dossier y prueba corregida R1.39](SECURITY_UTIL_LINUX_CVE_78409_APPLICABILITY_R139_2026-11-20.md). La puerta G2 sigue bloqueada.

**Fecha:** 2026-11-20. **Base:** R1.37 / PR #98 fusionada con CI completa verde en `main` (`5d7acf5e11abcfc608ca6d645c2611b3985cdfa4`). **Ámbito:** investigación en `util-linux 2.41.6-0+folio2~deb13u1`, sin instalar paquetes, construir o publicar una nueva imagen, ni levantar G2.

## Hallazgo crítico: CVE-2026-78409 no cuenta con el guard esperado en folio2

La fuente R1.36 fue autenticada con los **tres hashes SHA-256 fijos** antes de hacer `dpkg-source --no-check -x` dentro de un directorio privado temporal. El verificador `apps/inspector/util_linux_folio2_cve_regression.py` examina siete archivos fuente y cuatro rutas de seguridad. Es un **control estático de guardas de código**, no una reproducción de explotación ni una certificación CVE.

| CVE | Propiedad inspeccionada en `folio2` | Resultado |
| --- | --- | --- |
| `CVE-2026-76642` | `mnt_context_do_mount()` no invoca `MNT_STAGE_MOUNT_POST` si falla el mount helper (`is_mount_stage_failed`) | Guarda presente |
| `CVE-2026-78408` | Descriptor `cgroup.procs` abierto con `O_CLOEXEC`, cerrado tras `join_into_cgroup()`; llamadas seleccionadas de `unshare` con `O_CLOEXEC` | Guardas presentes |
| `CVE-2026-78409` | `X-mount.subdir` debe resolver dentro del árbol desacoplado sin symlinks intermedios, con `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, ruta relativa y sin `open_tree` inseguro | **Guarda ausente: gate FAIL / exit 3** |
| `CVE-2026-78410` | Fuente restringida resuelta con `mnt_open_tree` + `RESOLVE_NO_SYMLINKS`; canonicalización restringida y `hook_idmap` con guard equivalente | Guardas presentes |

**Evidencia material de CVE-2026-78409:** la fuente `libmount/src/hook_subdir.c` (SHA-256 `5a832d08ed196100f1f53f4badb2b9c09fe79f371c9b1bcf5ee273d852c302bc`) aún contiene `open_tree(api->fd_tree, subdir, OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE)` y no elimina las barras iniciales de `X-mount.subdir`. `libmount/src/hook_mount.c` (SHA-256 `099733e68154f3e0cc2a90be731dc323adad0e393861e55a3f54f1738256cf79`) tampoco contiene la rama `mnt_open_tree(... RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)` del parche publicado.

El commit upstream específico `ed072cf2297b68f86af8e08209907f605dd42e5d` [implementa protección contra symlinks intermedios y recorrido fuera del árbol](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/ed072cf2297b68f86af8e08209907f605dd42e5d%5E!/). Las [notas upstream de 2.41.6](https://lists.openwall.net/linux-kernel/2026/09/02/753) registran CVE-2026-76642, 78408 y 78410, pero no 78409. Por tanto, **el nuevo binario folio2 no acredita la remediación de CVE-2026-78409**. El paquete fuente se conserva byte por byte, no se introdujo un parche silencioso.

Comando reproducible:

```bash
python3 apps/inspector/util_linux_folio2_cve_regression.py \
  --source-dir /ruta/privada/r136-folio2
# Exit 3 esperado en la fuente actual:
# missing_source_guards=["CVE-2026-78409"]
# release_authorized=false; cve_remediated=false
```

Las otras tres propiedades estáticas presentes **tampoco** son pruebas de explotación ni acreditan remediación a nivel runtime; el informe fuerza `runtime_cve_regressions_passed=false`. Ninguna prueba realiza montajes, namespaces, escalada de privilegios o cambios en `fstab`.

## ABI de consumidores Debian stock: siete utilidades / cinco bibliotecas

El segundo ejecutable `apps/inspector/util_linux_folio2_consumer_smoke.py` admite exclusivamente las cinco bibliotecas candidatas `folio2` cuyos hashes SHA-256 coinciden con la salida reproducible R1.37 (43/43 en el dossier anterior). También admite cuatro paquetes de referencia descargados mediante índices APT firmados de Debian 13.7. **El descriptor `folio2` no es una fuente oficial firmada; los artefactos de referencia Debian sí proceden de APT autenticado.**

| Archivo Debian stock extraído en laboratorio | SHA-256 |
| --- | --- |
| `fdisk_2.41.5-0+deb13u1_amd64.deb` | `7f37094ca3f63c3a07b4431532b0bcc4aa64291e75c48cabebf41bf42ad706b1` |
| `uuid-runtime_2.41.5-0+deb13u1_amd64.deb` | `826690419ef231e93d3d756ab19835ebd0fe3029bb1314987fd8f76fd04c6983` |
| `libreadline8t64_8.2-6_amd64.deb` | `eeadf2b5e755c9f183883feea2d9b5b28560284275d5f54d3e55d0923b1d0967` |
| `libncursesw6_6.5+20250216-2_amd64.deb` | `47baa2e11579583654583a066b69bd5a5d2f22423081f707ed6c0c3ba6d538b7` |

Prueba ejecutada dentro de Debian **13.7/amd64** fijado al digest OCI `sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2`, con `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 1000:1000`, sin ejecución privilegiada, sin instalación ni acceso a producción. Los paquetes `.deb` solo se extraen mediante `dpkg-deb -x` a `tmpfs` efímero `/scratch`. Los binarios Debian stock `lsblk`, `findmnt`, `blkid`, `mount`, `umount`, `uuidgen` y `fdisk` ejecutaron operaciones no mutantes; `LD_DEBUG=libs` confirmó la carga efectiva de **libmount.so.1, libblkid.so.1, libsmartcols.so.1, libuuid.so.1 y libfdisk.so.1** desde las bibliotecas candidatas `folio2`.

Comando de evidencia:

```bash
python3 apps/inspector/util_linux_folio2_consumer_smoke.py \
  --binary-dir /ruta/privada/r137-folio2 \
  --stock-dir /ruta/privada/apt-debian13
# Exit 2 esperado: siete consumidores, cinco DSO candidatas realmente cargadas
# release_authorized=false; debian_trixie_abi_validated=false
```

Este smoke prueba **enlace dinámico y arranque de comandos seguros**, no compatibilidad ABI exhaustiva, integridad de semántica de llamadas, operaciones de disco/montaje ni resistencia a explotaciones de los CVE. Las referencias stock se obtuvieron y ejecutaron por separado de los `.deb` candidatos, sin modificar el host. El verificador rechaza también cualquier fichero `.deb` extra que no coincida con las 43 identidades del inventario R1.37, evitando selecciones ambiguas mediante glob.

## Pruebas y siguiente paso

Las pruebas TDD verifican la presencia/ausencia de guardas por CVE, alteraciones deliberadas de fuente, versiones/hash de cinco paquetes binarios, permisos, rechazos de ficheros inesperados, modo no root y límites del contenedor. El resultado real **3/4 guardas presentes, 1/4 ausente** es el comportamiento esperado **de detección de un defecto**, no una suite de seguridad superada.

**Resultados ejecutados (2026-11-20):** el verificador CVE se ejecutó independientemente contra las **dos fuentes privadas folio2** de R1.36; ambas devolvieron `exit 3`, con la única entrada en `missing_source_guards` igual a `CVE-2026-78409`. El smoke de consumidores se ejecutó contra las **dos compilaciones binaras privadas folio2** de R1.37; ambas devolvieron `exit 2`, siete comandos aprobados y cinco bibliotecas candidatas comprobadas en `LD_DEBUG=libs`. El resultado de ambas pruebas conserva `release_authorized=false`.

**TDD:** 20 nuevas pruebas (`8` controles de fuente CVE y `12` de consumidores/hashes/aislamiento, incluido rechazo de un `.deb` adicional no declarado); `py_compile` aprobado. Después de incorporar los cambios concurrentes del `main` (incluidas PR #99 OCR y #96 CI), el conjunto completo del inspector pasó **450/450** pruebas Python. Los artefactos permanecen fuera de Git, en carpetas privadas; la salida fuente de prueba de seguridad fallida no debe convertirse en un resultado verde artificial.

Para R1.39: portar con revisión manual el parche upstream CVE-2026-78409 a la **rama 2.41.6** (las estructuras de `hook_mount` y `hook_subdir` difieren de la rama 2.42), generar versión distinta `folio3` y `.dsc` con entrada quilt explícita; comprobar rutas relativas/absolutas, symlinks intermedios y `..` mediante pruebas no privilegiadas, repetir extracción de fuente y builds, consumidores ABI y CVE, y solo después plantear una imagen OCI aislada con CycloneDX/Trivy del digest exacto.

**Security gate G2: BLOCKED.** Debian Trixie oficial sigue marcando los cuatro CVE como vulnerables; no hay autorización de release, `VEX`, waiver, escaneo de imagen candidata ni despliegue. El código R1.38 incrementa la detección y la evidencia, **no parchea el runtime**.
