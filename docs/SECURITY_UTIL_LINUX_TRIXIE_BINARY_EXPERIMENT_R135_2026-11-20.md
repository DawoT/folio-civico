# R1.35 — Compilación binaria aislada de util-linux para Debian Trixie (NO RELEASE)

**Fecha:** 2026-11-20 (America/Lima). **Origen:** R1.34 integrada en `main` por PR #85. **Alcance:** laboratorio local no privilegiado del host, sin Dockerfile productivo, instalación de binarios, VEX, SBOM nueva, publicación de imagen ni despliegue.

## Hipótesis y límite de confianza

La evidencia de R1.33/R1.34 identifica los **tres archivos fuente** experimentales:

- Upstream `util-linux_2.41.6.orig.tar.xz`: SHA-256 `e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed`.
- Descriptor `util-linux_2.41.6-0+folio1~deb13u1.dsc`: `ec1d158d4b8a17d74e31dafccbe9a755a323497d6cc4bef88ccc599c9bfbc752`.
- Quilt `util-linux_2.41.6-0+folio1~deb13u1.debian.tar.xz`: `8449886af6bd4d2cf9c4753596719c380ba951e7d220e27610aa6c881426a5e7`.

El tar upstream original y el paquete Debian de Trixie fueron verificados criptográficamente por R1.33; **el .dsc experimental no está firmado**. El archivo `UNSIGNED_SOURCE_ONLY.json` de R1.34 es evidencia local no firmada. R1.35 exige **los tres hashes inmutables**, formato y estado `release_authorized=false`, permisos privados y ausencia de archivos adicionales: no confía exclusivamente en un JSON editable.

## Builder de Debian 13.7 y controles

`apps/inspector/build_util_linux_trixie_binary_experiment.sh` usa **solo Docker local**, tras `preflight.py --mode build`. Imagen base fijada por digest OCI:

`docker.io/library/debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2`

En el contenedor se exige Debian `13.7` / `amd64`, se habilita temporalmente `deb-src` en APT oficial con firmas verificadas (la red Docker bridge del laboratorio **no constituye filtrado de egreso**), se instalan dependencias **solo en la raíz efímera del contenedor**, se aplica la fuente con `dpkg-source` y se intenta `dpkg-buildpackage --build=binary --no-sign --jobs=2`. Se limitan CPU (2), RAM (6 GiB), procesos (512), capacidades y privilegios. No se monta Docker socket ni credenciales. Las fuentes y el parche se montan solo lectura; el único bind mount escribible es un **directorio nuevo privado** de artefactos experimentales. El contenedor se elimina con `--rm`.

La primera prueba con `--cap-drop ALL` impidió que APT ejecutara correctamente su separación de usuarios; el builder usa las capacidades limitadas necesarias para esa tarea (`CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `FOWNER`), sin `SYS_ADMIN`, sin modo privilegiado ni capacidades al host. El validador final opera con `--read-only --network none --cap-drop ALL --security-opt no-new-privileges`.

## Defecto de compilación detectado y parche diferenciado

Una compilación completa del paquete de fuentes R1.34 falló en `libmount/src/hook_idmap.c:335`: `RESOLVE_NO_SYMLINKS` usado sin declaración visible. El upstream `lib/fileutils.c` ya incluye `<linux/openat2.h>` bajo `HAVE_LINUX_OPENAT2_H`, mientras `hook_idmap.c` no. El ajuste se limita a la inclusión condicional del mismo encabezado.

Parche adicional **exclusivo de investigación, no incorporado al .dsc experimental original**:

`apps/inspector/research_patches/util-linux-2.41.6-r135-openat2-include.patch`

SHA-256: `cf8166e6d0cc5472bf7e78753f81e7c6b68f43a5784668c1a748baed4508a179`. Se exige `git apply --check` primero, después aplicación solo forward; el tar upstream no se edita. El archivo fuente resultante se hashea por separado en el laboratorio. **Este patch adicional impide tratar los binarios como derivación exacta del .dsc sin una siguiente revisión quilt y versión fuente propia.**

## Versionado con epoch de cuatro binarios Debian

`dpkg-buildpackage` generó **43 paquetes `.deb`** desde el origen experimental. De ellos, 39 llevan `2.41.6-0+folio1~deb13u1`; **`bsdutils` y `bsdutils-dbgsym`** tienen `1:2.41.6-0+folio1~deb13u1`, y **`login` y `login-dbgsym`** tienen `1:4.16.0-2+really2.41.6-0+folio1~deb13u1`. El validador acepta exclusivamente esos dos grupos de excepciones, fijados por identidad de paquete; rechaza cualquier versión arbitraria, arquitectura ajena o fuente diferente de `util-linux`.

## Evidencias y restricciones

- Compilación y preflight locales: no se instaló ninguna dependencia en el **host Ubuntu 24.04**; todos los paquetes de compilación se instalaron en contenedores Debian descartables.
- Regresiones Python del inspector: **364/364** sobre la rama rebasada con cambios concurrentes de `main`; incluyen TDD sobre permisos privados, hashes, fuente alterada, aplicación invertida de patches, ambas familias con epoch, procedencia del parche y ausencia de privilegios/publicación. `py_compile` y `bash -n` aprobaron.
- Cualquier `.deb` resultante es **EXPERIMENTAL / UNRELEASED / NO SIGNED**. No se permite añadir estos ficheros a la imagen del inspector ni instalarlos sobre host o servicios. Un inventario de paquetes generados no prueba compatibilidad ABI, cierre de CVE ni corrección de la imagen.
- Los cuatro CVE `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409`, `CVE-2026-78410` permanecen vulnerables para Trixie según el [Debian Security Tracker](https://security-tracker.debian.org/tracker/source-package/util-linux), aún con `2.41.5-0+deb13u1`. No hay VEX, waiver ni excepción al gate.

## Resultado final / auditoría de salida

En la quinta ejecución se completó `dpkg-buildpackage`, con **43 paquetes `.deb`** conservados en un directorio privado. El wrapper rechazó correctamente un epoch no contemplado (`bsdutils`: `1:...`) y devolvió **exit 3**; el contrato se corrigió sin modificar los artefactos construidos. Sobre ese conjunto ya generado, el verificador Python devolvió **exit 2 previsto** con los 43 hashes individuales y `release_authorized=false`; un contenedor Debian 13.7 independiente, sin red, sin capacidades y con raíz de solo lectura, comprobó el metadata `Package`/`Version` de **43/43** y devolvió **exit 0**. Se necesitó UID/GID del propietario de la evidencia `0700` y un `/tmp` efímero `tmpfs` para el análisis no privilegiado. Esta quinta ejecución, considerada aisladamente, **no constituía una ejecución integral aprobada**. La sexta ejecución documentada a continuación cierra esa comprobación.

Comprobación ELF **estática, sin instalación ni ejecución de los binarios**, sobre cinco bibliotecas extraídas a un directorio temporal del host: `libuuid.so.1`, `libblkid.so.1`, `libmount.so.1`, `libsmartcols.so.1` y `libfdisk.so.1` conservan sus SONAME esperados. La comprobación termina correctamente, pero **no acredita compatibilidad de símbolos versionados, ABI de dependientes ni comportamiento real**. El directorio temporal usado para extracción fue eliminado.

Hashes SHA-256 de una selección de binarios experimentales de la quinta ejecución (no firmados): `util-linux` `3600618e144d3ced8dc430d6b5304dba8c7eeeb16b5856907d52d4e9bb10a85d`, `libmount1` `85a1bb660023aa8bba32590bf1e2cf11cbdccbe11312cb4ffca4c31f57c4bc9b`, `libuuid1` `4d1e2fab8e6aefff84ddd9c5f9293fd3c007cc2ba92b1aedf990eaca7064799e`. Evidencia del fuente `hook_idmap.c` compilado con el patch adicional: SHA-256 `e12678246515279507185598710821dc23387b08b84b4eeb9b4977e733e391c1`.

**Sexta ejecución integral verificada:** `bash apps/inspector/build_util_linux_trixie_binary_experiment.sh --source-dir <directorio-fuente-privado> --output-dir <nuevo-directorio-privado>` terminó con **exit 2 esperado** tras `dpkg-buildpackage` completo, inspección offline Debian **13.7/amd64** con `--read-only`, `--network none`, `--cap-drop ALL`, UID/GID sin privilegios y `tmpfs` temporal; manifiesto Python de salida con **43/43 paquetes**, hashes SHA-256 individuales, metadata de `Source/Version/Architecture`, versión especial con epoch y `release_authorized=false`. El fichero `UNSIGNED_BINARY_RESEARCH_ONLY.json` está en directorio de evidencia local y **no se versiona ni publica como release**.

**Reproducibilidad de dos builds aislados en el mismo entorno:** se compararon los SHA-256 de los 43 `.deb` de las ejecuciones quinta y sexta; **43/43 hashes idénticos, 0 diferencias**. Ambos manifiestos identificaron los mismos tres insumos fuente, el mismo parche adicional y el mismo hash `hook_idmap.c`; ambos mantuvieron `release_authorized=false`. La quinta ejecución del wrapper había rechazado correctamente un epoch todavía no registrado (`exit 3`); su inventario posterior se validó de manera independiente. La sexta ejecución demuestra el flujo completo corregido con `exit 2` de evidencia válida y publicación bloqueada.

**El inspector permanece BLOQUEADO.** El resultado no corrige ni autoriza actualizar el runtime.

## Gates posteriores no cubiertos

Para considerar una candidata corregida se requiere reconstruir el **paquete fuente completo** con el parche adicional y una identidad/versionado inequívocos; completar una auditoría ABI de símbolos, dependencias y consumidores más allá de la comprobación SONAME estática de cinco bibliotecas; probar regresiones por los cuatro CVE; validar PDF/OCR/AV/HTTP reales; generar CycloneDX/Trivy sobre una **imagen nueva y exacta**; y obtener autorización independiente. Ninguno se suple con un `exit 0` funcional ni con la ausencia de hallazgos en un inventario estático.

**Security gate: BLOCKED. Release autorizado: NO.**
