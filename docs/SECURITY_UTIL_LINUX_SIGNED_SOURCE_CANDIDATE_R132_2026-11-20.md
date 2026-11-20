# R1.32 · Candidato de origen firmado para util-linux (NO RELEASE)

**Fecha:** 2026-11-20. **Rama:** `security/util-linux-source-evidence-r132`. **Ámbito:** pruebas de autenticidad de la fuente y compilación nativa de una única utilidad en laboratorio. **No es** un paquete Debian, una imagen corregida ni una autorización de despliegue.

## Hallazgos de proveedor

Debian Trixie mantiene `util-linux 2.41.5-0+deb13u1` como **vulnerable (no DSA)** a cuatro CVE: `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409` y `CVE-2026-78410`. En sid/forky la versión corregida es `2.42.4-1`; **no deben mezclarse** bibliotecas ABI de estas ramas con Trixie. Véase [Debian Security Tracker](https://security-tracker.debian.org/tracker/source-package/util-linux).

El [anuncio firmado por el proyecto util-linux 2.41.6](https://lists.openwall.net/linux-kernel/2026/09/02/753) describe los arreglos iniciales de la serie 2.41. No obstante, para `CVE-2026-78408` la primera mitigación `O_CLOEXEC` no cerraba la capacidad que porta `cgroup.procs` durante el cambio de credenciales. Es imprescindible el [backport posterior `485dbb67f1b6bb18e08b1b77f4aa2373ff3a705b`](https://github.com/util-linux/util-linux/commit/485dbb67f1b6bb18e08b1b77f4aa2373ff3a705b), también documentado en [OpenEmbedded/Yocto](https://patchwork.yoctoproject.org/project/oe-core/patch/20261003204118.1827359-1-peter.marko@siemens.com/). Este parche cierra el descriptor temporal del cgroup y el descriptor `cgroup.procs` inmediatamente después de realizar la migración, antes de `setgid`, `setuid` y `execvp`.

## Procedencia comprobada en la ejecución real

| Artefacto | Verificación |
| --- | --- |
| `util-linux-2.41.6.tar.xz` | SHA-256 `e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed` |
| `util-linux-2.41.6.tar.sign` | **Firma OpenPGP válida sobre el tar descomprimido**, GPG exit 0 |
| Clave primaria del mantenedor Karel Zak | `B0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284` |
| `sha256sums.asc` | **Firma válida** y SHA firmado coincidente, GPG exit 0 |
| Clave primaria del autosigner kernel.org | `B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1` |
| Backport upstream `485dbb67...patch` | SHA-256 `0b30248db96c77926ab9ad33474003bb1b13d652368dc754a84ac51ec61f7220` |
| `nsenter.c` antes del parche | SHA-256 `9de70a7aaeebc492ee4eaff3597c82d290aa150bd04f1c91b782f19c5348c390` |
| `nsenter.c` después del parche | SHA-256 `070fb7c5fac3dfcebaff3ae008999fac21bf4d1e5e01ee4dfb0aa225555a2d0c` |

Las claves públicas se obtuvieron de keyserver.ubuntu.com, distinto del servidor kernel.org de la fuente, y se cotejaron por fingerprint exacto en un GNUPGHOME temporal. **No se afirma una certificación independiente Web of Trust de la identidad de las claves.** El backport por HTTPS no cuenta con firma OpenPGP independiente: se ata al commit upstream, su único fichero afectado y el hash SHA-256 exacto.

La aplicación del backport sobre el tar firmado fue **limpia, sin fuzz** (`git apply --check`, `git apply`) y se corroboró el digest final del C. Una variante de ese parche procedente de la rama principal upstream (`afe067c979b9...`) **no aplica íntegramente a 2.41.6** y queda expresamente descartada de la receta.

## Cambios y controles TDD

- `apps/inspector/util_linux_source_candidate.py` realiza la verificación de fuente **offline**: dos certificados primarios, dos firmas criptográficas, SHA de archivo y manifiesto, alcance de parche y digest del fichero modificado. Extrae fuentes únicamente bajo `/tmp` con directorio privado y comprueba patrones estáticos de los cuatro CVE. **Exit 2** cuando la evidencia es consistente, **exit 3** ante cualquier alteración.
- `apps/inspector/fetch_util_linux_source_candidate.sh` descarga por HTTPS seis artefactos con URL explícitas, sin omitir certificados ni instalar dependencias, y elimina el temporal al terminar. No modifica el inspector ni las bases institucionales.
- `apps/inspector/build_util_linux_nsenter_source_smoke.sh` verifica primero firmas/patch; compila **únicamente nsenter**, deshabilitando los demás programas y bibliotecas, bajo usuario sin privilegios y en carpeta efímera. Solo ejecuta `--version` y `--help` (sin PID, namespaces o cambio de credenciales). **No hace make install ni produce un paquete .deb**.
- `apps/inspector/tests/test_util_linux_source_candidate.py` contiene **8 pruebas TDD RED → GREEN**, con casos de hash, firma, clave, parche, orden del cierre del descriptor, dependencias y prohibición de instalaciones/despliegues.

Se probaron también **tres alteraciones reales**: parche adulterado, manifiesto firmado alterado y clave de mantenedor sustituida por otra. Los tres casos devolvieron **exit 3** y `release_authorized=false`.

## Resultados verificados

| Control | Resultado |
| --- | --- |
| `bash apps/inspector/fetch_util_linux_source_candidate.sh` | **Exit 2 esperado**; autenticidad y parche verificados |
| TDD nuevas | **8/8** |
| Aplicación del backport sobre 2.41.6 | **Exit 0**, sin fuzz |
| Configuración/compilación aislada de nsenter | **Exit 0** |
| `nsenter --version` / `--help` (únicas llamadas) | **Exit 0** |
| `build_util_linux_nsenter_source_smoke.sh` | **Exit 2**, binario nativo construido, nunca instalado |
| Paquete Debian Trixie reconstruido | **NO** |
| Imagen Docker reemplazada / publicada | **NO** |
| Source patch aplicado al runtime actual | **NO** |
| Estado de los cuatro CVE | **Abiertos en Debian Trixie** |
| VEX / waiver / despliegue / release | **NO** |

**Preflight de Docker:** `python3 apps/inspector/preflight.py --mode build` devolvió **exit 2**, con **2,28 GiB libres frente al mínimo de 8 GiB** tanto para workspace como para almacenamiento Docker. No se eliminaron imágenes, volúmenes, cachés compartidas ni worktrees para forzar la reconstrucción. La compilación de nsenter se ejecutó fuera de Docker en un directorio temporal y **no demuestra compatibilidad ABI de paquetes Debian Trixie**.

**Alcance de las pruebas:** los hashes y fragmentos C demuestran integridad y presencia de mitigaciones en las fuentes; no son tests de explotación que puedan establecer por sí solos la corrección completa. Falta compilar los paquetes Debian, comprobar libmount/mount/nsenter/unshare y regresiones CVE sobre Debian 13, generar SBOM/Trivy del runtime reconstruido y ejecutar los smokes de documentos. La herramienta nsenter no se reinstala en el runtime podado R1.29/R1.30.

## Reproducibilidad

`bash apps/inspector/fetch_util_linux_source_candidate.sh` descarga y valida los artefactos y retorna `exit 2`. Para compilar el smoke nativo se requiere un directorio temporal privado que contenga esos seis archivos (en la ejecución local se preparó tal carpeta): `bash apps/inspector/build_util_linux_nsenter_source_smoke.sh --artifacts-dir /tmp/your-signed-artifacts` (salida `exit 2`). No se versionan artefactos binarios upstream. El CI funcional sigue siendo `sh scripts/ci.sh` local; **CI verde no concede autorización de seguridad**.

## Siguiente decisión

Cuando exista espacio suficiente sin interferir con otros trabajos, construir un **paquete Trixie compatible y verificable** desde la fuente Debian y los parches del proveedor, ejecutar regresiones CVE individuales y los motores PDF/OCR/AV, y repetir SBOM/Trivy y `sh scripts/ci.sh`. La promoción o despliegue seguirán requiriendo autorización explícita independiente.
