# R1.33 · Debian Trixie: paquete fuente experimental y reproducible (NO RELEASE)

**Fecha:** 2026-11-20. **Objetivo:** comprobar que la fuente upstream firmada 2.41.6 y el backport CVE-2026-78408 pueden rebasarse sobre el empaquetado fuente oficial de Debian Trixie sin revertir parches de seguridad. **No equivale a un paquete .deb corregido ni autorizado.**

## Autenticidad de los tres insumos

- **Debian Trixie 2.41.5-0+deb13u1**: descriptor `util-linux_2.41.5-0+deb13u1.dsc`, SHA-256 `43e9b2cbebd10fdc598c4ad10217c8202c28de53af6eafc892c8e9b5cbf3a3a5`, firmado con OpenPGP por Christian Hofstaedtler. Huella primaria fijada `7D1ACFFAD9E0806C9C4CD3925C13D6DB93052E03` (identidad documentada por [Debian](https://lists.debian.org/debian-newmaint/2013/09/msg00022.html)). `VALIDSIG` verificado con GNUPGHOME aislado.
- **Tar upstream Debian 2.41.5**: SHA-256 `f586e35d320ff537aab3ffeca37e9ecd482ccbe013590db4429a414d8aa6a728`, 9.474.992 bytes. **Debian packaging** `debian.tar.xz` SHA-256 `5b327ccd22f0f4ed28a389870aa51d04ecedb8693e52a1d122850f2b3188cbf6`, 107.604 bytes. Ambos hashes corresponden exactamente al manifiesto SHA-256 contenido en el descriptor Debian firmado.
- **Upstream 2.41.6 + backport**: se reutiliza la verificación R1.32, que comprueba tanto la firma del mantenedor Karel Zak como la firma de checksum kernel.org del tar `2.41.6` (SHA-256 `e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed`) y fija el parche `485dbb67f1b6bb18e08b1b77f4aa2373ff3a705b` (SHA-256 `0b30248db96c77926ab9ad33474003bb1b13d652368dc754a84ac51ec61f7220`). **El parche Git no tiene firma OpenPGP independiente.** Las claves descargadas y verificadas por huella no constituyen una certificación independiente Web of Trust.

Fuentes oficiales: [paquete Debian Trixie](https://packages.debian.org/trixie/source/util-linux), [Debian Security Tracker](https://security-tracker.debian.org/tracker/source-package/util-linux), [fuente util-linux](https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.41/), [backport](https://github.com/util-linux/util-linux/commit/485dbb67f1b6bb18e08b1b77f4aa2373ff3a705b).

## Hallazgo importante: inversión silenciosa de parches

El descriptor Debian firmado contiene **11 patches**. Al aplicar `patch --batch` sin proteger la dirección sobre el tar 2.41.6 se observaron dos parches marcados como *reversed or previously applied*; el comando **asumió inversión automática**, lo cual podría deshacer mitigaciones. Esa prueba exploratoria fue ejecutada solamente sobre un árbol temporal que no se reutiliza.

La herramienta final exige que `git apply --check` **falle** y `git apply --reverse --check` **pase**, ambos sobre el tar upstream limpio y firmado, antes de eliminar exactamente estos dos parches ya incorporados:

- `upstream/loopdev-use-openat2-RESOLVE_NO_SYMLINKS-for-backing-file.patch`
- `upstream/libmount-restrict-source-path-canonicalization-for-non-ro.patch`

Conserva los **nueve patches propios de Debian** sin alterar orden ni contenidos y añade un único `upstream/CVE-2026-78408-followup.patch` con hash exacto. La serie nueva tiene **10 patches**.

El changelog lleva la versión estrictamente **experimental** `2.41.6-0+folio1~deb13u1`, la distribución **UNRELEASED** y una identidad local `noreply@invalid`. **No representa un upload de Debian.**

## Validación real y reproducibilidad

`apps/inspector/util_linux_debian_source_overlay.py` realiza todas las verificaciones **offline** y, solo sobre directorios privados de `/tmp`, ejecuta `dpkg-source --before-build`, `dpkg-source --build` y `dpkg-source --no-check -x` para reconstruir y reextraer el **paquete fuente Debian 3.0 (quilt)**. El árbol resultante contiene los 10 patches esperados y `nsenter.c` con SHA-256 **`070fb7c5fac3dfcebaff3ae008999fac21bf4d1e5e01ee4dfb0aa225555a2d0c`**. Las condiciones fuente de los cuatro CVE siguen documentadas como patrones estáticos, **no son regresiones de explotación**.

`apps/inspector/fetch_util_linux_debian_source_overlay.sh` obtiene los diez archivos necesarios mediante HTTPS, sin desactivar certificados TLS; verifica firmas y hashes; retorna **exit 2** con evidencia íntegra (release bloqueado) o **exit 3** ante archivos corruptos, alteraciones o errores de descarga. Se observó una respuesta HTTP 503 transitoria en una primera ejecución y una ejecución posterior pasó; se reforzó la traducción de errores de transporte a exit 3.

R1.33 fija `SOURCE_DATE_EPOCH=1795190400` y normaliza las marcas temporales **solo de la carpeta de empaquetado temporal**, manteniendo intacto el tar upstream firmado. **Dos reconstrucciones aisladas produjeron exactamente los mismos hashes**:

| Artefacto fuente experimental local | SHA-256 idéntico en 2/2 |
| --- | --- |
| `util-linux_2.41.6-0+folio1~deb13u1.dsc` | `ec1d158d4b8a17d74e31dafccbe9a755a323497d6cc4bef88ccc599c9bfbc752` |
| `util-linux_2.41.6-0+folio1~deb13u1.debian.tar.xz` | `8449886af6bd4d2cf9c4753596719c380ba951e7d220e27610aa6c881426a5e7` |

Esto verifica reproducibilidad **en el mismo entorno**. No acredita reproducibilidad entre toolchains heterogéneos. El nuevo descriptor fuente **NO está firmado**: se autenticaron los orígenes, no se publicó un paquete firmable o aprobado.

Los **cuatro controles adversarios reales** devolvieron **exit 3**: descriptor Debian adulterado, `debian.tar.xz` adulterado, clave del mantenedor sustituida por otra, y parche upstream alterado. Ningún artefacto binario/OCI se creó; los temporales se eliminan automáticamente.

**Pruebas TDD nuevas:** 10/10, incluyendo la prohibición de ejecución como root, pines, cobertura de los archivos `.dsc`, orden exacto de patches, prevención de inversión, sello `UNRELEASED`, marcas temporales reproducibles y negativa a liberar ante faltantes.

## Límites y siguientes pasos

- **No se ha generado un archivo binario `.deb`** ni instalado un parche, actualizaciones de Debian, librerías o el inspector.
- **No se ha modificado la imagen productiva**, ni se han usado credenciales de despliegue, datos institucionales o D1/R2 remoto.
- **Los cuatro CVE siguen abiertos para Trixie**; una fuente compilable no basta para establecer un fix ni una inaplicabilidad.
- **Preflight Docker sigue bloqueado** por falta de 8 GiB libres de espacio. No se borraron imágenes, volúmenes, caches o worktrees compartidos.
- Pendiente: construir binarios Debian 13 en un entorno adecuado, validar ABI de `libuuid` y bibliotecas necesarias, ejecutar regresiones por CVE, smokes PDF/OCR/AV/HTTP, generar CycloneDX/Trivy y someter cualquier runtime a revisión separada.

### Reproducir (solo local, sin despliegue)

`python3 -m unittest discover -s apps/inspector/tests -p 'test_util_linux_debian_source_overlay.py' -v`

`bash apps/inspector/fetch_util_linux_debian_source_overlay.sh`  — **exit 2 esperado**

`FOLIO_E2E_PORT=43333 sh scripts/ci.sh`  — CI funcional

`bash apps/inspector/scan_util_linux_cve_scope.sh`  — **exit 2: release bloqueado**

**La aprobación de CI, la autenticación de la fuente y la construcción de un paquete fuente local son tres evidencias distintas; ninguna autoriza un release.**
