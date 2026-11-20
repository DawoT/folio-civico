# R1.34 · Entrega privada de fuente experimental util-linux para pruebas binarias Debian 13 (NO RELEASE)

**Fecha:** 2026-11-20. **Base:** R1.33, PR #77 integrada en `main`. **Alcance:** permitir que una validación binaria posterior consuma exactamente la fuente ya autenticada y reconstruida, sin convertirla en un paquete Debian oficial ni tocar el runtime.

## Hallazgo y decisión

R1.33 verificaba firmas upstream y Debian, hashes, los 10 parches correctos y el roundtrip `dpkg-source`, pero destruía todos los archivos fuente al finalizar. Una prueba binaria Trixie necesitaría volver a producir esos archivos o saltarse el verificador, perdiendo trazabilidad. Se incorpora una **opción de entrega explícita**, no un build binario.

`bash apps/inspector/fetch_util_linux_debian_source_overlay.sh` **sin parámetros** conserva el comportamiento de R1.33: directorio temporal eliminado, evidencia válida `exit 2`, publicación bloqueada. Para entregar una copia local:

```sh
# Crear un padre exclusivo y privado. No versionar ni publicar su contenido.
source_parent="$(mktemp -d /tmp/folio-ul-r134.XXXXXX)"
bash apps/inspector/fetch_util_linux_debian_source_overlay.sh \
  --export-dir "$source_parent/source"
# exit 2 esperado: verificación completa, NO release
```

El padre debe existir, no ser un enlace simbólico y no atravesar enlaces simbólicos. El destino **no debe existir**. La herramienta rechaza directorios ya ocupados y nunca los vacía ni sobrescribe. Todos los chequeos de R1.33 se ejecutan antes de exportar. Solo si han pasado se copian en un nuevo directorio `0700` tres archivos `0600` y un manifiesto `0600`:

| Archivo | SHA-256 observado |
| --- | --- |
| `util-linux_2.41.6.orig.tar.xz` | `e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed` |
| `util-linux_2.41.6-0+folio1~deb13u1.dsc` | `ec1d158d4b8a17d74e31dafccbe9a755a323497d6cc4bef88ccc599c9bfbc752` |
| `util-linux_2.41.6-0+folio1~deb13u1.debian.tar.xz` | `8449886af6bd4d2cf9c4753596719c380ba951e7d220e27610aa6c881426a5e7` |

**`UNSIGNED_SOURCE_ONLY.json`** registra la identidad experimental, los tres SHA-256 y los límites: `experimental_dsc_signed=false`, `debian_binary_packages_built=false`, `runtime_image_replaced=false`, `release_authorized=false`, `vex=not_issued`. Es una afirmación local no firmada; las firmas autentican los **insumos originales**, nunca este descriptor experimental.

Se verifica nuevamente el SHA-256 al copiar; si los archivos temporales cambian o la exportación falla, el proceso aborta con `exit 3` y no habilita publicación. No se exportan `.deb` ni `.udeb`. La marca de completitud se crea después de copiar y verificar los tres archivos.

## Ejecución y evidencia de esta iteración

- TDD: nueva prueba primero roja por ausencia del exportador; después **5/5** tests pasan. Comprueban privacidad del directorio, manifiesto y hashes, negativa a sobrescribir trabajo ajeno, insumos inválidos, enlaces simbólicos y prohibición de build/deploy en la ruta de R1.33.
- Regresión Python del inspector: **343/343**, incluyendo las diez pruebas originales de R1.33. `py_compile` de código y tests: **exit 0**.
- Descarga HTTPS de los diez insumos y entrega privada end-to-end: **exit 2 esperado**; firmas upstream y Debian válidas; los tres hashes del manifiesto coinciden bit a bit con los archivos entregados. El servidor devolvió HTTP 503 transitorio durante el proceso y los reintentos de `curl` permitieron completar la verificación.
- Prueba temporal realizada dentro de un directorio nuevo de `/tmp`; el directorio de **esta prueba**, y solamente ese, se eliminó tras verificarlo. No se borraron imágenes, volúmenes, caches o worktrees compartidos.
- Nuevo preflight read-only en el host de ejecución: **66,8 GiB** libres (mínimo 8 GiB) y **54,58 GiB** de RAM disponible (mínimo 4 GiB), `ready=true`, `exit 0`. Es una observación puntual diferente del preflight histórico de R1.32 (2,28 GiB); repetir antes de construir.
- El host observado es **Ubuntu 24.04**, no Debian Trixie; su `dpkg-buildpackage` no prueba ABI Debian 13. El inventario Docker no contiene la imagen R1.29 esperada; por tanto no se reejecuta ni se afirma una auditoría actual sobre esa imagen.

## Restricciones de seguridad y siguiente gate

**Ningún archivo `.deb` se construyó**, ninguna dependencia se instaló en el host, ningún contenedor se creó y no se modificó el `Dockerfile` productivo. No hubo OCI build/push, VEX/waiver, firma de paquete experimental ni deploy. Los cuatro CVE (`CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409`, `CVE-2026-78410`) permanecen abiertos para Trixie según el tracker Debian a la fecha de esta investigación.

**Siguiente paso (todavía pendiente):** en una imagen temporal Debian 13, con capacidad prevalidada y sin escritura sobre el host salvo un directorio exclusivo, verificar primero el manifiesto, extraer `dpkg-source`, obtener las Build-Depends de Trixie en un builder desechable, construir `.deb` experimentales y comprobar compatibilidad ABI/ELF de las bibliotecas realmente requeridas. Después ejecutar regresiones específicas de los cuatro CVE y smokes reales del inspector, generar SBOM/Trivy y mantener el gate de release bloqueado hasta revisión independiente.

Una fuente firmada y reproducible **no es** un paquete binario corregido. Ningún cambio de esta iteración altera esa conclusión.
