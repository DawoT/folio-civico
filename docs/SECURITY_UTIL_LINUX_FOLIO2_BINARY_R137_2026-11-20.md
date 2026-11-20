# R1.37 — Debian 13.7: binarios experimentales procedentes de la fuente folio2 (NO RELEASE)

**Fecha:** 2026-11-20. **Base:** PR #91 / `main` `013f3e3` (CI de merge aprobada). **Ámbito:** laboratorio sin instalación sobre host, sin modificar `apps/inspector/Dockerfile`, sin despliegue ni excepción de seguridad.

## Problema y criterio de identidad

R1.35 consiguió generar 43 binarios reproducibles con parche `openat2.h` externo al `.dsc` local `folio1`. R1.36 cerró esa brecha incorporando el parche como entrada 11 de `debian/patches/series` y creó el nuevo paquete fuente `2.41.6-0+folio2~deb13u1`. **R1.37 solo admite ese origen específico**: el generador binario compara tres hashes fuente contra constantes inmutables y el manifiesto R1.36; rechaza `folio1`, directorios inseguros, symlinks, entradas adicionales y reclamaciones de release.

| Fuente R1.36 | SHA-256 |
| --- | --- |
| `util-linux_2.41.6.orig.tar.xz` | `e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed` |
| `util-linux_2.41.6-0+folio2~deb13u1.debian.tar.xz` | `204326e759e7b81b03b23eae8b43a65567512eccaf862dcf2426212c05145288` |
| `util-linux_2.41.6-0+folio2~deb13u1.dsc` | `a0301270ca8ca6f9000bf48097f0b51a29aa07b9d7dc0182f486f59fe85439b6` |

La fuente `.dsc` local **no tiene firma propia**. El tarball upstream y los componentes originales Debian se autentificaron previamente, no se atribuye firma a la salida `folio2`.

## Builder experimental y controles

`build_util_linux_folio2_binary.sh` usa Debian **13.7/amd64** fijada por digest OCI `sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2`. El preflight read-only exige espacio y RAM mínimos; el contenedor tiene límites de CPU/RAM/procesos/capacidades, `no-new-privileges`, entrada montada solo lectura, salida exclusiva `0700` y `--rm`. Solo instala build-dependencies en la raíz efímera Debian. **La red `bridge` para APT no es un filtro de egreso**, y no se monta socket Docker, secrets ni rutas de otros trabajos.

`dpkg-source --no-check -x` extrae exclusivamente los archivos previamente fijados por SHA-256; se comprueba la serie de once parches y el hash `e12678246515279507185598710821dc23387b08b84b4eeb9b4977e733e391c1` de `libmount/src/hook_idmap.c`. **No hay `git apply` ni parche fuera del `.dsc`**. El build invoca `dpkg-buildpackage --build=binary --no-sign --jobs=2`. El verificador exige exactamente **43 identidades de paquetes**, incluido el esquema Debian con epoch para `login{,-dbgsym}` y `bsdutils{,-dbgsym}`, hashes SHA-256 individuales, arquitectura y `Source` correcto. Una inspección independiente usa un segundo contenedor Debian sin red, sin capacidades, con raíz `--read-only`, usuario no root y `tmpfs` temporal.

Las salidas experimentales tienen permiso `0600`, incluyen el manifiesto `UNSIGNED_FOLIO2_BINARY_RESEARCH_ONLY.json`, y siempre mantienen `release_authorized=false`, `cve_remediated=false` y `debian_trixie_abi_validated=false`. El código deliberadamente devuelve `exit 2` ante evidencia válida y release bloqueado; errores generan `exit 3`.

## ABI: referencia Debian firmada por APT

Se descargaron **cinco paquetes Debian oficiales** `2.41.5-0+deb13u1` a una carpeta local de laboratorio desde índices APT autenticados dentro de Debian 13.7, sin instalar paquetes en el host ni ejecutar bibliotecas experimentales.

| Biblioteca | Referencia Debian SHA-256 |
| --- | --- |
| `libuuid1` | `c1bf4c4c3ff48c57fabf93307dfb56996b60cfa33927afc4158b5db36fb2721e` |
| `libblkid1` | `81535f3c2c0efc732965907c8749103a0a26377c761622c9ce39b4c92dcde52f` |
| `libmount1` | `6d00f45f2e80e078e906e3eedecd3ba6913e39fef49bff361ee583f17f00ec05` |
| `libsmartcols1` | `d96bac9c8805685f2734885098a214b82950da6ebb182c27a6b7a124a0323392` |
| `libfdisk1` | `7f96d173cc01787201691f80ca9b335b8c7d6cdcc6fb81011302d4a005ff5089` |

El comparador `util_linux_folio2_elf_surface.py` **solo extrae archivos ELF a un directorio temporal**, consulta `readelf -d` y `nm -D --defined-only --with-symbol-versions`, y registra SONAME, dependencias `NEEDED`, símbolos exportados versionados añadidos/eliminados. No ejecuta ni instala bibliotecas. Su informe **no certifica** compatibilidad de todos los consumidores, símbolos requeridos por dependientes externos, semántica de llamadas ni regresiones de CVE.

La comparación inicial con `folio1` y la comprobación directa contra `folio2` ya están ejecutadas; los resultados y las limitaciones se detallan en la sección de evidencia real.

## Evidencia real y aceptación técnica

La primera ejecución integral del builder R1.37 devolvió **exit 2 previsto**: Debian 13.7 compiló 43 paquetes `.deb` desde el descriptor fuente `folio2` sin parches externos, el contenedor offline aceptó sus metadatos y el validador Python confirmó **43/43** nombres, versiones, `Source`, arquitectura y SHA-256, sin firmar ni instalar ningún paquete. Distribución de versiones: **39** paquetes `2.41.6-0+folio2~deb13u1`, **dos** `1:2.41.6-0+folio2~deb13u1` (bsdutils) y **dos** `1:4.16.0-2+really2.41.6-0+folio2~deb13u1` (login). El manifiesto conserva `cve_remediated=false`, `release_authorized=false` y `security_gate=blocked`.

SHA-256 de la primera compilación: `util-linux` `99c9a623b957ef85bec89547ef437dc9b0a885b0a513d55b22aa3f8dd41f4210`, `libmount1` `12b47b934c0561dd120879b4b7f8a849558ec4c23b0ab546d4a3b7ff5f7e8c59`, `libuuid1` `811ebda0609b334ca359e39dc9dc1c3f366e6b69f584ec2c69045b2cf8d2a155`, `bsdutils` `87cc66547957259a411b5a48fbf1a77c105c982f853ff1181f194c553a290d21` y `login` `a002b50c773b7d131b997a6cf455e13f04fe9df186ebfee06ecdbde2cee8be53`.

El verificador ELF se ejecutó sobre los **nuevos binarios folio2**, comparándolos tanto con los cinco paquetes Debian oficiales (2.41.5-0+deb13u1, obtenidos de índices APT autenticados) como con los binarios experimentales folio1. Resultado de las cinco bibliotecas en ambos casos: **cero símbolos exportados versionados perdidos o añadidos**, **cero SONAME modificados** y **cero dependencias `NEEDED` nuevas**, con los mismos 32 (libuuid), 125 (libblkid), 348 (libmount), 218 (libsmartcols) y 294 (libfdisk) símbolos expuestos. Ambos comparadores retornaron **exit 2** de evidencia estática sin release. No demuestra compatibilidad ABI completa, semántica binaria de todos los consumidores ni cierre de CVE.

Prueba no privilegiada adicional: dentro de un contenedor Debian 13.7 `--read-only --network none --cap-drop ALL --user 1000:1000`, con `tmpfs` exclusivamente temporal, `dpkg-deb -x` extrajo el paquete util-linux folio2 y `nsenter --version` mostró **`nsenter from util-linux 2.41.6`**; `--help` completó con `exit 0`. No se ejecutaron operaciones de namespaces ni instalaciones.

La defensa adicional `sha256sum --check` sobre los **tres archivos montados**, antes de la extracción en Debian, pasó de manera independiente en un contenedor sin red y sin capacidades (3/3). Es una protección complementaria frente a cambios de bytes después de la admisión en el host.

**Segunda ejecución integral terminada:** desde la segunda copia autenticada/reproducible de fuente `folio2` se generaron otros 43 paquetes Debian 13.7; el wrapper completó compilación, auditoría offline de metadata y validador Python con **exit 2 esperado**. Un script de comparación **independiente** releyó los `.deb` de ambos directorios privados y sus 43 SHA-256 individuales: **43/43 hashes idénticos, 0 diferencias**, mismas identidades fuente `folio2` y hash de `hook_idmap.c`. `release_authorized=false` en ambos reportes. Esta reproducibilidad es del **mismo entorno Debian 13.7 e insumos APT de la fecha**, no de toolchains heterogéneas ni de un snapshot APT perpetuo.

Pruebas: **14 casos nuevos R1.37**, que verifican procedencia y hashes de fuente, seguridad de rutas, manipulación, versión Debian con epoch, inventario positivo sintético de 43 paquetes, rechazo de colección incompleta y regresión ELF simulada. Suite Python completa del inspector sobre rama integrada con `main`: **407/407**; `py_compile`, sintaxis Bash y validación aislada de `sha256sum --check` de los tres archivos fuente montados también pasan.

Advertencia de `dpkg-shlibdeps`: se emitieron warnings sobre diversiones de `ld-linux-x86-64.so.2`; no provocaron fallo de build y **no deben confundirse con una prueba ABI satisfactoria**. El informe ELF indica ausencia de diferencias en cinco superficies exportadas, no valida todos los símbolos requeridos por consumidores ni el comportamiento de carga/ejecución a nivel runtime.

## Límites y siguientes gates

- **Cuatro CVE de util-linux** siguen abiertos en Debian Trixie; ningún hallazgo se cierra automáticamente por un build local. Se requieren pruebas CVE específicas, incluyendo `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409` y `CVE-2026-78410`.
- Se mantiene pendiente una prueba ABI integral con consumidores reales, además de las superficies ELF estáticas.
- No se construyó ni auditó una imagen nueva del inspector; sigue pendiente SBOM CycloneDX/Trivy del digest exacto, pruebas reales PDF/OCR/AV/HTTP y evaluación independiente G2.
- Ningún `.deb` experimental se instala, publica o despliega; no hay `VEX` ni waiver. **Inspector: `blocked_runtime_release`.**
