# R1.30 — Reducción de las ABI residuales blkid/smartcols en el inspector

**Corte:** 20/11/2026 (America/Lima). **Rama:** \`security/utility-dso-r130\`, basada en \`security/libmount-prune-r129\` (PR #54). **Control:** imagen Docker local experimental; sin despliegue, merge, VEX, waiver, supresión de CVE, firma ni publicación OCI.

## Propósito y límites de seguridad

R1.24 limitó con chmod 0644 catorce comandos privilegiados. R1.28 demostró que una llamada explícita al cargador ELF eludía esa restricción y eliminó físicamente los comandos. R1.29 eliminó además libmount.so.1 y nueve utilidades administrativas no usadas, con FROM scratch y pruebas reales del inspector.

El análisis de los **1.525 ELF de /usr y /opt** en la imagen R1.29 reveló que aún hay dos bibliotecas compartidas de util-linux sin consumidores funcionales en el pipeline del inspector:

| SONAME | ELF con referencia literal | Consumidores distintos |
| --- | ---: | --- |
| \`libblkid.so.1\` | **8** | partx, blkdiscard, blkid, findfs, mkswap, swaplabel, wipefs, biblioteca propia |
| \`libsmartcols.so.1\` | **11** | lscpu, lsipc, lslogins, lsmem, partx, prlimit, wdctl, losetup, wipefs, zramctl, biblioteca propia |

Dos utilidades (\`partx\`, \`wipefs\`) aparecen en ambas listas. La unión exacta es **15 comandos ELF**, más **dos bibliotecas ELF** y **dos symlinks SONAME**: **19 rutas** pertenecientes a \`util-linux\`, \`mount\`, \`libblkid1\` y \`libsmartcols1\`, todos en versión \`2.41.5-0+deb13u1\` en el runtime.

### Excepción legítima a conservar

**\`libuuid.so.1\` no debe eliminarse.** La extensión ELF \`/usr/local/lib/python3.12/lib-dynload/_uuid.cpython-312-x86_64-linux-gnu.so\` la utiliza directamente. Se fijan y contrastan los SHA-256 de:
- \`/usr/lib/x86_64-linux-gnu/libuuid.so.1.3.0\`.
- \`/usr/local/lib/python3.12/lib-dynload/_uuid.cpython-312-x86_64-linux-gnu.so\`.

Se comprueban también la carga real de \`libuuid.so.1\` y la generación UUID nativa mediante \`_uuid.generate_time_safe()\`.

## Correspondencia individual con CVE

Las cuatro alertas recientes de util-linux tienen superficies distintas y deben permanecer abiertas hasta contar con prueba CVE específica:

| CVE | Superficie afectada según upstream | Decisión R1.30 |
| --- | --- | --- |
| \`CVE-2026-76642\` | mount(8), hooks post-montaje tras error | Se había eliminado mount; no se emite VEX |
| \`CVE-2026-78408\` | nsenter(1)/unshare(1), fuga de descriptor | Se habían eliminado los comandos; no se emite VEX |
| \`CVE-2026-78409\` | mount(8) / X-mount.subdir | Se había eliminado mount y luego libmount; no se emite VEX |
| \`CVE-2026-78410\` | validación de rutas de origen restringidas durante montaje | Ya no está libmount, pero se conservan dependencias ABI de util-linux; no se emite VEX |

**Estado Debian:** la edición Trixie \`2.41.5-0+deb13u1\` sigue marcada vulnerable para \`CVE-2026-76642\` en Debian Security Tracker. Las correcciones \`2.42.3/2.42.4\` de ramas más recientes **no se copian** a Trixie; tampoco se altera la versión declarada en \`dpkg\`, los registros de Trivy ni el SBOM.

Fuentes:
- https://security-tracker.debian.org/tracker/source-package/util-linux
- https://security-tracker.debian.org/tracker/CVE-2026-76642
- https://security-tracker.debian.org/tracker/CVE-2026-78408
- https://security-tracker.debian.org/tracker/CVE-2026-78409
- https://security-tracker.debian.org/tracker/CVE-2026-78410
- https://seclists.org/oss-sec/2026/q3/652

## Implementación

1. \`utility_dso_surface.py\`: inventario previo obligatorio de 19 rutas; \`dpkg-query -S\`, versiones/modos/tipos y symlinks exactos, recorrido de todos los ELF regulares bajo /usr y /opt con dos SONAME buscados como bytes. Se exige el inventario antes de modificar y **cero referencias ELF directas** al terminar. Las rutas se borran en builder descartable con \`unlink\` explícito; se verifica conservación byte a byte de \`libuuid\` y de la extensión Python.
2. \`Dockerfile.utility-dso-experiment\`: reduce el filesystem de la imagen R1.29 en un stage temporal y crea una nueva imagen **FROM scratch** que no contiene capas antiguas con las bibliotecas retiradas.
3. \`utility_dso_smoke.py\`: pruebas en el contenedor como UID 65534, \`CapEff=0\`, \`NoNewPrivs=1\`, sin red y rootfs solo lectura; requiere \`ENOENT\` para cada comando, falla el intento de invocar sus ELFs mediante \`ld-linux\`, y verifica que \`ctypes.CDLL\` rechace ambos SONAME. Además prueba \`libuuid\`, \`_uuid\`, ClamAV, PDF y OCR.
4. \`utility_dso_dpkg.py\`: compara dos informes \`dpkg -V\` de los cuatro paquetes afectados. No afirma que la instalación Debian sea intacta: acepta los faltantes históricos idénticos en ambas imágenes, más **19 ausencias nuevas esperadas** y ningún archivo modificado.
5. \`utility_dso_gate.py\`: compara dos Docker IDs inmutables, metadata del runtime, dos SBOM CycloneDX, dos escaneos Trivy JSON, inventarios ELF/UUID, el delta Debian y siete archivos nativos de ClamAV preservados. Diferencia o evidencia incompleta = **exit 3**; evidencia válida = **exit 2 y publicación bloqueada**.
6. Se agregaron **6 pruebas TDD** nuevas. Se constató RED por módulos no disponibles y GREEN después de implementar. No se modificó el código productivo del inspector ni los test gate de producción.

### Alcance de comprobación

El inventario de coincidencias en bytes dentro de todos los ELF es **conservador, pero no exhaustivo**: no detecta nombres de biblioteca ensamblados dinámicamente, carga con un alias distinto, introspección indirecta o interfaces syscall desde otro código. Los controles de \`ctypes.CDLL\` y de dependencias \`ldd\` refuerzan la evidencia, pero no prueban inaplicabilidad de CVE. El paquete Debian queda registrado como instalado aunque se retiren archivos de su filesystem.

Se mantiene prohibido promover la imagen a Preview o producción hasta cumplir el gate de release. El propósito es reducir superficie alcanzable de código de administración de sistemas, nunca ocultar hallazgos ni suplantar un parche de la distribución.

## Resultados verificados

| Control | Resultado |
| --- | --- |
| Imagen base R1.29 (ID Docker local) | \`sha256:0af77fb9144634a8e4d77456eb460f92e5d9274ad042f52483157330d565651c\` |
| Nueva imagen R1.30 (ID Docker local) | \`sha256:61e966a276d30bf576049f9621227c58e3b55f5326ec4341eecebf343a7e8c77\` |
| Build experimental y controles reales | **exit 0** |
| Pruebas PDF/OCR/AV (incluido EICAR) | **6/6** |
| Pruebas HTTP/autorización | **4/4** |
| Herramientas CLI físicamente ausentes | **15/15** |
| Rechazos del kernel por ejecución directa | **15/15** |
| Fallos del cargador ELF | **15/15** |
| Bibliotecas blkid y smartcols no cargables con ctypes | **2/2** |
| SHA-256 de libuuid y _uuid de Python | **2/2 intactos** |
| Código nativo ClamAV preservado | **7/7 SHA-256 intactos** |
| Informe dpkg, nuevos faltantes exactos | **19/19** |
| Paquetes Debian instalados en SBOM | **141, sin cambios** |
| Capas OCI antiguas con contenido reutilizadas | **0** |
| Trivy CRITICAL / HIGH / UNKNOWN antes y después | **0 / 59 / 15**, sin alteraciones |
| Auditoría diferencial | **exit 2 — release bloqueado** |
| TDD específico | **6/6** |

El \`exit 2\` no es un error de integridad: es el contrato del gate que impide promover imágenes con hallazgos pendientes aun cuando el endurecimiento está íntegro. El \`exit 3\` corresponde a evidencia alterada/incompleta. Ninguno autoriza publicar, firmar ni emitir VEX.

## CI funcional y trazabilidad

La ejecución real `FOLIO_E2E_PORT=42992 sh scripts/ci.sh` terminó **exit 0**. Incluyó **7/7 controles de CI local**, **414/414 tests Vitest**, **229/229 pruebas Python inspector**, `tsc --noEmit`, compilaciones de Web/API/MCP/Processor/Gateway, cuatro `wrangler deploy --dry-run` sin despliegue, **5/5 pruebas Workers locales**, **81/81 Playwright Chromium** y migraciones D1 sobre bases **locales exclusivamente**. El parámetro de puerto es parte del diseño existente del test runner para evitar colisiones entre worktrees; no se modificó `scripts/ci.sh`.

**Incidencia de capacidad reproducible:** el primer build R1.30 no comenzó porque el preflight exigió **8 GiB libres** en disco y Docker y solo estaban disponibles **7,68 GiB**. No se omitió el control. Se eliminaron exclusivamente entradas antiguas y regenerables de caché del builder Docker mediante filtros de antigüedad `until=30h`, `until=24h` y `until=18h`; la limpieza de 18h recuperó **436,4 MB** según Docker. No se borraron imágenes, volúmenes, datos institucionales ni worktrees. La segunda ejecución del build pasó preflight con **8,18 GiB libres**, construyó la imagen nueva y ejecutó sus smokes con éxito. Posteriormente el sistema volvió a acumular contenido de compilación, por lo que futuras imágenes deben comprobar capacidad de nuevo.

Los resultados finales de la auditoría de origen y destino fueron **0 CRITICAL / 59 HIGH / 15 UNKNOWN**. Sus vulnerabilidades, severidades y 141 paquetes son idénticos; no se realizó supresión, upgrade accidental ni emisión VEX. El gate independiente terminó **exit 2 — blocked**, no con una autorización de release.

## Reproducción local

\`\`\`bash
python3 -m unittest discover -s apps/inspector/tests -p test_utility_dso_prune.py -v
bash apps/inspector/build_utility_dso_experiment.sh
bash apps/inspector/scan_utility_dso_experiment.sh   # exit 2: expected, release blocked
FOLIO_E2E_PORT=42991 sh scripts/ci.sh
\`\`\`

\`scripts/ci.sh\` es el mecanismo CI funcional principal. No se necesita GitHub Actions y no se cambia el gate de seguridad.
