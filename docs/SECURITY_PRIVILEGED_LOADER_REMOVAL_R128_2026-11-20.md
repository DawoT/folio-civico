# R1.28 · Cierre del bypass del cargador ELF sobre la mitigación R1.24

**Corte:** 2026-11-20 (America/Lima). **Rama:** `security/privileged-loader-r128`, basada en `security/clamav-cli-r127`. **Estado:** experimento local no desplegable; no hay merge, VEX, supresión de CVE, firma OCI, preview ni producción.

## Causa raíz reproducida sobre binarios reales

R1.24 cambió los permisos de **14 ejecutables administrativos/SUID** a `0644`. Eso bloqueó llamadas directas a `execve` del usuario 65534, pero **no elimina la posibilidad de cargar un ELF legible mediante el intérprete dinámico**. R1.28 reprodujo el bypass sobre la imagen real R1.27, sin red, sin capacidades y con rootfs read-only:

| Programa bajo modo `0644` | Ejecución directa | `/lib64/ld-linux-x86-64.so.2 <programa> --version` |
| --- | --- | --- |
| `nsenter` | EACCES | Ejecutó e informó versión 2.41.5 |
| `mount` | EACCES | Ejecutó e informó versión 2.41.5 |
| `unshare` | EACCES | Ejecutó e informó versión 2.41.5 |
| `su` | EACCES | Ejecutó e informó versión 2.41.5 |
| `passwd` | EACCES | Arrancó e imprimió ayuda; finalizó con error de argumentos |

La carga ELF **no prueba que los binarios ganaran capacidades o privilegios**. Sin embargo, invalida el supuesto de R1.24 de que estos entrypoints no podían ejecutar código. Este informe sustituye expresamente esa afirmación, sin alterar el historial de experimentos.

**La corrección es la eliminación física de los 14 archivos en el filesystem final**. Se mantiene el principio de permisos mínimos, UID 65534, sin red, sin escalada de privilegios y con filesystem de solo lectura. R1.27 ya había aplicado una corrección equivalente a diez comandos no usados de ClamAV.

## Alcance y propiedad Debian

Los 14 archivos se clasifican por propietario del paquete `dpkg-query -S`:

| Paquete | Archivos eliminados (en R1.28) |
| --- | --- |
| `passwd` | `chage`, `chfn`, `chsh`, `expiry`, `gpasswd`, `passwd` |
| `login` | `newgrp` |
| `mount` | `mount`, `umount` |
| `util-linux` | `nsenter`, `setpriv`, `su`, `unshare` |
| `libpam-modules-bin` | `unix_chkpwd` |

No se eliminan los paquetes ni bibliotecas esenciales (`libmount.so.1`, `libuuid.so.1`), no se altera ninguna versión ni CVE y no se mezcla Debian sid/forky en el runtime Trixie. El inventario `dpkg` **deliberadamente sigue reportando archivos faltantes**. La auditoría comprueba que, al comparar con la imagen R1.27, solo aparecen las **14 ausencias adicionales esperadas**, aparte de las ausencias de documentación y los diez CLI de ClamAV ya existentes.

**Debian Security Tracker:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) e [información sobre util-linux](https://security-tracker.debian.org/tracker/source-package/util-linux) mantienen Trixie `2.41.5-0+deb13u1` como vulnerable para cuatro casos de `util-linux`: `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409` y `CVE-2026-78410`. Esta eliminación reduce superficie de comandos pero **NO equivale a aplicar sus parches ni a demostrar la inaplicabilidad de los CVE en libmount u otras rutas**.

## Implementación TDD y auditoría fail-closed

Se añadieron exclusivamente archivos experimentales, sin cambiar el entrypoint del inspector ni los workflows de CI existentes:

- `apps/inspector/privileged_loader_surface.py`: 14 rutas absolutas con propietarios fijados. Falla ante un ELF inesperado, symlink, modo diferente, propietario inesperado, ausencia parcial o bit SUID/SGID en el filesystem estático. Exige estado origen `baseline` antes de eliminar, y resultado destino `removed` sin esos archivos. Audita además los SUID/SGID restantes.
- `apps/inspector/privileged_loader_dpkg.py`: recolecta evidencia de `dpkg -V` y versiones de cinco paquetes propietarios. Dado que la imagen ya había podado documentación, **compara deltas exactos antes/después** en lugar de fingir un `dpkg -V` limpio. Acepta solo catorce `missing` adicionales de propietario correcto; rechaza desaparición/reaparición de archivos no previstos y versiones cambiadas.
- `apps/inspector/Dockerfile.privileged-loader-experiment`: `FROM folio-civico-inspector:clamav-cli-limited-experiment AS hardener`; elimina las 14 rutas en una etapa desechable, revalida, y luego `FROM scratch` / `COPY --from=hardener / /`. Se conserva la configuración ENV, CMD y usuario 65534.
- `apps/inspector/privileged_loader_smoke.py`: ejecutado realmente bajo `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`. Exige 14 ENOENT de ejecución directa, 14 fallos de cargador ELF, ausencia física, `CapEff=0` y `NoNewPrivs=1`; comprueba que `clamscan` sigue funcionando.
- `apps/inspector/privileged_loader_gate.py`: contrasta dos Docker IDs inmutables, ausencia de capas históricas con contenido, configuración, Trivy JSON, CycloneDX, 14 inventarios de ELF, 5 informes Debian y código nativo de ClamAV retenido. CVE, paquete, byte o ruta inesperado = **exit 3**. Evidencia coherente = **exit 2**, bloqueo.
- `apps/inspector/build_privileged_loader_experiment.sh` y `scan_privileged_loader_experiment.sh`: orquestación exclusivamente local y explícita. El permiso DAC_READ_SEARCH se usa **solo en el contenedor efímero de auditoría de filesystem, como root, sin red**, para enumerar directorios que UID 65534 no puede leer; los tests funcionales y el runtime continúan sin capacidades.
- `apps/inspector/tests/test_privileged_loader_removal.py`: **siete pruebas TDD** (RED por módulos inexistentes; GREEN tras la implementación), casos adversarios de symlink, permisos, CVE, hashes, modificaciones de paquete, capa OCI, versiones, rutas extras y retorno bloqueado.

## Resultados reales

| Control | Evidencia |
| --- | --- |
| Imagen origen R1.27 (ID local) | `sha256:9183e79856f5d3ede45e5324b78ddd965959ab42a9719bbadaeb17cfcf739b73` |
| Imagen destino R1.28 (ID local) | `sha256:08d4bfe0baaf611adb7199495ec28177cecbe3b542693cac4d97a2c3c3a97afb` |
| Build Docker aislado | **exit 0** |
| Comandos administrativos/SUID/namespace ausentes | **14/14** |
| Direct exec fallido por ENOENT | **14/14** |
| Loader ELF fallido por archivo ausente | **14/14** |
| Controles reales de PDF/OCR/AV (incluye EICAR) | **6/6** |
| Controles HTTP/auth/manifest/health | **4/4** |
| Privilegios efectivos | UID 65534, `CapEff=0`, `NoNewPrivs=1`, rootfs read-only |
| Paquetes | Sin cambios de identidad/versiones |
| Gate de Trivy/CycloneDX y paquetes | **exit 2, release bloqueado** |
| Trivy actual CRITICAL/HIGH/UNKNOWN, ambas imágenes | **0 / 59 / 15** (sin diferencia origen-destino) |
| Paquetes Debian, antes y después | **141**, identidades/versiones intactas |
| Integridad: nuevos archivos faltantes en cinco paquetes | **14/14**, exactamente los previstos |
| Integridad: archivos nativos de ClamAV retenidos | **7/7**, SHA-256 idénticos |
| Capas OCI previas con contenido reutilizadas | **0** |

**Nota de reproducibilidad del escáner:** la auditoría R1.27 anterior registró **59 HIGH / 19 UNKNOWN**. En esta ejecución R1.28, Trivy 0.76.2 utilizó DB v2 con `UpdatedAt=2026-11-20T07:09:47Z` y `DownloadedAt=2026-11-20T13:16:59Z`, registrando **59 HIGH / 15 UNKNOWN** tanto en origen R1.27 como destino R1.28. La diferencia histórica de cuatro UNKNOWN es **drift de datos del escáner entre cortes**; no es una corrección causada por eliminar los 14 ELF. Continúan abiertos 15 UNKNOWN bajo la base actual y los 19 de la instantánea anterior necesitan conciliación por identificador antes de cualquier afirmación de remediación.

**Estabilidad de CI local:** al ejecutar `sh scripts/ci.sh`, Vitest falló inicialmente en cuatro casos de dos suites ajenas al inspector. Se reprodujeron **los mismos cuatro fallos en la rama base R1.27**. Causa: fixtures de `quarantine-audit.test.ts` y `processing-pipeline.e2e.test.ts` combinaban `CURRENT_TIMESTAMP` real de SQLite con evaluaciones simuladas fijadas a noviembre 2026; el reloj de ejecución había cruzado el límite temporal. Se corrigieron **solo las fechas de los fixtures sintéticos**, no el código productivo. Los **16/16 tests focalizados** pasaron tras el cambio. La CI integral se vuelve a ejecutar para confirmar.

Los comandos R1.24 continúan físicamente presentes y potencialmente invocables mediante loader en **la imagen base R1.27**. R1.28 **no corrige retrospectivamente esa imagen ni promueve la nueva**: exige utilizar solo el nuevo experimento para evaluar esta defensa, y queda sujeto a revisión humana.

## Reproducción local

```bash
python3 -m unittest discover -s apps/inspector/tests -p 'test_privileged_loader_removal.py' -v
bash apps/inspector/build_privileged_loader_experiment.sh
bash apps/inspector/scan_privileged_loader_experiment.sh  # exit 2 previsto
sh scripts/ci.sh
```

`sh scripts/ci.sh` es la CI funcional local utilizada por este proyecto. La auditoría de imagen experimental se mantiene como gate independiente. No se requiere GitHub Actions.
