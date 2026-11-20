# R1.30 · Evaluación limitada de cuatro CVE util-linux en el inspector

**Fecha:** 2026-11-20 (America/Lima). **Rama:** `security/util-linux-cve-scope-r130`, basada en `security/libmount-prune-r129`. **Estado:** auditoría local sobre **imagen R1.29 inmutable**, sin construir una imagen nueva ni modificar la aplicación o sus bases de datos. **Prohibido interpretar esta atestación como VEX, parche, autorización de publicación o prueba absoluta de no explotabilidad.**

## Resumen de seguridad: fuente vulnerable y precondiciones no observadas

La imagen local estudiada es `folio-civico-inspector:libmount-pruned-experiment`, identificada por el **ID Docker** `sha256:0af77fb9144634a8e4d77456eb460f92e5d9274ad042f52483157330d565651c`. No es una imagen firmada o publicada en un registro OCI.

Se comprobaron en **tiempo de ejecución real**:

- **19 rutas** de comandos de montaje/administración y ABI `libmount` ausentes, incluidos alias de `/bin` y `/usr/bin` heredados de Debian usrmerge.
- `libmount.so.1` **no es cargable por `ctypes.CDLL`**; auditoría completa R1.29 de ELF regulares en `/usr` y `/opt` con **cero coincidencias** literales del SONAME.
- Usuario y UID efectivo 65534, `CapEff=0`, `NoNewPrivs=1`, raíz de solo lectura y **única interfaz de red `lo`** con `--network none`.
- `/etc/fstab` existe, contiene **solo comentarios**, sin líneas configuradas para montajes ni opciones `X-mount.*`.
- Ningún descriptor abierto de `cgroup.procs` en **el proceso de auditoría**. Esto **no prueba** la ausencia de otros descriptores en todos los procesos del sistema.
- Las mitigaciones anteriores se volvieron a ejecutar: **14 rutas de ELF privilegiados ausentes, sin SUID/SGID residuales** (R1.28) y **11 archivos libmount/consumidores retirados, sin referencias ELF al SONAME** (R1.29).
- El antivirus obligatorio `clamscan 1.5.5` continúa disponible, sin cambios de código ni paquetes.

Los nueve paquetes Debian del origen util-linux siguen registrados como instalados en `2.41.5-0+deb13u1` (con versiones Debian particulares para `bsdutils` y `login`). En la base Trivy actual los cuatro CVE se **repiten en cada paquete derivado**, produciendo **36 avisos HIGH**: son *cuatro vulnerabilidades de un mismo paquete fuente*, no 36 vulnerabilidades independientes ni una demostración de que todos los binarios contienen la función defectuosa.

## Matriz por CVE, componente y límites

| CVE | Mecanismo descrito por proveedor | Prerrequisitos concretos observados como ausentes | Conclusión permitida |
| --- | --- | --- | --- |
| `CVE-2026-76642` | `mount(8)` puede ejecutar post-hooks privilegiados tras fallo de un helper externo | `mount` no existe, el DSO `libmount` fue eliminado y no hay montajes `fstab` | **Ruta conocida no disponible en este contenedor**, CVE abierto |
| `CVE-2026-78408` | `nsenter --join-cgroup` puede filtrar un descriptor `cgroup.procs` abierto con autoridad inicial de root | `nsenter`/`unshare` ausentes; no se heredó ese descriptor en el proceso auditado; sin capacidades ni nuevos privilegios | **Ruta conocida no disponible**, CVE abierto; ausencia puntual de descriptor, no prueba universal |
| `CVE-2026-78409` | Resolución de symlinks en `X-mount.subdir` puede escapar de un árbol detached en `open_tree()` | Ejecutable `mount` y `libmount` ausentes; `fstab` no configura X-mount.subdir | **Ruta conocida no disponible**, CVE abierto |
| `CVE-2026-78410` | TOCTOU en fuente de un montaje `bind` restringido; los hooks de owner/group/mode pueden afectar un inode redirigido | `mount` y `libmount` ausentes; `fstab` sin entradas bind ni X-mount.owner/group/mode | **Ruta conocida no disponible**, CVE abierto |

**Límites de la conclusión:** los checks se ejecutan en un contenedor efímero bajo parámetros específicos y sin documentos privados. No demuestran que otros componentes no puedan invocar syscalls de montaje, crear rutas alternativas, cargar una biblioteca por nombre construido, ni que un fallo diferente del origen util-linux sea inexplotable. No se publicará un documento VEX y no existe autorización de release.

## Estado oficial de parches a la fecha

- [Debian Security Tracker, util-linux](https://security-tracker.debian.org/tracker/source-package/util-linux): **Debian Trixie** reporta los cuatro CVE como vulnerables (no DSA). Versión estable local: **2.41.5-0+deb13u1**.
- [Anuncio upstream util-linux 2.42.3](https://lists.openwall.net/linux-kernel/2026/09/02/767): documenta correcciones de CVE-2026-76642, CVE-2026-78409 y CVE-2026-78410, además de un primer endurecimiento para CVE-2026-78408.
- [Anuncio upstream 2.42.4](https://lists.openwall.net/linux-kernel/2026/09/21/1759): cierra la brecha restante de CVE-2026-78408 al **cerrar `cgroup.procs` tras unir el proceso**, en lugar de confiar solo en O_CLOEXEC.
- [Debian 2.42.4-1 admitido en unstable](https://tracker.debian.org/news/1803201/accepted-util-linux-2424-1-source-into-unstable/): la corrección completa está en **sid/forky**, no demuestra que exista un paquete Trixie equivalente.

**Decisión de compatibilidad:** NO instalar ni copiar librerías de `sid`/`forky` al contenedor Debian Trixie. La vía preferida es un **backport oficial de Trixie** y validación de su procedencia; alternativa controlada: reconstrucción aislada con fuentes verificadas, parches individualmente trazados y regresiones específicas, sin mezclas ABI.

El parche completo de origen **no ha sido aplicado** en R1.30. No se ha descargado ni instalado `util-linux 2.42.4` en el runtime.

## Implementación TDD / controles verificables

1. `apps/inspector/util_linux_cve_runtime.py`: ejecutado mediante `python3 -I -c` dentro de la imagen por **ID inmutable**. Sin operaciones de escritura, network, instalación ni payloads. Valida versiones de **nueve paquetes**, usuario/privilegios/raíz/red/archivos, fstab, ausencia de descriptores cgroup.procs en el proceso comprobado y carga fallida del DSO.
2. `apps/inspector/util_linux_cve_gate.py`: vincula ese reporte al **Docker ID exacto**, la arquitectura amd64, imagen de 2 capas aplanadas, configuración no root, Trivy JSON y CycloneDX. Exige **los 36 registros HIGH exactos** (9 paquetes × 4 CVE); cualquier ausencia, reclasificación, versión cambiada, duplicado o cambio de PURL de esos paquetes falla. Reutiliza validadores R1.28 y R1.29 para prohibir restitución de archivos ELF/capas peligrosas. Devuelve código **3** ante evidencia inconsistente y **2** cuando toda la evidencia es íntegra; **jamás devuelve autorización de publicación**.
3. `apps/inspector/scan_util_linux_cve_scope.sh`: realiza un solo Trivy JSON, un solo CycloneDX y tres probes Docker. El probe funcional usa UID65534, `--network none --read-only --cap-drop ALL --security-opt no-new-privileges`. Dos probes separados de **auditoría únicamente** usan root con capacidad DAC_READ_SEARCH sin red para enumerar directorios root-only; jamás ejecutan el inspector ni procesan documentos. Verifica que el Docker ID no cambie durante la operación. Los informes temporales se eliminan mediante `trap`.
4. `apps/inspector/tests/test_util_linux_cve_scope.py`: **siete pruebas TDD nuevas**, RED antes de crear módulos, GREEN tras implementación. Casos negativos: archivo `mount` reintroducido, otra biblioteca libmount con SONAME alternativo, `fstab` activo, privilegios/capacidades/red inesperados, cgroup.procs heredado, versiones/UID/Trivy/CycloneDX/CVE/RootFS/CLI alterados. Se verifica `exit 2` para evidencia válida y `exit 3` para adulteración.

## Resultado ejecutado

| Evidencia | Resultado |
| --- | --- |
| Imagen Docker local auditada | `sha256:0af77fb9144634a8e4d77456eb460f92e5d9274ad042f52483157330d565651c` |
| CVE HIGH exactos presentes en Trivy | **36/36**, nueve paquetes derivados de util-linux |
| Rutas y alias de comandos/DSO ausentes | **19/19** |
| Fstab con entradas no comentadas | **0** |
| Descriptores cgroup.procs en el proceso de auditoría | **0** |
| Referencias ELF a libmount, auditoría R1.29 | **0** |
| Herramientas privilegiadas R1.28 restauradas | **0** |
| UID, CapEff, NoNewPrivs, read-only root y red | **65534, cero, habilitado, sí, solo loopback** |
| CVE totales de imagen CRITICAL / HIGH / UNKNOWN | **0 / 59 / 15** |
| Trivy, SBOM y pruebas de escenario CVE | **exit 2 — integridad confirmada, publicación bloqueada** |
| VEX, source patch, despliegue, merge, autorización release | **Ninguno** |

## Reproducir

```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_util_linux_cve_scope.py' -v
bash apps/inspector/scan_util_linux_cve_scope.sh  # exit 2 esperado
FOLIO_E2E_PORT=43130 sh scripts/ci.sh
```

**CI local integral verificada (después de los cambios R1.30):** `FOLIO_E2E_PORT=43130 sh scripts/ci.sh` terminó **exit 0**, con **414/414 pruebas Vitest TypeScript** (72 suites), **230/230 pruebas Python inspector**, **5/5 Workers locales**, **81/81 Chromium/Playwright** (desktop, móvil y reflow), 7 tests del contrato de CI local, `tsc --noEmit`, compilaciones Web/API/MCP/Processor/Gateway, cuatro dry-runs Workers y migraciones D1 **únicamente locales**. El puerto 43130 estaba libre y evita interferir con otros worktrees; **no se cambió el script de CI**.

La CI de este proyecto es **local mediante el shell script**. No se utilizó GitHub Actions. Debe seguir diferenciándose una CI funcional aprobada del **gate independiente de seguridad**, que permanece bloqueado (59 HIGH / 15 UNKNOWN). 
