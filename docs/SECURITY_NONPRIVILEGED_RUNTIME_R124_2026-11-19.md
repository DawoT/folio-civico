# Seguridad R1.24 · Eliminación de ejecutables privilegiados en runtime

**Fecha de corte:** 2026-11-19 (America/Lima). **Alcance:** imagen local `folio-civico-inspector:nonprivileged-experiment`, derivada exclusivamente de `flat-runtime-experiment` (R1.23). **NO autoriza** fusiones de la cadena experimental, VEX, release, Preview ni producción.

## Incidente observado y amenaza

Una inspección directa de la imagen R1.23 detectó **11 archivos regulares con bits SUID/SGID** en `/usr/bin` y `/usr/sbin`:

| Familia | Ejecución anterior | Mitigación R1.24 |
| --- | --- | --- |
| `mount`, `umount` | SUID root, `4755` | `0644`; sin ejecución |
| `su`, `passwd`, `chsh`, `chfn`, `newgrp`, `gpasswd` | SUID root, `4755` | `0644`; sin ejecución |
| `chage`, `expiry`, `unix_chkpwd` | SGID shadow, `2755` | `0644`; sin ejecución |
| `nsenter`, `unshare`, `setpriv` | ejecutables no SUID, `0755` | `0644`; sin ejecución |

Total: **11** rutas anteriormente SUID/SGID y **14** ejecutables administrativos deshabilitados. Los paquetes Debian `util-linux`, `mount`, `libmount1` y demás bibliotecas **se conservan intactos** para mantener su árbol de dependencias.

Los cuatro CVE del grupo `util-linux` se aplican a operaciones de privilegio/mount/namespaces: `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409`, `CVE-2026-78410`. Esta medida reduce rutas de ejecución directas **pero NO repara `libmount` ni cambia la versión de Debian**. Otros entrypoints o usos a través de bibliotecas podrían persistir. No se solicita una clasificación VEX automática.

Referencias técnicas y correcciones upstream:
- [Debian Security Tracker: CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642).
- [Red Hat: CVE-2026-78408](https://access.redhat.com/security/cve/cve-2026-78408) (`nsenter --join-cgroup`).
- [Red Hat: CVE-2026-78409](https://access.redhat.com/security/cve/cve-2026-78409) y [CVE-2026-78410](https://access.redhat.com/security/cve/cve-2026-78410) (`libmount`).
- [Debian aceptó `util-linux 2.42.3-1` en unstable](https://tracker.debian.org/news/1793594/accepted-util-linux-2423-1-source-into-unstable/); no se instaló ningún paquete `sid` ni se hizo backport de un componente esencial.

## Implementación fail-closed con TDD

1. Se creó la rama independiente `security/nonprivileged-r124` sobre R1.23. **Red inicial:** los tests no encontraban `privilege_surface` ni `privilege_gate`. Se añadieron casos de cambio de modo, reemplazo por symlink, archivo desconocido con SUID, CVE desaparecido, identidad de imagen, metadata OCI y desajuste de huellas SHA-256.
2. `privilege_surface.py` recorre el filesystem estático y **rechaza errores de enumeración**. Verifica **exactamente** las 11 rutas originales SUID/SGID y 14 rutas de lanzamiento con ELF y SHA-256; transforma cada una a `0644` y comprueba que **ningún byte cambió** y que no queda ningún archivo con SUID/SGID en los directorios estáticos incluidos.
3. `Dockerfile.nonprivileged-experiment` hace el endurecimiento en una etapa intermedia y luego reconstruye la imagen mediante `FROM scratch` y `COPY --from=hardener / /`. **No reutiliza capas OCI anteriores con contenido**; conserva la configuración, el usuario 65534 y los motores/documentos base. No añade binarios ni instala paquetes nuevos.
4. `privilege_denial_smoke.py` corre **realmente** dentro del contenedor como UID 65534, con rootfs de solo lectura, `CapEff=0` y `NoNewPrivs=1`. Comprueba 14 permisos `0644` y que el kernel **niega con `EACCES`** la ejecución de `mount`, `umount`, `nsenter`, `unshare`, `setpriv` y `su`. La ruta de prueba no procesa expedientes ni documentos personales.
5. `privilege_gate.py` compara los **dos digest Docker inmutables**, sus listas exactas de vulnerabilidades Trivy, SBOM CycloneDX, configuración del contenedor y permisos + SHA-256 de los 14 ELF. Cualquier pérdida de un CVE o cambio del inventario de paquetes provoca **exit 3**, no una reducción artificial del score. Con evidencia coherente se devuelve **exit 2 (blocked)**.
6. El inventario offline inicial reveló que `--cap-drop ALL` impide recorrer el directorio APT `/var/cache/apt/archives/partial`, por lo que devolvía exit 3, como estaba previsto. Para no falsear cobertura, **solo el contenedor efímero de auditoría** usa `--cap-add DAC_READ_SEARCH --user 0:0`; continúa sin red, con filesystem read-only y sin montajes. El runtime y las pruebas de motores permanecen sin capacidades.

## Resultados verificables

| Métrica | R1.23 | R1.24 |
| --- | ---: | ---: |
| Trivy CRITICAL | 0 | **0** |
| Trivy HIGH | 59 | **59** |
| Trivy UNKNOWN | 19 | **19** |
| Paquetes Debian | 141 | **141** |
| Cambios no autorizados de paquetes/CVE | — | **0** |
| Ejecutables SUID/SGID | 11 | **0** |
| Utilidades administrativas ejecutables medidas | 14 | **0** |
| Cambios de contenido ELF en los 14 binarios | — | **0** |
| Capas históricas con contenido reutilizadas | — | **0** |
| Autorización de liberación | **no** | **no** |

ID de imagen experimental local: `sha256:e79cf1ad4dc960cf892d1bb267297f3ce8563abf4ee7749753aa4e8338626d4e`. ID padre: `sha256:0d75d8790bcdd758340a4014a705fe246283df8c97fb66a222f8c22d7688d50e`. **No son digests de registro o atestaciones firmadas.**

El builder terminó con **exit 0**; los motores reales aprobaron **6/6** pruebas PDF/ClamAV/OCR y **4/4** pruebas HTTP/autorización. La prueba negativa del kernel `privileged_entrypoints_denied` completó con **exit 0**. El escaneo diferencial completó con **exit 2** y mantuvo íntegros todos los registros HIGH/UNKNOWN. TDD focalizado **6/6**; suite Python del inspector **195/195**. La CI integral local `sh scripts/ci.sh` finalizó con **exit 0** (Vitest, TypeScript, compilaciones y dry-runs de Workers, Playwright Chromium y migraciones D1 locales); **no** es aprobación del gate CVE.

## Revisión de los siete avisos ClamAV

La imagen sigue incorporando un `.deb` del fabricante Cisco Talos cuya firma GPG se verifica durante el build con una huella primaria fijada, y confirma el motor `ClamAV 1.5.5`. Las publicaciones del proveedor indican que los siete CVE siguientes fueron corregidos ya en **1.5.3**: `CVE-2026-20213`, `CVE-2026-20214`, `CVE-2026-20215`, `CVE-2026-20216`, `CVE-2026-20217`, `CVE-2026-20243`, `CVE-2026-20244`.

Fuentes: [Cisco Talos, ClamAV 1.5.3/1.4.5](https://blog.clamav.net/2026/07/clamav-153-and-145-security-patch.html); [Ubuntu USN-8517-1](https://ubuntu.com/security/notices/USN-8517-1). **Esta correlación de versiones no demuestra reproducibilidad bit a bit ni revisión binaria específica por CVE**. No se ocultan los siete HIGH, ni se emite VEX, ni se modifica la clasificación de Trivy. La firma del artefacto descargado no equivale a la atestación de la imagen OCI final.

## Riesgos y pendientes

- **59 HIGH y 19 UNKNOWN** permanecen en el gate. El endurecimiento impide directamente ejecutar las 14 utilidades medidas, pero **no corrige los CVE en las bibliotecas** ni elimina otras cadenas de explotación. Algunas herramientas de Debian quedan deliberadamente inejecutables; una actualización futura del runtime puede reinstaurar permisos o necesitar esas herramientas, por lo que la política debe revalidarse en cada build.
- `libmount`, libc, SQLite, Expat, ClamAV y bibliotecas del OCR siguen pendientes de correcciones o análisis individual. La actualización desde `unstable` no está autorizada.
- La imagen no representa un runtime completo evaluado en Preview. El escaneo de permisos se limita al filesystem estático y excluye pseudo-filesystems y directorios efímeros; la futura configuración del Container debe mantener rootfs read-only, UID no root y ausencia de capacidades.
- **Sin** release, despliegue, firma OCI, VEX, documentación institucional, acceso a producción ni mutación de D1/R2/Queues.

## Repetición

```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_privilege_hardening.py' -v
bash apps/inspector/build_nonprivileged_experiment.sh
bash apps/inspector/scan_nonprivileged_experiment.sh # exit 2 esperado
sh scripts/ci.sh
```
