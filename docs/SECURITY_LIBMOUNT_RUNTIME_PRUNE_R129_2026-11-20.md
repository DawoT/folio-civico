# R1.29 · Reducción de libmount y sus nueve consumidores no requeridos

**Fecha:** 2026-11-20 (America/Lima). **Rama:** security/libmount-prune-r129, descendiente de security/privileged-loader-r128. **Resultado:** experimento local **NO DESPLEGABLE**, sin VEX, waiver, firma OCI, actualización del gate o cambio de binarios del inspector.

## Riesgo y criterio de intervención

R1.28 eliminó 14 comandos con privilegios/administración que seguían siendo cargables mediante el intérprete ELF a pesar de chmod 0644. La biblioteca compartida **libmount.so.1**, del paquete Debian Trixie **libmount1 2.41.5-0+deb13u1**, permanecía físicamente accesible.

La revisión de vulnerabilidades de util-linux ha mostrado cuatro CVE HIGH distintos en el paquete y sus derivados. No son intercambiables: las vulnerabilidades de mount(8), nsenter(1)/unshare(1), las opciones X-mount.subdir y las opciones X-mount.owner/group/mode tienen requisitos de explotación diferentes. Las referencias oficiales son:

- [Estado de vulnerabilidades util-linux en Debian Security Tracker](https://security-tracker.debian.org/tracker/source-package/util-linux).
- [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642): comprobación incorrecta del resultado del helper de montaje.
- [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408): descriptor abierto en nsenter / unshare.
- [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409): resolución de symlinks en X-mount.subdir.
- [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410): uso de rutas de origen vulnerables en montajes restringidos.
- [Publicación de parches upstream util-linux 2.42.3](https://tracker.debian.org/news/1793594/accepted-util-linux-2423-1-source-into-unstable/).

**La decisión NO consiste en incorporar binarios ni repositorios de Debian sid al runtime Trixie.** Se elimina solo código no necesario para el producto, se mantiene el SBOM de los paquetes y se deja a revisión la necesidad de una corrección de fuente o backport sustentado por pruebas de CVE individuales.

## Evidencia de alcance antes de modificar la imagen

Se examinaron **1.525 archivos ELF** bajo /usr y /opt (266.555.480 bytes). La búsqueda conservadora del SONAME **libmount.so.1** produjo exactamente **10 coincidencias**, correspondientes a:

| Paquete | Archivos ELF que contienen la referencia |
| --- | --- |
| util-linux | findmnt, lsblk, lslocks, lsns, mountpoint, fsck, fstrim |
| mount | swapoff, swapon |
| libmount1 | libmount.so.1.1.0 |

En total se identificaron **9 ejecutables administrativos no utilizados** y el ELF de la propia biblioteca. Se incluyó además el **symlink ABI** /usr/lib/x86_64-linux-gnu/libmount.so.1, que apunta a libmount.so.1.1.0. Los **11 archivos** pertenecen a 3 paquetes Debian según dpkg-query -S. Los motores PDF/OCR/AV y Python no declararon libmount como dependencia en sus comprobaciones dinámicas.

La búsqueda de cadenas sobre ELF tiene límites explícitos: **no demuestra ausencia de carga mediante un nombre construido dinámicamente, de enlaces inusuales o de caminos no ejecutados durante los smokes**. Por ello se incluyen pruebas adicionales de carga DSO, de dependencias de los motores y se mantiene el bloqueo de publicación.

## Implementación aislada y validación fail-closed

- **libmount_prune_surface.py:** afirma la propiedad Debian, versión de permisos, modo ELF y symlink exactos. Escanea todo ELF regular bajo /usr y /opt y exige exactamente las diez referencias conocidas **antes** de modificar. Después de retirar 9 binarios, el ELF y su alias, vuelve a escanear y **exige cero referencias al SONAME**. La eliminación no sigue symlinks arbitrarios ni usa comodines.
- **Dockerfile.libmount-prune-experiment:** utiliza la imagen R1.28 como builder descartable y genera un filesystem final con FROM scratch y COPY --from=hardener / /. Ninguna capa histórica con contenido puede contener los binarios eliminados. UID y configuración del inspector permanecen intactos.
- **libmount_prune_smoke.py:** se ejecuta en la imagen, UID 65534, sin red, sin capacidades y filesystem de solo lectura. Requiere ENOENT en los 9 comandos, error del cargador ELF en los mismos, **fallo al abrir libmount mediante ctypes.CDLL** y comprobación de dependencias ldd en Python, Poppler, Tesseract y ClamAV. Los smokes funcionales originales de PDF/OCR/antivirus y HTTP siguen siendo obligatorios.
- **libmount_prune_dpkg.py:** no falsifica un dpkg -V completamente limpio. Compara informes antes/después sobre **util-linux, mount y libmount1** y exige solo las 11 nuevas ausencias de archivos, conservando los paquetes y los faltantes históricos de documentación. Cualquier cambio extra o versión inesperada devuelve error.
- **libmount_prune_gate.py:** compara IDs de imagen Docker, pares Trivy JSON/CycloneDX, capas sin reutilización de contenido, configuración, inventarios ELF, diferenciales dpkg y hash de los archivos ClamAV retenidos. No acepta desaparición ni severidad menor para ningún CVE del scanner. **Exit 3** para evidencia incompleta; **exit 2** para evidencia íntegra y liberación BLOQUEADA.
- **test_libmount_prune.py:** seis pruebas TDD con fase RED por módulos ausentes, seguida de GREEN. Incluye pruebas de symlinks alterados, dependencias ELF imprevistas, faltantes adicionales, CVE suprimidos, versiones, hashes y capas OCI.

## Resultado y alcance de seguridad

La intervención se limita a **11 rutas eliminadas**: 9 utilidades, libmount.so.1.1.0 y libmount.so.1. **No se elimina un paquete del inventario Debian ni se alteran claves de D1/R2, la API, los datos ciudadanos o el código de aplicación.** Los hallazgos util-linux/libmount se mantienen en Trivy aun si el código DSO ya no existe, puesto que el reporte es sobre versión del paquete instalado en dpkg. No se emite un VEX ni una excepción de CVE.

La evaluación definitiva de las vulnerabilidades de Trixie requerirá evidencia específica de parches upstream/backport y controles de libmount o reemplazo por paquetes Debian oficialmente corregidos. Este experimento puede reducir la superficie disponible, pero **no demuestra que el código vulnerable restante sea seguro frente a todos los ataques**.

### Resultado real verificado (imagen inmutable y código nativo)

| Control | Resultado |
| --- | --- |
| Imagen local origen R1.28 | sha256:08d4bfe0baaf611adb7199495ec28177cecbe3b542693cac4d97a2c3c3a97afb |
| Imagen local R1.29 nueva | sha256:0af77fb9144634a8e4d77456eb460f92e5d9274ad042f52483157330d565651c |
| Build Docker y smokes sobre la imagen R1.29 | **Exit 0** |
| PDF/OCR/antivirus (incluye EICAR, rechazo de incrustados/cifrados/defectuosos) | **6/6** |
| HTTP/manifest/autorización/hash/health | **4/4** |
| Ejecución directa y mediante intérprete ELF de las nueve utilidades | **9/9 + 9/9 denegadas** |
| Carga dinámica de libmount.so.1 mediante ctypes.CDLL | **Rechazada** |
| Dependencias ldd de Python, Poppler, Tesseract y ClamAV | **Sin librería faltante ni libmount** |
| Referencias ELF al SONAME en destino | **0** |
| Paquetes del inventario Trivy Debian | **141 sin cambio** |
| Archivos desaparecidos adicionales según dpkg -V | **11 exactos en util-linux, mount y libmount1** |
| Hash de los archivos nativos de ClamAV | **7/7 preservados** |
| Capas antiguas con contenido reutilizadas | **0** |
| CVE totales CRITICAL/HIGH/UNKNOWN | **0 / 59 / 15** en ambas imágenes |
| Auditoría diferencial fail-closed | **Exit 2: release bloqueado** |
| Tests TDD nuevos | **6/6** |
| Suite Python completa del inspector | **223/223** |

Los 15 UNKNOWN son el corte actual de Trivy que ya aparecía en R1.28. Una instantánea anterior registró 19 UNKNOWN; esa diferencia histórica está atribuida a datos del escáner y **no** a estas eliminaciones. Los cuatro CVE HIGH de util-linux deben seguir abiertos en seguimiento aunque las nueve utilidades restantes y libmount ya no estén físicamente disponibles.

El ID es de una **imagen Docker local**, no constituye un digest publicado en un registro OCI ni una firma de distribución. Este experimento no permite afirmar que un atacante con ejecución arbitraria no pueda ejercer otras funcionalidades de montaje en Linux: quedan otras bibliotecas y llamadas al sistema bajo las políticas del runtime.

### Reproducibilidad local

\`\`\`bash
python3 -m unittest discover -s apps/inspector/tests -p test_libmount_prune.py -v
bash apps/inspector/build_libmount_prune_experiment.sh
bash apps/inspector/scan_libmount_prune_experiment.sh  # exit 2: bloqueado
FOLIO_E2E_PORT=4177 sh scripts/ci.sh
\`\`\`

**CI funcional:** solo script local sh; no se requiere GitHub Actions. El estado de publicación permanece independiente del éxito de CI.
