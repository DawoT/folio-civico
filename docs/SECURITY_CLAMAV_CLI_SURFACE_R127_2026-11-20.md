# R1.27 · Reducción verificable de comandos ClamAV en la imagen del inspector

**Fecha:** 2026-11-20 (America/Lima). **Rama:** `security/clamav-cli-r127`, basada en `security/clamav-provenance-r126`. **Estado:** exclusivamente experimento Docker local, **NO RELEASE**, sin VEX, merge, deploy, push de imagen OCI, secretos ni datos institucionales.

## Causa raíz y corrección tras prueba adversaria

El paquete firmado por Cisco Talos `clamav 1.5.5-1` instala **11 comandos** en `/usr/local/bin` y `/usr/local/sbin`. El único comando necesario en el runtime que analiza PDFs es `clamscan`. `freshclam` es necesario **solo al construir la imagen** para descargar firmas del proveedor; no debe ejecutarse cuando se procesan documentos. `clamd`, `clamonacc`, `clamdscan` y otras herramientas administrativas tampoco son necesarias.

**Se detectó y rechazó la primera mitigación:** cambiar permisos de los diez ELF a `0644` impedía `execve` directo, **pero no la carga mediante `/lib64/ld-linux-x86-64.so.2 /usr/local/bin/freshclam`**. La prueba adversaria reprodujo que `freshclam` y `clamdscan` iniciaban ejecución y solo después fallaban por ausencia de sus archivos de configuración. Por tanto, **la variante chmod-only no se considera una mitigación suficiente y no se publica en Git**.

**Corrección:** el builder R1.27 **elimina físicamente** los diez archivos innecesarios, verifica el único comando superviviente y copia el filesystem final a una imagen nueva mediante `FROM scratch`, sin capas históricas OCI con los ejecutables eliminados. El kernel devuelve `ENOENT` y el cargador ELF falla al intentar iniciar cualquiera de las diez rutas. La eliminación es explícita, de rutas exactas y con manifest de `dpkg-query` validado, nunca un `rm -rf` genérico.

## Contrato de archivos

| Programa | Estado R1.27 |
| --- | --- |
| `/usr/local/bin/clamscan` | **Presente**, ejecutable (`0755`), SHA-256 idéntico |
| `clamav-config`, `clambc`, `clamconf`, `clamdscan`, `clamdtop`, `clamsubmit`, `freshclam`, `sigtool`, `clamd`, `clamonacc` | **Ausentes** en el filesystem final |
| `libclamav.so.12.1.0`, bibliotecas de descompresión, bibliotecas Rust, `libfreshclam.so.4.0.0` | Presentes; cada SHA-256 retenido se cotejó con el paquete firmado |
| Metadatos `dpkg` del paquete `clamav` | Conservados para mantener visibilidad del escáner; **desajuste esperado y limitado a las diez rutas eliminadas** |

La distinción es esencial: **`dpkg -V clamav` NO queda limpio** después de borrar archivos que pertenecen al paquete. El inventariador `clamav_cli_native_inventory.py` exige que sus únicos diagnósticos sean exactamente los **diez `missing` declarados**, sin ningún otro archivo modificado o ausente. Esto evita reclamar falsamente integridad completa de la instalación Debian después de una poda deliberada.

## Implementación con TDD y verificación independiente

1. La fase RED de las pruebas exigía módulos inexistentes; seis casos nuevos verifican allowlist exacta, fallos ante rutas adicionales/symlinks/estados parciales, pertenencia a `dpkg-query`, bytes de `clamscan`, identidad Talos, manipulación de CVE y metadatos OCI.
2. `clamav_cli_surface.py`: valida el manifiesto exacto de **11** comandos, la versión `1.5.5-1`, propiedad de archivos regulares root y el estado `baseline`; elimina las diez rutas predefinidas y comprueba el estado `limited`: **diez ausentes, solo `clamscan` presente** con SHA-256 inalterado.
3. `Dockerfile.clamav-cli-experiment`: el endurecimiento ocurre en una etapa desechable. `FROM scratch` y `COPY --from=hardener / /` evitan retener en la imagen los ejecutables de las capas anteriores. Configuración operacional, usuario `65534:65534` y los motores PDF/OCR/ClamAV se mantienen intactos.
4. `clamav_cli_denial_smoke.py`: prueba real en contenedor sin red, `CapEff=0`, `NoNewPrivs=1`, rootfs read-only, UID 65534, CPU/memoria y pids limitados. Comprueba **diez respuestas ENOENT** en ejecución directa, **diez fallos del cargador ELF**, y versión de `clamscan` sin cambios.
5. `clamav_cli_native_inventory.py`: mide el ELF y las bibliotecas realmente instaladas, coteja las diez ausencias con el resultado literal de `dpkg -V`, comprueba `ldd` contra `libclamav.so.12.1.0` y genera un manifiesto de los **7 archivos nativos** retenidos.
6. `scan_clamav_cli_experiment.sh`: vuelve a descargar y verificar temporalmente el `.deb` oficial, su firma detached y la clave Talos (huella primaria fija `5BADCA2665EF59DCF8A23D8B707F0DB480836771`). Recolecta Trivy JSON y CycloneDX para ambas imágenes, los dos inventarios de CLI y los dos manifiestos de código nativo **por ID Docker inmutable**.
7. `clamav_cli_gate.py`: vuelve a utilizar `verify_signed_vendor_evidence` R1.26 para exigir que los **16/16** archivos nativos de la imagen origen coincidan con el paquete firmado. Exige que los **7/7** archivos retenidos en la imagen destino sean los bytes originales, que solo se hayan quitado **9 ELF nativos y un script**, que no se haya cambiado ningún paquete, CVE, configuración ni capa OCI con contenido. Toda discrepancia **exit 3**; evidencia íntegra **exit 2 / blocked**, sin posibilidad de liberar la imagen.

## Resultados ejecutados

| Control | Resultado |
| --- | --- |
| Imagen R1.24/R1.26 origen | `sha256:e79cf1ad4dc960cf892d1bb267297f3ce8563abf4ee7749753aa4e8338626d4e` |
| Imagen R1.27 final | `sha256:9183e79856f5d3ede45e5324b78ddd965959ab42a9719bbadaeb17cfcf739b73` |
| Firma GPG/Talos del paquete oficial | Verificada |
| Código nativo original equivalente al paquete firmado | **16/16** |
| Código nativo retenido equivalente a su origen firmado | **7/7** |
| Entradas ejecutables ClamAV eliminadas físicamente | **10** |
| Verificación `dpkg -V` de eliminación exacta | **10/10 `missing` previstos; ningún otro** |
| ClamAV `clamscan`, detección EICAR, PDF y OCR | **6/6 controles reales** |
| Autorización HTTP/manifest, hash y health | **4/4 controles reales** |
| Intentos de ejecución directa y con cargador ELF | **Todos denegados** |
| Paquetes Debian instalados en el manifiesto | **141**, sin alteraciones |
| CVE Trivy general CRITICAL/HIGH/UNKNOWN | **0/59/19**, sin alteraciones |
| CVE ClamAV HIGH/MEDIUM | **7/6**, sin alteraciones |
| Capas anteriores con contenido reutilizadas | **0** |
| Auditoría diferencial completa | **exit 2 — publicación bloqueada** |
| VEX, waiver, merge, deploy, publicación OCI | **Ninguno** |

El *package manifest* de Debian **intencionalmente contiene rutas ya ausentes**; el SBOM de Trivy se mantiene por identidad de paquete, no garantiza que los 10 ejecutables estén presentes. Esa es la razón del inventario adicional de filesystem y del comparador. Los hash de código fuente de Poppler/Tesseract/Expat y el gate de release no cambian.

## Límites, pendientes y riesgo residual

La eliminación de comandos reduce el conjunto de herramientas disponibles para un atacante con ejecución arbitraria de código, pero **no corrige los CVE del parser de `libclamav` que invoca `clamscan`**. `libfreshclam.so` sigue retenida y podría ser alcanzada desde otro código; la defensa debe combinarse con política de red, seccomp, mínimos privilegios y firma/actualización segura de la imagen. Las bases de firmas se descargan **antes del runtime**; la política vigente exige actualización mediante un nuevo build y rechaza firmas antiguas.

Persisten **59 HIGH y 19 UNKNOWN** en el escaneo de la imagen, además de 7 HIGH y 6 MEDIUM de ClamAV cuyo ciclo de correcciones oficial requiere revisión CVE individual. La image solo es local y experimental: no se ha promovido, firmado para registro, ni ejecutado con documentos institucionales.

## Reproducir

```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_clamav_cli_surface.py' -v
bash apps/inspector/build_clamav_cli_experiment.sh
bash apps/inspector/scan_clamav_cli_experiment.sh # exit 2 esperado
sh scripts/ci.sh
```
