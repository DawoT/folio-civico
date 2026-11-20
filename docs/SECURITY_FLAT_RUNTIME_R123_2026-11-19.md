# Seguridad R1.23 · Imagen experimental sin capas OCI heredadas

**Fecha de investigación:** 2026-11-19 (America/Lima). **Ámbito:** worktree `security/flat-runtime-r123`, sobre la rama experimental R1.22 `security/headless-runtime-r122`. **No autoriza** Preview, producción, publicación OCI ni emisión de VEX.

## Causa raíz y objetivo

Las imágenes R1.18–R1.22 mejoraron el *filesystem* visible mediante instalaciones y `apt-get purge`, pero heredaban **20 capas OCI**, incluidas capas donde paquetes purgados estuvieron presentes. Aunque el contenedor de runtime ya no cargaba esos ejecutables, los bytes de capas históricas podían permanecer recuperables en un artefacto OCI.

Objetivo R1.23: crear un **nuevo artefacto experimental por `FROM scratch`** que copie únicamente el árbol de archivos final desde una fase temporal `pruner`; conservar su identidad funcional, no heredar **ninguna capa anterior que contenga archivos**, probar una reducción adicional estricta del paquete `libncursesw6`, y mantener el gate CVE bloqueado.

## Investigación de dependencias

Se simuló `apt-get -s purge` en `folio-civico-inspector:headless-pruned-experiment` para dependencias HIGH. Debian rechazó la retirada de `libacl1`, `libudev1`, `libsystemd0`, `libssl3t64`, `libtinfo6`, `libblkid1`, `libsqlite3-0` y otras por dependencias de `coreutils` o `util-linux`. `ncurses-bin`, `ncurses-base`, `dpkg` y `perl-base` no pueden purgarse sin intervenir paquetes esenciales. La retirada de `libtiff6` o `libopenjp2-7` desinstalaría `libleptonica6`; la de `libgnutls30t64` desinstalaría `qpdf`. No se forzó ninguna de estas operaciones.

En cambio, la simulación de `pinentry-curses` y `libncursesw6` devuelve **exactamente dos paquetes**, sin advertencia de elementos esenciales. `pinentry-curses` había quedado huérfano tras eliminar GnuPG R1.21, y `libncursesw6` aporta un aviso HIGH `CVE-2025-69720` al paquete propio. No se retira `libtinfo6` ni `ncurses-bin`; sus avisos continúan.

## Implementación con TDD

1. **Red:** no existía el comparador de imagen plana. Las pruebas detectaron además un control incorrecto que confundía un CVE eliminado con una exención implícita.
2. **Green:** `Dockerfile.flat-runtime-experiment` exige que la simulación de APT elimine exclusivamente `pinentry-curses` y `libncursesw6`, sin `--allow-remove-essential`, `autoremove` ni paquetes adicionales. Valida permanencia de motores PDF/ClamAV/OCR, bibliotecas y modelos, crea fase `FROM scratch` y copia **solo el árbol de archivos final** con `COPY --from=pruner / /`. Reproduce configuración operacional de usuario, `PATH`, modelos, firma antivirus, puerto y comando del servicio.
3. Se elimina únicamente la variable `GPG_KEY` heredada de la imagen oficial de Python: es la huella de una **clave pública de verificación usada en build**, innecesaria para runtime. El comparador exige esta omisión exacta y rechaza cualquier cambio de otras variables funcionales.
4. `build_flat_runtime_experiment.sh`: no cambia la etiqueta padre, comprueba las capas Docker antes de ejecutar antivirus/PDF/OCR/HTTP bajo contenedores con `--network none`, `--read-only`, capacidades nulas y límites de memoria/CPU.
5. `flat_runtime_comparison.py` y `scan_flat_runtime_experiment.sh` reconcilian dos escaneos Trivy JSON, dos SBOM CycloneDX, los dos objetos `docker image inspect`, e inventarios nativos **medidos dentro de cada digest inmutable**. Exigen que no haya cambios de binarios ni de modelos OCR, biblioteca Expat, parche o paquetes y CVE ajenos. El único HIGH que puede desaparecer es `CVE-2025-69720` atribuido a `libncursesw6`.
6. BuildKit crea una **segunda capa vacía** para `WORKDIR`; en el control inicial falló la hipótesis de una única capa. La política ahora exige dos capas exactas: **una nueva con contenido** y **una capa tar vacía** con DiffID conocido `5f70bf18...`. No admite compartir con el padre ningún DiffID que contenga archivos. Así no se confunde una capa vacía, deduplicable por contenido, con una capa histórica vulnerable.

## Resultados de la comparación diferencial observada

| Medición | Padre R1.22 | R1.23, imagen plana experimental |
| --- | ---: | ---: |
| CRITICAL | 0 | **0** |
| HIGH | 60 | **59** |
| UNKNOWN | 19 | **19** |
| Paquetes Debian detectados | 143 | **141** |
| Capas OCI totales | 20 | **2** |
| Capas antiguas con contenido reutilizadas | — | **0** |
| Paquetes retirados | — | **2** |
| CVE ajenos desaparecidos o nuevos | — | **0** |
| Procedencia de Expat/Poppler/Tesseract | documentada | **inalterada** |
| Estado de seguridad | blocked | **blocked / exit 2** |

**Digest de las imágenes locales medidas:** base R1.22 `sha256:df8b791d742ed3583541b53bfd373698277635cccc9195b6e24bcd2847109aea`; resultado R1.23 `sha256:0d75d8790bcdd758340a4014a705fe246283df8c97fb66a222f8c22d7688d50e`. Son IDs locales de Docker, **no** digests firmados de un registro OCI.

**Pruebas reales finales:** build con salida 0, **6/6** casos de motores PDF, OCR y antivirus, **4/4** casos de protocolo HTTP y autorización, **4/4** pruebas TDD focalizadas, **189/189** pruebas Python del inspector. La CI local integral `sh scripts/ci.sh` finalizó **exit 0**, con Vitest, TypeScript, builds/dry-runs de Workers, Playwright Chromium y D1 locales; **no** implica autorización del gate del inspector. `scan_flat_runtime_experiment.sh` devuelve **2** (bloqueo de seguridad previsto) después de validar dos informes CycloneDX, dos escaneos de CVE, dos `docker inspect` y los inventarios ELF/Expat medidos sin red en cada contenedor.

La comparación no constituye una autorización de lanzamiento. El artefacto resultante **no** es todavía un rebuild reproducible independiente desde fuentes verificadas de todos los motores. Cualquier archivo que estuviera presente en el árbol final de la imagen padre también se copia; la operación no reemplaza una auditoría de secretos, contenido o licencias. Tampoco resuelve los paquetes HIGH que deben continuar instalados.

## Bloqueantes posteriores

- **59 HIGH / 19 UNKNOWN** observados por Trivy en el runtime experimental. Los 36 registros de `util-linux` corresponden a cuatro CVE propagados a múltiples paquetes esenciales; Debian Trixie no tiene todavía parche estable que demuestre su cierre. No utilizar binarios `sid` directamente.
- ClamAV 1.5.5 cuenta siete HIGH atribuibles a CVE que el fabricante documentó corregidos desde 1.5.3; se necesita evaluación formal de procedencia, versión y aplicabilidad por CVE antes de emitir VEX o levantar el gate.
- Expat, Poppler y Tesseract requieren evidencia y clasificación de vulnerabilidades individuales; un CycloneDX y los hashes ELF miden identidad, no prueban ausencia de vulnerabilidades.
- Seguridad de redes, admisión en Container/Preview, firmas, SBOM completo de build, compatibilidad con producción y datos institucionales siguen sin autorización.

**Operación:** ninguna imagen de referencia, bucket, cola, D1 remota, servicio Cloudflare, imagen OCI publicada o documento institucional fue modificado.

## Repetición

```bash
python3 -m unittest discover -s apps/inspector/tests -p 'test_flat_runtime.py' -v
bash apps/inspector/build_flat_runtime_experiment.sh
bash apps/inspector/scan_flat_runtime_experiment.sh # exit 2 esperado
sh scripts/ci.sh
```
