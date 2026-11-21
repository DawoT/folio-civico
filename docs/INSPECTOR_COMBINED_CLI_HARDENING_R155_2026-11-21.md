# R1.55 · G2 · Reducción combinada de CLI ClamAV y privilegiadas

**Fecha:** 2026-11-21. **Ticket:** [#144](https://github.com/DawoT/folio-civico/issues/144). **Contrato de coordinación:** [#133](https://github.com/DawoT/folio-civico/issues/133). **Alcance:** solo investigación con imágenes Docker locales, sin publicación OCI, Preview, producción, archivos institucionales, waivers ni VEX.

## Problema reproducido (RED)

La imagen de laboratorio R1.48 ya carece de **15 ejecutables privilegiados y administrativos** heredados, pero todavía conserva **10 comandos auxiliares ClamAV**. El servicio del inspector llama únicamente a `clamscan`; el resto incluye `freshclam`, `clamd` y herramientas de administración no necesarias en la operación de análisis HTTP. El probe existente `clamav_cli_denial_smoke.py`, ejecutado en la imagen R1.48 en modo no root, red deshabilitada y FS read-only, devolvió **exit 1**: `Unnecessary ClamAV program survived in runtime`. Un inventario independiente confirmó que los **16 archivos nativos** del paquete ClamAV en R1.43 y R1.48 tienen exactamente los mismos SHA-256.

Una investigación anterior R1.27 había implementado un eliminador de esas CLI, pero no se había combinado con las defensas posteriores R1.48. No se modifica `inspector.py` ni el Dockerfile operativo.

## Implementación experimental (GREEN)

Se reutiliza `clamav_cli_surface.py` en un build **sin red ni pull de imágenes**, aplicado sobre el objeto inmutable R1.48 y reempaquetado desde `FROM scratch`. El runtime conserva UID 65534, CMD, variables de entorno, puertos y todas las bibliotecas empleadas por los motores. El build usa explícitamente **`python3 -B -I`**: la primera prueba del prototipo con `-I` generó dos archivos `__pycache__`, detectados como adiciones indebidas por el inventario exhaustivo. Se cambió a `-B -I`, reconstruyó y verificó de nuevo: cero archivos extra.

| Propiedad | Imagen anterior R1.48 | Imagen experimental R1.55 |
|---|---|---|
| Docker ID local | `sha256:089a9fdd23ca5d8ca6274c546ff4f249ecfb4c6713b5f5135dcf0b888f8c882a` | `sha256:767e28efb6607eb74dc0ef24114583a0ba74c057a6ae7978509f82cf9ce2b327` |
| Rutas permanentes completas | 6513 | 6503 |
| Comandos ClamAV auxiliares | 10 presentes | 0 presentes |
| Código nativo ClamAV | 16 archivos | 7 archivos |
| Código nativo conservado | — | 7/7 SHA-256 idénticos |
| SUID/SGID | 0 | 0 |
| Poppler/Tesseract/modelos OCR | hashes verificados | sin cambios |
| SBOM CycloneDX / registros Trivy | baseline exacta | sin diferencias |
| CRITICAL / HIGH / UNKNOWN | 0 / 55 / 15 | **0 / 55 / 15** |
| Gate de release | bloqueado | **bloqueado** |

La auditoría total compara cada ruta y SHA con el mismo snapshot de base de datos Trivy. **R1.55 solo elimina las diez rutas previstas**: cero adiciones, cero modificaciones, cero rutas inesperadas. Los dos objetos OCI son distintos y las capas no vacías no se heredan. El build posterior en otro equipo o día no queda autorizado por este digest; necesita nueva atestación.

Los scripts reproducibles de investigación son:
- `apps/inspector/build_combined_cli_r155_research.sh` — reconstrucción local offline desde la base fijada; no publica.
- `apps/inspector/scan_combined_cli_r155_research.sh` — inventario FS íntegro, comparativa Trivy/CycloneDX, fuentes/modelos, enlaces/archivos ClamAV. **Exit 2 cuando evidencia válida y release bloqueado; exit 3 si incompleta**.
- `apps/inspector/combined_cli_prune_r155.py` — validador fail-closed con resultados estructurados, independiente del script de recolección.
- `apps/inspector/tests/test_combined_cli_prune_r155.py` — pruebas adversariales y contrato de no regresión.

Los informes brutos se mantienen en un directorio privado temporal, con eliminación en la salida del wrapper; únicamente se emiten campos de procedencia y contadores. La única ejecución forense con `DAC_READ_SEARCH` y root se usa para lectura exhaustiva y **nunca** para procesar documentos; los smokes operativos usan UID 65534, sin red, privilegios ni escritura en root.

## Pruebas de comportamiento realizadas en el digest final R1.55

- `clamav_cli_denial_smoke.py`: exit 0, diez CLI ausentes (incluido rechazo de ejecución por cargador ELF), `clamscan` presente.
- `clamav_cli_native_inventory.py`: exit 0, 7 binarios/librerías conservados, `dpkg -V` solo las diez eliminaciones esperadas, SONAME vinculado a la biblioteca conservada.
- `smoke_real_engines.py`: exit 0, texto PDF y OCR reales sintéticos, antivirus EICAR detectado, parser aislado, adjuntos/cifrado/malformados rechazados.
- `smoke_http_real.py`: exit 0, health correcto, petición no autenticada y SHA falsificado rechazados, manifest unsigned válido solo para la prueba.
- `smoke_signature_freshness.py`: exit 0, firma fresca aceptada y vencimiento simulado a 72 horas bloqueado.
- El primer gate de FS detectó y rechazó dos `__pycache__` indebidos; con `-B -I`, el gate final **exit 2** con identidad, FS, SBOM, scanner y DSO verificadas.

## Limitaciones y plan de integración

El resultado **no remedia ninguno de los 55 HIGH ni 15 UNKNOWN**; los componentes instalados y sus filas de escáner siguen intactos. El inventario de fuentes Poppler/Tesseract mantiene `source_cve_coverage=unassessed`. Las firmas ClamAV embebidas expiran a las 72 horas. No se infiere que una función vulnerable es inalcanzable solo porque se eliminó un ejecutable; quedan bibliotecas cargadas por `clamscan` y motores de PDF. No existe firma reproducible source→ELF ni aprobación humana G2/G4. **`release_authorized=false` y `vex=not_issued`**.

La corrección existe en rama/worktree aislados del ticket #144, pero el límite WIP 2/2 está ocupado por #135 y #139. No abrir tercer PR ni fusionar nada sin **revisión independiente**. Antes de integración: tests focales, `sh scripts/ci.sh` sobre el SHA exacto, PR cuando haya cupo, revisión, merge y nueva CI **local** posterior, conforme #133. Si falla una futura prueba de equivalencia, no debilitar el gate: revertir el PR o descartar la nueva imagen experimental, conservando R1.48 como referencia no publicable.
