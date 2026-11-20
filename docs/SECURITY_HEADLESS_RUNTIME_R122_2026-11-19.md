# Seguridad R1.22 · Poda X11/Cairo en runtime documental headless

**Fecha:** 2026-11-19 (America/Lima). **Estado:** investigación local, rama `security/headless-runtime-r122`, sobre el commit R1.21 (`d55cb25`) y sin modificar imágenes operativas. **NO AUTORIZA** release, VEX, Preview ni producción.

## Hipótesis y selección

Después de R1.21, la imagen experimental tenía 63 registros HIGH y 19 UNKNOWN de Trivy. La dependencia de X11/Cairo quedó instalada pese a que el inspector es headless y sus cinco ejecutables de Poppler, los motores Tesseract y ClamAV no la muestran en sus `ldd` directos observados. Se investigó desinstalar **exclusivamente** cinco paquetes de la cadena X11/Cairo:

| Paquete | Motivo | Registros HIGH que desaparecen |
| --- | --- | ---: |
| `libx11-6` | Biblioteca de cliente X11 sin uso demostrado en este runtime | 1 (`CVE-2026-88806`) |
| `libx11-data` | Datos de X11 sin cliente X11 | 1 (`CVE-2026-88806`) |
| `libxrender1` | Extensión de renderizado X11 innecesaria para las CLI | 1 (`CVE-2026-88807`) |
| `libxext6` | Dependencia transitiva eliminada por APT | 0 |
| `libcairo2` | Dependencia transitiva eliminada por APT | 0 |

**Descartado:** `ncurses-bin` parece removible en un análisis superficial, pero la simulación APT marca su eliminación como la de un **paquete esencial**. Por eso no se ha incluido. `libtiff6` tampoco se elimina: forma parte de la dependencia real del motor OCR. No se ha empleado `apt-get autoremove` ni `--allow-remove-essential`.

## Implementación TDD
1. **Red:** el test nuevo no podía importar `headless_prune_comparison.py`; después, un caso de falsificación de CVE mostró la necesidad de restringir los CVE HIGH eliminados. Se detectó también que un comparador demasiado estricto rechazaba avisos LOW/MEDIUM de los mismos paquetes desaparecidos.
2. **Green:** `Dockerfile.headless-pruned-experiment` hereda **únicamente** `folio-civico-inspector:runtime-pruned-experiment`; simula `apt-get -s purge` y exige un conjunto **exacto de cinco paquetes y cero avisos de esenciales** antes de purgar. Comprueba la permanencia de `ncurses-bin`, `libtiff6`, `libleptonica6`, `qpdf`, `libexpat1` y certificados, además de los ejecutables, modelos OCR, fuentes, enlaces dinámicos y ClamAV 1.5.5.
3. `build_headless_pruned_experiment.sh` construye otra etiqueta sin tocar la base y ejecuta los smokes reales de PDF, OCR, antivirus y HTTP bajo contenedores sin red, sin capacidades y con filesystem de solo lectura.
4. `headless_prune_comparison.py` **reutiliza** los parsers Trivy/SBOM existentes de R1.21; exige identidades Docker distintas, borrado exacto de cinco paquetes, ninguna incorporación inesperada y cero modificaciones sobre los CVE de cualquier paquete conservado. Acepta que desaparezcan LOW/MEDIUM solo de los cinco paquetes eliminados; los HIGH desaparecidos han de ser **exactamente** los tres registros conocidos.
5. `scan_headless_pruned_experiment.sh` ejecuta cuatro escaneos (CVE JSON + CycloneDX por imagen) y verifica que las dos imágenes mantengan su digest original. No hay supresiones, VEX ni excepciones. **El estado final siempre es exit 2 (blocked)** cuando la diferencia es válida; las inconsistencias provocan exit 3.

## Evidencia ejecutada

| Resultado real | Antes (R1.21) | Después (R1.22) |
| --- | ---: | ---: |
| Paquetes Debian detectados | 148 | 143 |
| CycloneDX componentes | 150 | 145 |
| CRITICAL | 0 | 0 |
| HIGH | 63 | **60** |
| UNKNOWN | 19 | **19** |
| MEDIUM eliminados en los paquetes purgados | — | 6 |
| LOW eliminados en los paquetes purgados | — | 3 |
| Paquetes o CVE ajenos modificados | — | **0** |
| Gate de publicación | bloqueado | **bloqueado** |

- Base: `sha256:fb6fadc18a9e1190ec6b104b2faedfebb2381a627d4d9586dc416671da034b4f`.
- Nueva imagen experimental local: `sha256:df8b791d742ed3583541b53bfd373698277635cccc9195b6e24bcd2847109aea`.
- Docker build concluido con exit 0; motor real **6/6** (incluida detección EICAR, OCR, PDF malformado, cifrado y adjuntos) y HTTP real **4/4** (incluida autorización).
- La auditoría diferencial de Trivy pasó **solo en consistencia de evidencia**, con exit 2 por vulnerabilidades no resueltas.
- TDD focalizado `test_headless_pruning.py`: 4/4.

## Riesgos remanentes y límites
- La nueva imagen es **una capa experimental** sobre otras imágenes experimentales; aunque el filesystem final no instala X11/Cairo, **capas OCI inferiores pueden seguir conteniendo archivos históricos**. No se presenta como una imagen mínima limpia, ni se ha publicado OCI.
- `ldd` y los smokes no cubren todas las rutas con carga dinámica, integraciones o formatos maliciosos futuros. Se requieren pruebas adversarias, política de VEX y revisión humana antes de cualquier release.
- Los **60 HIGH / 19 UNKNOWN** persisten, con vulnerabilidades de componentes esenciales `util-linux`, ClamAV, Expat, libc y otros. La poda no modifica el gate central `audit_image.py`.
- Ningún dato institucional, recurso remoto Cloudflare, despliegue, gasto ni etiqueta operativa fue utilizado o modificado.

## Reproducción
```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_headless_pruning.py' -v
bash apps/inspector/build_headless_pruned_experiment.sh
bash apps/inspector/scan_headless_pruned_experiment.sh  # expected exit 2
```
