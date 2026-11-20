# R1.18 · Experimento local de reconstrucción de Expat 2.10.0

**Fecha de corte:** 2026-11-19 (America/Lima). **NO AUTORIZA** Preview, producción, despliegue de Container, cambio de etiquetas operativas, VEX ni tratamiento de expedientes reales.

## Problema comprobado
El runtime experimental Poppler partía de `libexpat1 2.9.0-1~deb13u1`, para el cual Debian Trixie registraba 4 avisos HIGH y 2 UNKNOWN. Debian aceptó Expat **2.10.0-1** en `unstable` el 2026-11-02 y documentó correcciones para cuatro de esos CVE. La versión de Trixie seguía siendo vulnerable según su tracker. Por eso **no se ha incorporado ningún repositorio sid/unstable al runtime**, ni se han aceptado paquetes binarios externos.

Fuente oficial de hashes y correcciones: https://tracker.debian.org/news/1818607/accepted-expat-2100-1-source-into-unstable/

| Fuente Debian | SHA-256 fijado |
| --- | --- |
| `expat_2.10.0-1.dsc` | `8c4623c101959b8709a3f0a10c06a40d413dc7a6f5ffad3bc9d0cd010d850956` |
| `expat_2.10.0.orig.tar.gz` | `b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f` |
| `expat_2.10.0-1.debian.tar.xz` | `9be65c3ff79ca0508590970422de0a55f117bb7134a0274dd1ed3261f85631dc` |

Los hashes están publicados en un anuncio firmado por Debian, pero el prototipo no implementa **una verificación GPG independiente del anuncio**. No se puede afirmar que el build sea reproducible bit a bit; hacen falta comprobaciones adicionales.

## TDD e implementación
Se creó `security/expat-prototype-r118` sobre `origin/main` en un worktree independiente, sin modificar el trabajo Poppler R1.17 en curso.

1. **Red:** tres tests iniciales fallaron porque no existían los artefactos de investigación. El control del empaquetado volvió a fallar al exigir el `.dsc`, los hashes de la pila Debian y el paquete instalado.
2. **Green:** `Dockerfile.expat-experiment` verifica los tres hashes, extrae el `.dsc` exacto con `dpkg-source`, ejecuta CMake/CTest y **reconstruye `libexpat1_2.10.0-1_amd64.deb` desde fuente** con toolchain Trixie.
3. Instala ese paquete en una imagen nueva `folio-civico-inspector:expat-experiment`, heredada de **Poppler experimental**, sin alterar `validation`, `ocr-integrated` ni `poppler-experiment`. `dpkg-query`, `ctypes.XML_ExpatVersion` y `ldd` comprueban versión real y enlaces PDF.
4. `build_expat_experiment.sh` limita la ejecución a Docker local, sin red/privilegios/montajes en los smokes, y nunca publica ni despliega.
5. `scan_expat_experiment.sh` ejecuta Trivy local sin suppressions y produce exclusivamente diagnóstico; **siempre retorna exit 2** al escanear correctamente, por mantener bloqueado el release gate. El parser rechaza objetivos o versiones inconsistentes.

## Hallazgos frente a upstream
| CVE | Publicación Expat 2.10.0 | Situación para Folio Cívico |
| --- | --- | --- |
| CVE-2026-113351 | Corrección anunciada | Falta PoC/evaluación VEX individual |
| CVE-2026-115506 | Corrección anunciada | Falta PoC/evaluación VEX individual |
| CVE-2026-117610 | Corrección anunciada | Falta PoC/evaluación VEX individual |
| CVE-2026-118370 | Corrección anunciada | Falta PoC/evaluación VEX individual |
| CVE-2026-124317 | **No corregido por 2.10.0 sin backport** | Parche #1492 incorporado en R1.19 local; UNKNOWN continúa bloqueando sin VEX |
| CVE-2026-128241 | **No corregido por 2.10.0** | UNKNOWN, `xmlwf` no presente; sin VEX |

**No asumir** que desaparece un CVE por no aparecer en una ruta dinámica; el parser puede ser indirectamente alcanzable, y Trivy Trixie no reconoce automáticamente las correcciones de la rama `unstable`.

## Evidencia efectivamente ejecutada
- Pruebas del inspector: **168/168 Python**; pruebas focalizadas de Expat **6/6**.
- CTest del Expat fuente: **1/1 suite** aprobada. Build de paquete Debian y `dpkg -i` completados con exit 0.
- Versión `dpkg-query -W libexpat1`: **2.10.0-1** dentro de imagen experimental.
- Versión `XML_ExpatVersion`: **expat_2.10.0**. `pdfinfo`, `pdftotext` y `pdftoppm` resuelven la `libexpat.so.1` del paquete reconstruido.
- Smokes de motor real: **6/6**; HTTP: **4/4**, sin red en el contenedor.
- **Trivy sobre nueva imagen:** 0 CRITICAL, **70 HIGH, 19 UNKNOWN**; sigue atribuyendo **4 HIGH y 2 UNKNOWN** a `libexpat1 2.10.0-1`. Comando diagnóstico **exit 2 (blocked)**, no es el gate completo SBOM.
- `sh scripts/ci.sh` **exit 0 tras la reconstrucción de paquete y la ampliación de tests**: Vitest, 168 pruebas Python, TypeScript, compilación y dry-runs de Workers, 81 pruebas Chromium y migraciones D1 locales. Esta CI no sustituye el gate CVE independiente.

## R1.19 · Backport upstream CVE-2026-124317 (incremento posterior)

**Objetivo:** corregir un camino de sobrelectura real sin esperar un binario Debian Trixie y sin suprimir diagnósticos ni tocar las imágenes de referencia.

**Procedencia del código:** [libexpat PR #1492](https://github.com/libexpat/libexpat/pull/1492), merge upstream del 2026-11-07 (tres commits `bf26290`, `3d77567`, `0507597`). Archivo congelado en `apps/inspector/research_patches/expat-pr1492.patch`, SHA-256:

```text
0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3
```

- Docker verifica digest, aplica con `patch --batch --fuzz=0 -p1` y exige la prueba upstream `test_misc_unknown_encoding_no_source_overread`. La aplicación no utilizó *fuzz*; se observó un desplazamiento de contexto de 29 líneas en el hunk de registro de la prueba.
- **Compatibilidad fuente (detectada en Red):** la prueba de Expat master emplea `XML_GetBuffer64`, ausente en 2.10.0. Se adaptó solo la llamada de prueba a `XML_GetBuffer(parser, (int)docLen)` con comprobaciones exactas antes y después; el cuerpo de la corrección `xmltok.c` **no se alteró**.
- El paquete reconstruido se identifica como `libexpat1 2.10.0-1+folio1` para distinguir claramente el backport local del `2.10.0-1` oficial de Debian. La procedencia en la imagen incluye fuente y hash del parche.
- `xmlwf` (vector de **CVE-2026-128241**) no se compila en la suite CMake de esta imagen y se verifica su ausencia del runtime. Esa observación **no** representa una revisión VEX ni prueba la ausencia de todos los riesgos asociados a la biblioteca.
- TDD: dos tests nuevos primero fallaron (faltaban parche, aplicación y prohibición de `xmlwf`); posteriormente **8/8 tests focalizados** pasaron.
- Imagen reconstruida localmente: build `exit 0`, CTest nativo con el test upstream incorporado, **6/6** smokes de antivirus/PDF/OCR y **4/4** de HTTP. Imagen local experimental ID `sha256:221078247d17f98ab0981c3808ddfe7da65db8e5d9a99b5f5bc3431e5276f4d7` (no digest de registro).
- Trivy de la imagen reconstruida: **0 CRITICAL, 70 HIGH, 19 UNKNOWN**, de los cuales `libexpat1 2.10.0-1+folio1` sigue contribuyendo **4 HIGH + 2 UNKNOWN**. Diagnóstico `exit 2` **bloqueado**; no sustituye la auditoría oficial ni genera CycloneDX/VEX. Las cifras reflejan la base del scanner, no una prueba de que el parche no funcione.

**Por resolver:** evidencia independiente de procedencia y firma, evaluación específica de los seis CVE de Expat sobre el código reconstruido, pruebas adversarias adicionales para UTF-16 y XML, SBOM exhaustivo y análisis del resto de hallazgos. La corrección upstream de `CVE-2026-128241` existe en [PR #1502](https://github.com/libexpat/libexpat/pull/1502), pero su herramienta `xmlwf` no forma parte del runtime; no se incorporó ese parche ni se emitió VEX.

## R1.20 · Reconciliación de evidencia CycloneDX y ELF nativo

**Objetivo:** impedir que un escaneo experimental de Trivy se considere válido cuando el SBOM, la identidad del contenedor, el paquete nativo, el binario ELF o los parches fuente no coinciden. Esta etapa **NO AUTORIZA** liberación.

**Implementación:**
- `scan_expat_experiment.sh` obtiene un informe Trivy JSON de CVE y un SBOM **CycloneDX 1.7** de la **misma etiqueta**. El digest inmutable Docker se comprueba antes y después; los inventarios se generan dentro del **mismo ID de imagen**, sin red, montajes, puertos ni privilegios.
- `source_inventory.py`, **reutilizado** sin modificar su política, mide las bibliotecas y binarios nativos de Tesseract/Poppler, además del conjunto de modelos OCR. Se valida con la política existente y se reconcilia con el ledger seleccionado de **24 CVE**; esto no implica que sea exhaustivo.
- `expat_runtime_inventory.py` compara el paquete `libexpat1 2.10.0-1+folio1` con los metadatos esperados de la fuente y del parche; calcula el SHA-256 **del ELF instalado**, comprueba `XML_ExpatVersion`, los enlaces dinámicos de **cinco** herramientas Poppler y la ausencia del ejecutable `xmlwf`.
- `expat_evidence.py` rechaza el SBOM vacío, imagen ajena, digest inconsistente, bibliotecas o metadatos falsificados, versión contradictoria del paquete, anomalías del inventario nativo y casos de cobertura incompleta. Su código 0 indica **únicamente consistencia de evidencia**. El proceso total ejecuta después `expat_prototype_scan.py`, que **siempre devuelve código 2 (blocked)** ante un escaneo válido y nunca produce autorización.
- Ninguna lista de ignorados, clasificación VEX automática ni cambio al gate oficial `audit_image.py`.

**Evidencia real de la imagen `folio-civico-inspector:expat-experiment`:**

| Comprobación | Resultado |
| --- | --- |
| Imagen Docker local | `sha256:221078247d17f98ab0981c3808ddfe7da65db8e5d9a99b5f5bc3431e5276f4d7` |
| CycloneDX | 159 componentes, un `libexpat1 2.10.0-1+folio1` consistente |
| SHA-256 de `libexpat.so.1` instalada | `4bea107cfb1ec4dcbe2bc0062967cd8ee1df80f830da203dc60b477bc8beecef` |
| SHA-256 del parche | `0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3` |
| Componentes fuente sin CVE assessment completo | **3**: Expat, Poppler y Tesseract |
| Ledger de investigación nativa existente | **24** CVE seleccionados de Poppler y Tesseract; no incluye todos los CVE |
| CVE del escáner | **0 CRITICAL / 70 HIGH / 19 UNKNOWN**, incluyendo 4 HIGH + 2 UNKNOWN atribuidos a Expat |
| Resultado combinado | Integridad de evidencia válida; **exit 2 / release bloqueado** |

TDD: las pruebas de R1.20 empezaron con **importación fallida** al faltar los validadores; luego se comprobaron casos sintéticos corruptos de versión, SHA, digest, SBOM, herramientas y `xmlwf`. Una discrepancia real en la ausencia de `xmlwf` fue detectada durante el escaneo: Debian `dash` devuelve **127** (además del estado 1 aceptable) para `command -v xmlwf`; se admiten solo 1/127 **sin salida ni error**, con comprobación de rutas del ejecutable.

**Limitaciones explícitas:** CycloneDX no cubre automáticamente todos los CVE de componentes compilados desde fuente; los hashes identifican el binario, pero **no equivalen a atestación firmada del build, prueba de reproducibilidad, VEX ni aprobación institucional**. Es necesario clasificar los 70 HIGH y 19 UNKNOWN con evidencia específica y controles independientes. El experimento sigue heredando una imagen Poppler no desplegable.

## Riesgos y siguientes gates
- **Gate oficial del inspector sigue BLOQUEADO.** R1.20 sí produce un CycloneDX reconciliado, pero no genera un VEX aprobado, una atestación independiente del build ni la evaluación CVE completa que exige el gate formal. No incorporar esta imagen a `apps/inspector-gateway`.
- La imagen es un **prototipo en capas** sobre Poppler, no una imagen multi-stage limpia de release; el paquete es una reconstrucción local no incluida en los repositorios estables de Trixie.
- Para atribuir cada CVE como corregido/no alcanzable se requieren prueba adversaria, revisión de código, hashes de ELF, inventario completo y decisión VEX con responsable/vigencia. Faltan CVE de Poppler, Expat restantes y otros 70/19 hallazgos.
- No se realizaron despliegues, mutaciones de D1/R2/Queues, OCR institucional, gastos Cloudflare ni intervención en otros worktrees.

## Repetición
```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_expat_prototype.py' -v
bash apps/inspector/build_expat_experiment.sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_expat_evidence.py' -v
bash apps/inspector/scan_expat_experiment.sh  # evidencia verificada; exit 2: bloqueo esperado
```
