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
| CVE-2026-124317 | **No corregido por 2.10.0** | UNKNOWN continúa bloqueando |
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

## Riesgos y siguientes gates
- **Gate oficial del inspector sigue BLOQUEADO.** El escaneo diagnóstico no genera un VEX, una atestación de corrección específica ni el CycloneDX requerido por el gate formal. No incorporar esta imagen a `apps/inspector-gateway`.
- La imagen es un **prototipo en capas** sobre Poppler, no una imagen multi-stage limpia de release; el paquete es una reconstrucción local no incluida en los repositorios estables de Trixie.
- Para atribuir cada CVE como corregido/no alcanzable se requieren prueba adversaria, revisión de código, hashes de ELF, inventario completo y decisión VEX con responsable/vigencia. Faltan CVE de Poppler, Expat restantes y otros 70/19 hallazgos.
- No se realizaron despliegues, mutaciones de D1/R2/Queues, OCR institucional, gastos Cloudflare ni intervención en otros worktrees.

## Repetición
```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_expat_prototype.py' -v
bash apps/inspector/build_expat_experiment.sh
bash apps/inspector/scan_expat_experiment.sh  # exit 2: bloqueo esperado
```
