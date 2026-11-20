# Seguridad R1.25 · Pruebas adversarias acotadas de Expat 2.10.0

**Corte:** 2026-11-19 (America/Lima), rama `security/expat-regression-r125`, sobre `security/nonprivileged-r124`. **Investigación local, NO VEX, NO RELEASE, sin despliegue, sin cambios en el gate oficial.**

## Hallazgo prioritario

Trivy sigue asignando a `libexpat1 2.10.0-1+folio1` cuatro HIGH y dos UNKNOWN. Además, registra un MEDIUM que no debe pasar inadvertido:

| CVE | Trivy | Declaración de Expat upstream | Evidencia R1.25 |
| --- | --- | --- | --- |
| `CVE-2026-113351` | HIGH | Corregido en 2.10.0, PR #1431 (`XML_ParserReset`) | Parser reutilizado con un documento acotado, pasa |
| `CVE-2026-115506` | HIGH | Corregido en 2.10.0, PR #1433 y #1439 (amplificación) | Rechazo de expansión de entidades con límite muy bajo, error 43, pasa |
| `CVE-2026-117610` | HIGH | Corregido en 2.10.0, PR #1444 (subparser vacío no final) | Subparser externo con dos llamadas de longitud cero, pasa |
| `CVE-2026-118370` | HIGH | Corregido en 2.10.0, PR #1450 (`storeAtts`) | **Sin reproducción**: prueba real requiere más de 2^30 atributos y varios GB |
| `CVE-2026-124317` | UNKNOWN | No corregido en release 2.10.0; PR #1492 incorporado en R1.19 | CTest nativo del build anterior; sin prueba nueva de explotación con ASan |
| `CVE-2026-128241` | UNKNOWN | `xmlwf` symlink handling, herramienta ausente | La ausencia se comprueba físicamente, no se emite VEX |
| `CVE-2025-66382` | MEDIUM | Sin corrección upstream confirmada al corte | **Abierto**, sin pretensión de cobertura |

**Fuentes oficiales:** [changelog Expat 2.10.0](https://fuchsia.googlesource.com/third_party/expat/+/refs/heads/upstream/prepare-release/expat/Changes), [Debian CVE-2026-115506](https://security-tracker.debian.org/tracker/CVE-2026-115506) (2.10.0-1 figura corregida), [correcciones y prerequisitos Debian en bug #1152337](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1152337) y [Expat 2.10.0](https://www.xml.com/news/2026-11-expat-2100/). El estado del release `2.10.0` según upstream no sustituye la auditoría del binario personalizado.

La fuente incorporada en R1.18 se fijó a `expat_2.10.0.orig.tar.gz` SHA-256 `b3644a12f62d7762b62c444f69d169ba0234f13138d0240244bca64cbe35286f`; el backport #1492 SHA-256 `0263891b16fd918e30f5116ff1cf33e757974a87ffc2c48667b06c98a85e46f3`. Estos valores y el ELF están cruzados con la evidencia del runtime, pero no constituyen reproducibilidad bit a bit.

## Implementación TDD, sin mutaciones del runtime

Se añadieron únicamente `apps/inspector/expat_cve_regression.py`, `apps/inspector/scan_expat_cve_regression.sh`, `apps/inspector/tests/test_expat_cve_regression.py` y este dossier.

1. **Red**: tests inexistentes para el nuevo módulo y fallos deliberados ante inconsistencias de identidad, CVE, SBOM o resultado de las pruebas. Una ejecución real reveló un caso omitido en el prototipo: `CVE-2025-66382` MEDIUM en Expat. Se añadió al contrato y se exigió expresamente su permanencia.
2. **Green**: el script de validación ejecuta `Trivy JSON`, `CycloneDX`, `expat_runtime_inventory.py` y tres pruebas en la **misma imagen inmutable**. Las dos invocaciones nativas utilizan el digest local, `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, UID predeterminado 65534, CPU 1, memoria 4 GiB y un presupuesto de 15 s medido dentro del lote de pruebas y un timeout externo de 60 s por contenedor, para evitar que un parser bloqueado retenga indefinidamente el proceso.
3. Los casos XML están limitados a **100 000 bytes por entrada**; no envían billion laughs sin límites ni generan documentos multigigabyte. Un parse de amplificación con restricciones deliberadamente bajas debe devolver `XML_ERROR_AMPLIFICATION_LIMIT_BREACH`, no simplemente fallar por otra causa.
4. El comparador verifica correspondencia exacta entre versión del paquete, `XML_ExpatVersion`, biblioteca `libexpat.so.1` cargada, SHA-256 real, Expat/CycloneDX, digest de imagen y siete avisos Trivy. Si alguno desaparece o cambia, el comparador **falla cerrando con exit 3**. No se autoriza a reetiquetar casos como `not_affected`.
5. Un informe coherente **siempre devuelve exit 2 / blocked**, incluso si tres pruebas pasan. No se crea VEX, suppressions, excepción de seguridad o vía alternativa de release.

## Evidencia real

- Imagen local sin cambios: `folio-civico-inspector:nonprivileged-experiment`, ID Docker `sha256:e79cf1ad4dc960cf892d1bb267297f3ce8563abf4ee7749753aa4e8338626d4e`.
- Biblioteca Expat efectivamente cargada: SHA-256 `4bea107cfb1ec4dcbe2bc0062967cd8ee1df80f830da203dc60b477bc8beecef`; el inventario existente confirma cinco binarios Poppler enlazados a esa misma biblioteca y `xmlwf` ausente.
- Pruebas: `XML_ParserReset` aprobado, umbral de amplificación aprobado con código de error 43, subparser no-final/final aprobado.
- Conteo Trivy sin variación: **0 CRITICAL, 59 HIGH, 19 UNKNOWN**. De ellos Expat sigue registrando **4 HIGH + 2 UNKNOWN + 1 MEDIUM**. Script `scan_expat_cve_regression.sh`: **exit 2**.
- Test adversarial de atributos masivos: **no ejecutado**; no se puede asumir que una prueba pequeña reproduce su desbordamiento original. El CTest upstream del build Expat previo y el changelog son evidencia de procedencia y pruebas nativas, no prueba formal por CVE.

## Pendiente antes de evaluar la autorización

- Trazar el contenido exacto del paquete binario `2.10.0-1+folio1` a una reconstrucción reproducible o atestada de Expat con pruebas instrumentadas, incluidos los parches del release y #1492.
- Evaluación formal por propietario de seguridad de la aplicabilidad de los siete avisos de Expat; resolver el MEDIUM `CVE-2025-66382` por separado.
- Corregir/examinar el resto de los **59 HIGH / 19 UNKNOWN** y los 24 avisos seleccionados nativos sin cobertura equivalente a Trivy.
- La imagen experimental no se promoverá a Preview ni producción sin gate original superado y aprobación expresa.

## Reproducir

```sh
python3 -m unittest discover -s apps/inspector/tests -p 'test_expat_cve_regression.py' -v
bash apps/inspector/scan_expat_cve_regression.sh  # exit 2 esperado
sh scripts/ci.sh
```
