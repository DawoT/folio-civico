# ADR-010 · Validación real de ClamAV, qpdf, Poppler y OCR

**Fecha:** 2026-11-18 (America/Lima)  
**Estado:** **smoke real local aprobado (6/6, exit code 0)** con documentos exclusivamente sintéticos. **No desplegado, no integrado con Cloudflare Preview ni probado con expedientes institucionales.**

## Objetivo y alcance

Verificar con ejecutables auténticos, firmas oficiales de ClamAV y datos originales sintéticos el circuito del inspector definido en ADR-008/009. La validación local no sustituye las pruebas remotas con Container, Service Binding, Queue, DLQ, Access y MFA.

## Resultados reproducibles

El host compartido había rechazado correctamente la ejecución inicial por falta de almacenamiento (menos de 4 GiB libres). El 18-11-2026, el preflight detectó **114,67 GiB libres**, Docker local y **más de 46 GiB de RAM disponible**. Esto permitió ejecutar:

```sh
bash apps/inspector/validate_real_engines.sh
# Equivalente: pnpm test:inspector:docker
```

La primera compilación descargó la imagen base y dependencias Debian, ejecutó `freshclam` y construyó exclusivamente la imagen local `folio-civico-inspector:validation`. El primer smoke real falló en **OCR** porque los glifos pixelados originales no eran suficientemente reconocibles. No se alteró el umbral de aprobación ni se sustituyeron motores por mocks para corregirlo.

Se modificó `build_scanned_fixture()` para renderizar mediante **Poppler real** un PDF de texto sintético y convertir sus píxeles PGM en un segundo PDF que contiene **solo un XObject de imagen**, sin fuentes ni operadores PDF de texto. Antes de la inspección OCR se verifica además con `pdftotext` real que **no existe texto seleccionable** en ese nuevo PDF. Se conservó `scanned_pdf()` con glifos originales de la biblioteca estándar para los tests de contrato que no requieren motores reales.

Se reconstruyó la imagen y el smoke pasó repetidamente. Después se añadieron dos escenarios negativos auténticos: **PDF cifrado** generado con qpdf y **PDF con adjunto** generado con pdfattach. El smoke final verifica seis casos, incluida la ejecución reforzada que exige que el PDF escaneado no tenga capa de texto:

```json
{"checks":{"antivirus_test":"detected","embedded_file":"rejected","encrypted":"rejected","malformed":"rejected","native":"passed","ocr":"passed"},"ready":true}
```

**Código de salida verificado: 0.** Este objeto refleja un smoke sobre archivos sintéticos, no una evaluación de seguridad de un repositorio de PDFs reales.

| Verificación real | Criterio | Resultado |
| --- | --- | --- |
| PDF nativo | ClamAV + qpdf + Poppler conservan `EXPEDIENTE`, `OBRA`, `2026` | **PASÓ** |
| PDF escaneado sin capa de texto | `pdftotext` devuelve vacío y Tesseract recupera `OBRA`, `2026` | **PASÓ** |
| PDF con estructura truncada | Rechazado por inspector sin `clean` | **PASÓ** |
| PDF cifrado con qpdf | Rechazado sin declaración `clean` | **PASÓ** |
| PDF con adjunto creado por pdfattach | Rechazado sin declaración `clean` | **PASÓ** |
| EICAR inofensivo | ClamAV con firmas oficiales lo detecta (exit code 1) | **PASÓ** |

### Versiones y firmas observadas

Consultadas **dentro de la imagen local ejecutada sin red**:

| Motor / base | Versión observada |
| --- | --- |
| ClamAV | `1.4.6` |
| qpdf | `11.3.0` |
| Poppler (`pdfinfo`) | `22.12.0` |
| Tesseract | `5.3.0` |
| Firmas `daily.cvd` | 28187; descargada 2026-11-19 02:42:27 UTC |
| Firmas `main.cvd` | 63; descargada 2026-11-19 02:42:30 UTC |
| Firmas `bytecode.cvd` | 339; descargada 2026-11-19 02:42:34 UTC |

**Riesgo abierto:** durante `freshclam` se advirtió que ClamAV `1.4.6` está detrás de la versión recomendada `1.4.7`. La prueba funcional EICAR fue satisfactoria, pero antes del piloto se debe **actualizar/pinear una versión de ClamAV mantenida**, regenerar la imagen, verificar CVEs y actualizar continuamente las definiciones. La imagen contiene una fotografía de firmas; con el contenedor sin salida a Internet debe rotarse **antes de que la antigüedad supere 72 horas**. La antigüedad del archivo no certifica por sí misma su origen o cobertura.

## Protección de recursos y privacidad

`apps/inspector/preflight.py` comprueba al menos 8 GiB libres en repositorio y Docker, 4 GiB de RAM disponible, daemon local por socket Unix y contexto no remoto. Si falla, devuelve exit code 2 y un JSON de problemas sin intentar construir.

El script `validate_real_engines.sh` usa la imagen del propio proyecto, **sin borrar ni limpiar cachés/volúmenes de otros proyectos**. Ejecuta el smoke como usuario no privilegiado con:

- `--network none`, sin puertos publicados, secretos de servicio ni conexiones Cloudflare.
- Root filesystem de solo lectura, `--cap-drop ALL`, `no-new-privileges`, 64 procesos, 1 CPU, 4 GiB RAM sin swap adicional y `tmpfs` limitado a 256 MiB.
- Directorios temporales eliminados al terminar; los PDFs de prueba se generan dentro del contenedor y nunca se extraen expedientes de R2.
- Herramientas PDF con 30 segundos por invocación, 8 minutos totales por expediente y stdout capturado en archivo temporal privado, con límite de 2 MiB antes de cargarlo en memoria.

La construcción de imagen obtiene firmas oficiales durante el build; **solo el build** usa red. El contenedor que procesa los PDFs sintéticos no tiene red. La imagen local queda etiquetada `folio-civico-inspector:validation` y no es la imagen de un despliegue productivo.

## Pruebas de contrato

Los tests Python independientes comprueban la tabla xref, presencia de XObject de imagen, ausencia de fuentes y texto PDF, validación de dimensiones PGM, bloqueos del preflight, comportamiento EICAR incorrecto, límites de procesador y estados. **Esos tests unitarios usan dobles cuando corresponde**, por lo que deben distinguirse de los resultados del smoke Docker.

## Límites pendientes

1. **No existe despliegue Cloudflare** de Container, gateway, Queue, DLQ ni cron. Los originales que se suban a la aplicación siguen en cuarentena.
2. No hay pruebas de ClamAV sobre amenazas reales ni garantía de detección universal. EICAR comprueba únicamente el funcionamiento básico del motor y de las firmas.
3. El OCR real se probó con **una** página sintética legible; faltan pruebas con múltiples páginas, orientación, baja resolución, tablas, documentos heterogéneos y contraste, todas con datos ficticios y revisión humana.
4. **El rechazo de PDFs cifrados y con adjuntos ya se comprobó con motores reales.** Siguen pendientes construcciones complejas (acciones activas, JavaScript, formularios, fuentes, contenido remoto), políticas de respuesta ante falsos positivos y aislamiento de parsers bajo carga adversarial.
5. No existe derivado visual saneado ni visor de PDF descargable; la interfaz solo consulta texto previamente admitido bajo firma y autenticación.
6. Antes de Cloudflare Preview se requiere autorización explícita de recursos, costos, Access/MFA, protección de servicio, versión ClamAV soportada, rotación de firmas y controles de red.

**Referencias:** [ADR-008](ADR-008-isolated-inspector-queues.md), [ADR-009](ADR-009-private-container-gateway.md), [Checklist Preview](PREVIEW_CHECKLIST.md). Documentación oficial: [ClamAV Docker](https://docs.clamav.net/manual/Installing/Docker.html), [administración de firmas](https://docs.clamav.net/manual/Usage/SignatureManagement.html).
