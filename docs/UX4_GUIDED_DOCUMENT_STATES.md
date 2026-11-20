# UX-4.4 — Estados guiados del listado y continuidad de la tarea

**Fecha:** noviembre de 2026. **Ámbito:** mesa documental de Folio Cívico.  
**Tipo de evidencia:** inspección de código y escenarios sintéticos reproducibles, **sin entrevistas ni sesiones con personal municipal**.

## Problema y riesgo

El listado previo mezclaba dos resultados materialmente distintos:

- Una **consulta autorizada y exitosa con 0 documentos**.
- Una **consulta fallida** (por ejemplo, 503 o credenciales no disponibles) que ponía `documents=[]` y activaba el mensaje «No hay documentos disponibles para este lote».

Ese falso vacío podía inducir a una persona a concluir que un expediente realmente no existe. El resumen de comisión ya diferenciaba «No disponible», creando una contradicción. Adicionalmente, la cabecera marcaba cero documentos durante fallos, la vista de evidencia invitaba a seleccionar un archivo inexistente, y una transición de lote podía conservar temporalmente el detalle de un lote anterior.

**Decisión:** nunca afirmar ausencia documental sin una respuesta válida del listado del lote actualmente autorizado.

## Resultado de UX

`DocumentListState` expresa cuatro estados excluyentes y una acción contextual:

| Estado | Mensaje principal | Acción y criterio |
| --- | --- | --- |
| Sin lote seleccionado | «Primero selecciona un lote» | Enlace de salto al selector de comisión; sin afirmar resultados |
| Consultando | «Consultando documentos…» | Estado anunciado, sin mostrar un cero incorrecto |
| Consulta fallida | «Listado no disponible» | Explica que fallo no equivale a lote vacío y ofrece **Reintentar consulta**, que vuelve a llamar al endpoint existente |
| Consulta correcta con 0 archivos | «Lote sin documentos registrados» | Quien tiene permiso puede seleccionar un PDF para registrar; observadores y roles sin carga reciben orientación de solo consulta |

Se reemplaza el número de cabecera por un guion con etiqueta accesible **«Cantidad de documentos no disponible»** mientras la lista no tiene una respuesta vigente, y se muestra el cero solo tras una consulta exitosa.

La zona de evidencia refleja los estados «Primero abre un lote», «Consultando evidencia» y «Evidencia no disponible» cuando corresponda; no invita a abrir un documento que no fue recuperado. La clave de alcance `commissionId:batchId` se compara con la carga vigente para evitar mostrar detalles de otro lote en transiciones asíncronas. La lista y detalle solo se consideran actuales cuando coinciden el alcance abierto, la respuesta y el estado sin error.

## Ingeniería, seguridad y controles de calidad

- Solo frontend y pruebas; endpoints existentes y autorizaciones Worker permanecen iguales. Reintentar no desactiva el control de roles ni convierte un 403/503 en «sin documentos».
- No se introduce almacenamiento persistente, reintentos automáticos, temporizadores ni peticiones adicionales para el resumen.
- Las acciones HTML son nativas: links a `#scope-commission` y `#upload-pdf`, botón de reintento; foco de teclado comprobado en navegador.
- Los estados están expuestos mediante un grupo nombrado, encabezado semántico, texto y señales de carga; no solo colores/iconos.
- La plantilla mantiene el mensaje explícito de cuarentena y no muestra ni abre los PDFs originales.

### TDD

1. **Red:** el nuevo contrato `DocumentListState.test.tsx` falló porque el componente no existía.
2. **Green:** cuatro contratos unitarios de estado, copia, rol y acciones, con TypeScript aprobado.
3. **Playwright/axe:** cuatro flujos por viewport (escritorio 1366, Pixel 7 y reflujo 320):
   - Antes de abrir lote: guía y salto enfocable a selección.
   - Lote vacío real: acción de carga solo a autor; observador sin acción habilitada.
   - Error 503: resumen «No disponible», cabecera sin cero engañoso, bloque de error con reintento; al recuperarse el servicio vuelve a mostrar archivo y metadatos reales.
   - Cambio de lote con respuesta demorada: no aparece detalle del lote anterior antes de que llegue la nueva respuesta.
4. **Gate obligatorio:** `FOLIO_E2E_PORT=<puerto> sh scripts/ci.sh` en worktree sincronizado con `origin/main`, incluyendo Vitest, Python inspector, workerd, typecheck, Vite, Chromium/axe y migraciones D1 locales. Sin usar GitHub Actions como control de aprobación.

## Evaluación de usabilidad pendiente con personas reales

La corrección está sustentada en pruebas de invariantes y recorridos sintéticos; no es evidencia de que personal de transferencia comprenda óptimamente la interfaz. Protocolo de estudio sugerido, sin inventar resultados:

- **Personas**: presidencia, miembro que registra PDF, revisor independiente y observador; utilizar sujetos y expedientes ficticios.
- **Tareas**: abrir lote, distinguir un lote vacío de un servicio fallido, recuperar la consulta, identificar cuarentena y localizar el siguiente paso autorizado.
- **Métricas**: tasa de éxito sin asistencia, primer clic correcto, errores de atribución («no existe» versus «no se pudo consultar»), tiempo por tarea y confianza declarada en la interpretación del estado.
- **Criterios antes de piloto**: ninguna persona debe interpretar un error inducido como evidencia de ausencia documental; navegación por teclado completa; registro explícito de toda confusión o acción inválida, con severidad y seguimiento.
- **Registro**: fecha, rol, versión, entorno de pruebas, tarea, resultado observado, incidentes y recomendaciones. No sustituir este registro por resultados de tests.

### Próximo paso

Con el flujo de documentos estabilizado, la investigación humana puede orientar un UX-4.5 o UX-5 centrado en navegación entre tareas, calidad de comprensión y pruebas NVDA/VoiceOver. Las validaciones de accesibilidad manual de UX-4.3 siguen abiertas.

**No hay despliegue remoto.** Las mejoras de frontend y el CI local no acreditan seguridad de inspector ni habilitan acceso a expedientes reales.
