# UX-5.2 — Registro local de pruebas moderadas y métricas verificables

**Folio Cívico · Fecha de preparación: 19 de noviembre de 2026.**

**Estado del proyecto:** instrumental de investigación preparado; **0 sesiones humanas ejecutadas por este incremento**. No confundir disponibilidad del protocolo con validación del piloto.

## Objetivo y límites

En UX-5.1 se automatizaron siete tareas encadenadas usando identidades y expedientes sintéticos, más regresión visual. UX-5.2 prepara la observación de **personas autorizadas reales** sin afirmar que sus resultados ya existen. **UX-5.3 calibra esas tareas por perfil para que el reporte no mezcle responsabilidades incompatibles.** No se usa este instrumental para aprobar Cloudflare Preview, producción, el inspector, una aprobación institucional o una auditoría WCAG.

El contrato y el cálculo están implementados en `scripts/ux5_study.py`. Utilizan únicamente Python 3 estándar. No envían información por red, no escriben datos de sesión automáticamente y no forman parte de la aplicación web. **Desde UX-5.4, `summarize` genera por defecto un estado de divulgación reducida, no un agregado con recuentos.** Las métricas detalladas requieren `--internal` para un uso local restringido y no se consideran publicables automáticamente.

## Protocolo moderado y consentimiento

Una persona responsable debe confirmar, antes de usar el instrumento, que:

1. Existe consentimiento informado explícito y adecuado al contexto, indicando la finalidad, la forma de uso y la conservación de datos.
2. La prueba se realiza exclusivamente en una **instancia local con comisiones, identidades y expedientes sintéticos**. Nunca se piden credenciales, correos personales o PDFs de la municipalidad.
3. Se usa un único archivo por sesión, guardado fuera del control de versiones, bajo `.ux5-study/sessions/` (ignorado por Git). No incluir nombres, identificadores, correos, archivos reales, URL personales, voz, video, capturas ni notas libres.
4. Los datos numéricos son observaciones **humanas realmente registradas**, no cronometrajes de Playwright. El campo `moderated_observation: true` es una declaración del operador, no una verificación técnica independiente.
5. Los defectos que requieren descripción se registran en un canal restringido y autorizado, con referencias a issues desprovistas de información personal; **no se incorporan al JSON de resumen**.

**Perfiles disponibles:** `president`, `author`, `reviewer`, `observer`. Idealmente reclutar 5–8 participantes autorizados distribuidos entre los roles; el tamaño no da precisión estadística representativa del universo municipal.

**Matriz de tareas asignadas (UX-5.3):**

| Perfil moderado | Tareas evaluables | Tareas de otros perfiles |
| --- | --- | --- |
| Presidencia (`president`) | `scope_opened` | `not_attempted` |
| Autor (`author`) | `scope_opened`, `pdf_quarantined`, `draft_registered`, `submitted_for_review` | `not_attempted` |
| Revisor independiente (`reviewer`) | `scope_opened`, `independent_decision` | `not_attempted` |
| Observador (`observer`) | `scope_opened`, `observer_read_only`, `sha256_export_verified` | `not_attempted` |

Esta matriz corresponde **a las tareas de investigación moderada del piloto UX-5.1**, no redefine permisos de Cloudflare Access ni afirma que una persona con otro rol no pueda realizar una acción legítima en la aplicación. En el estudio, una tarea no asignada al perfil **no es un fallo** y tampoco puede reportarse como completada: permanece `not_attempted`. De ese modo, la tasa de éxito de una tarea se calcula solo con intentos de personas a quienes se asignó.

**Compatibilidad de registros:** la versión del protocolo pasa a `ux5.3-v1`. Los archivos `ux5.2-v1` anteriores no se convierten automáticamente; deben revisarse y, si representan observaciones reales autorizadas, verificarse manualmente frente a esta matriz antes de decidir si corresponde recrearlos. No reemplazar el campo de versión sin revisar la evidencia original. El cambio no afirma que exista alguna sesión humana previa.

## Uso local

Desde la raíz del repositorio:

```sh
# El script crea .ux5-study/ y sessions/ de forma privada si no existen.

# Crear una plantilla incompleta, sin consentimiento ni resultados,
# preconfigurada para un perfil del estudio. Otros perfiles: president,
# reviewer, observer. Sin --role conserva role=null.
python3 scripts/ux5_study.py template --role author --output .ux5-study/sessions/session-01.json

# Completar el JSON únicamente después de la sesión moderada real.
# Validar estructura y restricciones antes de aceptar el registro.
python3 scripts/ux5_study.py validate .ux5-study/sessions/session-01.json

# Obtener estado de cobertura con divulgación reducida. NO equivale a anonimización.
python3 scripts/ux5_study.py summarize --output .ux5-study/coverage.json .ux5-study/sessions/*.json

# Solo para revisión interna autorizada: incluye recuentos exactos y métricas
# de cohortes pequeñas; mantenerlo local, restringido y fuera de Git.
python3 scripts/ux5_study.py summarize --internal --output .ux5-study/internal-aggregate.json .ux5-study/sessions/*.json

# Ejecutar los contratos de privacidad y agregación.
python3 -m unittest discover -s tests -p test_ux5_study.py

# Gate completo de integración (sin GitHub Actions).
sh scripts/ci.sh
```

**UX-5.5 — Archivos privados por defecto.** Los comandos con `--output` crean archivos JSON nuevos con permisos **0600** y directorios privados con **0700** (en entornos POSIX). Solo se admiten rutas bajo `.ux5-study/` o `.ux5-study/sessions/`; se rechazan enlaces simbólicos, rutas que escapan del directorio, directorios ya existentes accesibles para otros usuarios y sobrescrituras accidentales. **No crean copias de respaldo ni archivos de registros reales.** Los nombres deben ser distintos para cada sesión o resumen; si el destino existe, el comando falla sin modificarlo. Si un `.ux5-study/` anterior fue creado con `mkdir -p` y permisos 0755, **revisar sus permisos y los de cada archivo antes de continuar** y corregirlos manualmente de forma controlada, por ejemplo `chmod 700 .ux5-study .ux5-study/sessions` y `chmod 600 .ux5-study/sessions/*.json`, solo después de confirmar que se trata de los directorios y archivos correctos. `--internal` **requiere** `--output`; se ha eliminado su salida JSON detallada a la consola para evitar divulgación accidental en logs o tuberías.

**No enviar** `.ux5-study/` a GitHub, plataformas de analítica ni servicios externos. La carpeta está ignorada. Controlar su acceso y eliminar los archivos individuales conforme al consentimiento, la política institucional y las obligaciones locales aplicables. Ignorar archivos en Git y establecer permisos POSIX **no equivale** a cifrar ni garantizar retención segura; proteger además el equipo y sus copias de seguridad. Evitar redirigir la salida `template` a un archivo con `>`, porque podría crearse con permisos demasiado amplios; preferir siempre `--output`.

### Esquema único de registro

Todos los campos son obligatorios; **ningún campo adicional es aceptado**. El formulario comienza inválido hasta que se confirme consentimiento, observación moderada y uno de los roles autorizados. La sesión solo es registrable si al menos una tarea realmente se intentó.

```json
{
  "schema_version": 1,
  "study_version": "ux5.3-v1",
  "role": "author",
  "consent_obtained": true,
  "moderated_observation": true,
  "synthetic_environment": true,
  "tasks": [
    {
      "id": "scope_opened",
      "outcome": "completed_unassisted",
      "duration_seconds": 85,
      "navigation_errors": 0,
      "interpretation": "correct",
      "incident_codes": []
    }
  ]
}
```

El ejemplo muestra **solo un registro de tarea** por brevedad. Un archivo válido exige las **siete tareas** en el orden del contrato UX-5.1; las no realizadas **o no asignadas a ese perfil** usan `outcome: "not_attempted"`, `duration_seconds: null`, `navigation_errors: null`, `interpretation: "not_evaluated"` y `incident_codes: []`. El ejemplo no representa una sesión realizada.

Los IDs de tarea corresponden, en orden, a: `scope_opened`, `pdf_quarantined`, `draft_registered`, `submitted_for_review`, `independent_decision`, `observer_read_only` y `sha256_export_verified`.

**Resultados:** `completed_unassisted`, `completed_assisted`, `failed`, `not_attempted`. Las tareas intentadas requieren una duración en segundos enteros (1–7200) y un número entero de errores de navegación (0–100). `interpretation` puede ser `correct`, `incorrect` o `not_evaluated` cuando la comprensión no fue evaluada explícitamente.

**Categorías fijas de incidentes:** `unavailable_as_absent`, `quarantine_as_reviewed`, `internal_validation_as_official`, `sha256_as_signature`, `keyboard_blocker`, `other_blocker`. No se aceptan anotaciones arbitrarias, identidades ni rutas a grabaciones.

La validación es **fail-closed**: rechaza campos desconocidos, JSON con claves duplicadas, valores no tipados o fuera de rango, tareas repetidas, consentimientos pendientes, entornos no sintéticos y archivos mayores de 64 KiB. Un archivo puede ser estructuralmente válido aunque la declaración del operador sea falsa: el código **no puede certificar presencia humana ni consentimiento genuino**.

## Agregación y criterios de interpretación

**Por defecto**, `summarize` emite únicamente `schema_version`, `study_status`, `task_coverage`, `authorization`, `manual_accessibility` y `disclosure`. Si hay menos de cinco sesiones totales, `task_coverage="not_released"`; con al menos cinco sesiones muestra exclusivamente `minimum_met` o `below_minimum` por tarea, **sin recuentos ni éxitos/fallos concretos**. `authorization="not_granted"`, `manual_accessibility="not_verified"` y `disclosure="requires_human_review"` se conservan siempre.

**Este estado reducido NO garantiza anonimización ni autorización para publicar.** Comparar reportes de fechas distintas, combinar fuentes externas o evaluar grupos muy pequeños puede revelar patrones de participación incluso sin cifras. Se exige una revisión humana de privacidad y autorización antes de compartirlo externamente.

**Solo con `--internal --output .ux5-study/<archivo-nuevo>.json`**, `summarize` guarda en disco: versión del protocolo, procedencia declarada, número total de sesiones, contadores por tarea y categoría de incidente, métricas agregadas con denominador explícito y estado de gates. Este reporte **contiene información potencialmente identificable por inferencia en cohortes pequeñas** y se mantiene en un entorno local restringido. Se excluyen fichas individuales, nombres, rol por persona, tiempos por persona, archivos, hashes y texto. El operador recibe una advertencia por `stderr` al usar `--internal`.

| Métrica | Definición |
| --- | --- |
| Intentos por tarea | Sesiones con `outcome` distinto de `not_attempted` |
| Finalización autónoma | Recuento de `completed_unassisted` |
| Finalización con ayuda | Recuento de `completed_assisted` |
| Fallos y errores de navegación | Contadores observados, nunca inferidos |
| Comprensión incorrecta | Solo las tareas donde se evaluó la interpretación |
| Tasa de finalización autónoma | Completadas sin ayuda / intentos de esa tarea, **solo con al menos 5 intentos** |
| Mediana de duración | Segundos entre intentos, **solo con al menos 5 intentos** |
| Incidentes críticos | Cantidad por categoría predefinida |

En el **reporte interno**, con menos de cinco intentos por tarea, `unassisted_rate` y `median_seconds` son **`null`**, nunca cero ni porcentajes inventados. **El mínimo es por tarea y no por número total de participantes**: cinco personas de perfiles distintos no bastan para estimar la tasa de una tarea realizada solo por un revisor. Los recuentos internos incluso con muestras menores de cinco pueden revelar información sobre individuos de grupos pequeños: **no publicar ni compartir el resumen sin una revisión de divulgación específica**. El reporte con cero sesiones tiene `human_usability: "not_conducted"`. Si existe al menos una sesión estructuralmente aceptada, se marca `"moderator_entered_observations"` (declaración de procedencia, **no certificación**).

**En el detalle interno** se mantienen `manual_assistive_technology: "not_verified"`, `institutional_authorization: "not_granted"` y `release_gate: "requires_independent_approval"`; la versión reducida conserva las señales equivalentes `manual_accessibility: "not_verified"` y `authorization: "not_granted"`. Las pruebas NVDA/VoiceOver, zoom nativo y alto contraste Windows deberán registrarse y aprobarse mediante un procedimiento manual separado.

### Condiciones de bloqueo

Interpretar un error 503 como prueba de ausencia documental, la cuarentena como inspección, la validación interna como aprobación oficial, o SHA-256 como firma son hallazgos **críticos**. Registrar la categoría, abrir un defecto con acceso restringido y corregir su causa antes de declarar un piloto humano preparado. Las pruebas automatizadas siguen siendo necesarias pero insuficientes.

## Verificación del incremento

- `tests/test_ux5_study.py` contiene contratos Red → Green para plantilla y asignación de tareas por perfil, coincidencia con el contrato de siete tareas UX-5.1, consentimiento, privacidad de campos, tipos, límites, errores, agregación y creación segura de archivos privados (permisos 0600/0700, sin sobrescritura ni enlaces simbólicos).
- `scripts/ci.sh` ejecuta estas pruebas en un paso propio, sin añadir dependencias, GitHub Actions ni conectores de datos personales.
- `.gitignore` excluye `.ux5-study/` para reducir la posibilidad de añadir registros individuales por accidente. Esta protección por sí sola no impide un `git add -f` deliberado.
- No cambian la aplicación React, los Workers, el inspector, D1/R2 ni los permisos de la comisión.

**Pendiente (UX-5.2 real):** reclutar participantes, obtener consentimiento, ejecutar las tareas moderadas en una demo sintética autorizada, completar archivos locales, revisar incidentes y documentar decisiones de corrección. Hasta entonces, **la investigación humana no se ha ejecutado**.
