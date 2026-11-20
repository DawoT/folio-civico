#!/usr/bin/env python3
"""UX-5.2 local-only moderated observation helper.

Reads strictly structured JSON files and writes ONLY a sanitized aggregate
to stdout. Does not contact the network, persist participant data, or certify
WCAG, the inspector, or institutional pilot readiness.

Usage:
    python3 scripts/ux5_study.py template
    python3 scripts/ux5_study.py validate .ux5-study/session-01.json
    python3 scripts/ux5_study.py summarize .ux5-study/session-*.json
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

STUDY_VERSION = "ux5.3-v1"
TASK_IDS = [
    "scope_opened",
    "pdf_quarantined",
    "draft_registered",
    "submitted_for_review",
    "independent_decision",
    "observer_read_only",
    "sha256_export_verified",
]
# These are *study assignments*, not a replacement for authorization checks.
# A task not assigned to a profile cannot be scored for that profile.
ROLE_TASKS: dict[str, tuple[str, ...]] = {
    "president": ("scope_opened",),
    "author": ("scope_opened", "pdf_quarantined", "draft_registered",
               "submitted_for_review"),
    "reviewer": ("scope_opened", "independent_decision"),
    "observer": ("scope_opened", "observer_read_only", "sha256_export_verified"),
}
ROLES = frozenset(ROLE_TASKS)
OUTCOMES = frozenset({
    "not_attempted", "completed_unassisted", "completed_assisted", "failed"
})
INTERPRETATIONS = frozenset({"not_evaluated", "correct", "incorrect"})
INCIDENT_CODES = (
    "unavailable_as_absent",
    "quarantine_as_reviewed",
    "internal_validation_as_official",
    "sha256_as_signature",
    "keyboard_blocker",
    "other_blocker",
)
ROOT_KEYS = frozenset({
    "schema_version", "study_version", "role",
    "consent_obtained", "moderated_observation", "synthetic_environment",
    "tasks",
})
TASK_KEYS = frozenset({
    "id", "outcome", "duration_seconds", "navigation_errors",
    "interpretation", "incident_codes",
})
# Rates/medians from very small samples can be misleading and reveal
# recognizable individual performance. Suppress both below this denominator.
MIN_AGGREGATE_DENOMINATOR = 5
MAX_SESSION_BYTES = 65536
MAX_INPUT_SESSIONS = 100


class StudyDataError(ValueError):
    """Invalid local study record. Error messages never embed submitted values."""


def _strict_keys(value: Any, allowed: frozenset[str], field: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != allowed:
        raise StudyDataError(f"Campos inesperados, ausentes o inválidos: {field}.")
    return value


def _integer(value: Any, low: int, high: int, field: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise StudyDataError(f"Entero fuera de rango: {field}.")
    return value


def new_session_template(role: str | None = None) -> dict[str, Any]:
    """Role-aware template; still invalid until real consent and observation."""
    if role is not None and (type(role) is not str or role not in ROLES):
        raise StudyDataError("Perfil de sesión desconocido.")
    return {
        "schema_version": 1,
        "study_version": STUDY_VERSION,
        "role": role,
        "consent_obtained": False,
        "moderated_observation": False,
        "synthetic_environment": True,
        "tasks": [
            {
                "id": task,
                "outcome": "not_attempted",
                "duration_seconds": None,
                "navigation_errors": None,
                "interpretation": "not_evaluated",
                "incident_codes": [],
            }
            for task in TASK_IDS
        ],
    }


def validate_session(data: Any) -> dict[str, Any]:
    """Fail closed on unknown fields, missing consent and fabricated placeholders.

    The operator is responsible for the truth of consent and observation.
    Structured validation cannot verify a human was actually present.
    """
    value = _strict_keys(data, ROOT_KEYS, "session")
    _integer(value["schema_version"], 1, 1, "schema_version")
    if value["study_version"] != STUDY_VERSION:
        raise StudyDataError("Versión de protocolo no admitida.")
    if type(value["role"]) is not str or value["role"] not in ROLES:
        raise StudyDataError("Perfil de la sesión inválido.")
    if value["consent_obtained"] is not True:
        raise StudyDataError("Se requiere consentimiento confirmado.")
    if value["moderated_observation"] is not True:
        raise StudyDataError("Se requiere observación moderada, no inferida.")
    if value["synthetic_environment"] is not True:
        raise StudyDataError("Solo se aceptan sesiones con entorno sintético.")
    tasks = value["tasks"]
    if type(tasks) is not list or len(tasks) != len(TASK_IDS):
        raise StudyDataError("La matriz de tareas debe estar completa.")
    for index, (task, task_id) in enumerate(zip(tasks, TASK_IDS)):
        entry = _strict_keys(task, TASK_KEYS, f"tasks[{index}]")
        if entry["id"] != task_id:
            raise StudyDataError("Tareas desconocidas, duplicadas o reordenadas.")
        if type(entry["outcome"]) is not str or entry["outcome"] not in OUTCOMES:
            raise StudyDataError("Resultado de tarea no admitido.")
        if type(entry["interpretation"]) is not str or entry["interpretation"] not in INTERPRETATIONS:
            raise StudyDataError("Interpretación de estado no admitida.")
        codes = entry["incident_codes"]
        if (type(codes) is not list
                or len(codes) > len(INCIDENT_CODES)
                or any(type(code) is not str or code not in INCIDENT_CODES for code in codes)
                or len(set(codes)) != len(codes)):
            raise StudyDataError("Categorías de incidente desconocidas o duplicadas.")
        if entry["outcome"] != "not_attempted" and entry["id"] not in ROLE_TASKS[value["role"]]:
            raise StudyDataError("Tarea no asignada al perfil del participante.")
        if entry["outcome"] == "not_attempted":
            if (entry["duration_seconds"] is not None
                    or entry["navigation_errors"] is not None
                    or entry["interpretation"] != "not_evaluated"
                    or codes):
                raise StudyDataError("No atribuir métricas a tareas no intentadas.")
        else:
            _integer(entry["duration_seconds"], 1, 7200, "duration_seconds")
            _integer(entry["navigation_errors"], 0, 100, "navigation_errors")
    if not any(task["outcome"] != "not_attempted" for task in tasks):
        raise StudyDataError("La sesión debe contener al menos una tarea observada.")
    return value


def summarize_sessions(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate counts only; never copy roles or raw session data to output."""
    if type(sessions) is not list or len(sessions) > MAX_INPUT_SESSIONS:
        raise StudyDataError("Número de sesiones fuera de límite.")
    entries = [validate_session(data) for data in sessions]
    tasks = []
    incidents = {code: 0 for code in INCIDENT_CODES}
    for i, task_id in enumerate(TASK_IDS):
        current = [session["tasks"][i] for session in entries]
        attempted = [task for task in current if task["outcome"] != "not_attempted"]
        unassisted = sum(task["outcome"] == "completed_unassisted" for task in attempted)
        assisted = sum(task["outcome"] == "completed_assisted" for task in attempted)
        failed = sum(task["outcome"] == "failed" for task in attempted)
        correct = sum(task["interpretation"] == "correct" for task in attempted)
        incorrect = sum(task["interpretation"] == "incorrect" for task in attempted)
        for task in attempted:
            for code in task["incident_codes"]:
                incidents[code] += 1
        publish_metrics = len(attempted) >= MIN_AGGREGATE_DENOMINATOR
        tasks.append({
            "id": task_id,
            "attempted": len(attempted),
            "not_attempted": len(current) - len(attempted),
            "completed_unassisted": unassisted,
            "completed_assisted": assisted,
            "failed": failed,
            "interpretation_evaluated": correct + incorrect,
            "interpretation_errors": incorrect,
            "navigation_errors": sum(task["navigation_errors"] for task in attempted),
            "unassisted_rate": round(unassisted / len(attempted), 3) if publish_metrics else None,
            "median_seconds": statistics.median(
                task["duration_seconds"] for task in attempted
            ) if publish_metrics else None,
        })
    return {
        "schema_version": 1,
        "study_version": STUDY_VERSION,
        "source": "moderator_entered_local_observations",
        "session_count": len(entries),
        "human_usability": "moderator_entered_observations" if entries else "not_conducted",
        "aggregate_minimum": MIN_AGGREGATE_DENOMINATOR,
        "tasks": tasks,
        "critical_incidents": incidents,
        "manual_assistive_technology": "not_verified",
        "institutional_authorization": "not_granted",
        "release_gate": "requires_independent_approval",
    }


def public_summary(internal: dict[str, Any]) -> dict[str, Any]:
    """Reduced-disclosure status, *not* an anonymity or publication guarantee.

    Individual role/task combinations can reveal performance even when a
    detailed aggregate hides percentages. Keep task statuses hidden until
    there are at least five sessions overall, and never include counts,
    outcomes, durations, incident categories or observed roles in this view.
    """
    expected_keys = frozenset({
        "schema_version", "study_version", "source", "session_count",
        "human_usability", "aggregate_minimum", "tasks", "critical_incidents",
        "manual_assistive_technology", "institutional_authorization", "release_gate",
    })
    report = _strict_keys(internal, expected_keys, "internal_summary")
    if (type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["study_version"] != STUDY_VERSION
            or report["source"] != "moderator_entered_local_observations"
            or report["manual_assistive_technology"] != "not_verified"
            or report["institutional_authorization"] != "not_granted"
            or report["release_gate"] != "requires_independent_approval"
            or report["aggregate_minimum"] != MIN_AGGREGATE_DENOMINATOR):
        raise StudyDataError("Resumen interno inconsistente o no autorizado.")
    session_count = _integer(report["session_count"], 0, MAX_INPUT_SESSIONS, "session_count")
    expected_human_status = "not_conducted" if session_count == 0 else "moderator_entered_observations"
    if report["human_usability"] != expected_human_status:
        raise StudyDataError("Estado humano inconsistente.")
    tasks = report["tasks"]
    if type(tasks) is not list or len(tasks) != len(TASK_IDS):
        raise StudyDataError("Resumen de tareas incompleto.")
    for i, task in enumerate(tasks):
        if type(task) is not dict or task.get("id") != TASK_IDS[i]:
            raise StudyDataError("Resumen de tareas desconocido o fuera de orden.")
        _integer(task.get("attempted"), 0, session_count, "attempted")
    # Only emit coarse coverage once enough sessions exist. A respondent's
    # failure and the presence of a rare-role respondent are never exported.
    if session_count < MIN_AGGREGATE_DENOMINATOR:
        coverage: list[dict[str, str]] | str = "not_released"
        status = "not_conducted" if session_count == 0 else "limited_observations"
    else:
        coverage = [
            {
                "id": task_id,
                "coverage": "minimum_met"
                    if task["attempted"] >= MIN_AGGREGATE_DENOMINATOR
                    else "below_minimum",
            }
            for task_id, task in zip(TASK_IDS, tasks)
        ]
        status = "coverage_review_available"
    return {
        "schema_version": 1,
        "study_status": status,
        "task_coverage": coverage,
        "authorization": "not_granted",
        "manual_accessibility": "not_verified",
        # Coarse statuses still reveal participation patterns; human privacy
        # review remains mandatory before any external disclosure.
        "disclosure": "requires_human_review",
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StudyDataError("Campos JSON duplicados.")
        value[key] = item
    return value


def _load_file(filename: str) -> dict[str, Any]:
    path = Path(filename)
    try:
        if not path.is_file() or path.stat().st_size > MAX_SESSION_BYTES:
            raise StudyDataError("Archivo de sesión ausente o demasiado grande.")
        data = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                StudyDataError("Constante JSON no admitida.")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StudyDataError("Archivo de sesión ilegible o JSON inválido.") from exc
    return validate_session(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="UX-5.2: captura local y agregación estricta de sesiones moderadas."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    template = sub.add_parser("template",
                              help="Imprime formulario sin consentimiento, opcionalmente asignado a un perfil.")
    template.add_argument("--role", choices=sorted(ROLES), default=None)
    validate = sub.add_parser("validate", help="Valida una sesión sin publicar datos.")
    validate.add_argument("file")
    summarize = sub.add_parser(
        "summarize", help="Estado de baja divulgación por defecto; detalle solo con --internal."
    )
    summarize.add_argument("--internal", action="store_true",
                           help="Expone recuentos de cohortes pequeñas; solo uso local restringido.")
    summarize.add_argument("files", nargs="+")
    args = parser.parse_args(argv)
    try:
        if args.command == "template":
            print(json.dumps(new_session_template(role=args.role), ensure_ascii=False, indent=2))
        elif args.command == "validate":
            _load_file(args.file)
            print("VALID")
        else:
            if len(args.files) > MAX_INPUT_SESSIONS:
                raise StudyDataError("Demasiadas sesiones.")
            resolved = [Path(item).resolve() for item in args.files]
            if len(set(resolved)) != len(resolved):
                raise StudyDataError("Ruta de sesión duplicada.")
            detailed = summarize_sessions([_load_file(item) for item in args.files])
            if args.internal:
                print("AVISO: solo uso local restringido; no compartir recuentos detallados.",
                      file=sys.stderr)
            print(json.dumps(
                detailed if args.internal else public_summary(detailed),
                ensure_ascii=False, indent=2
            ))
        return 0
    except StudyDataError as exc:
        print(f"UX-5.2: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
