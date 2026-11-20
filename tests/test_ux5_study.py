"""Local UX-5.2 moderated study contracts. All fixtures are synthetic."""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ux5_study.py"
SPEC = importlib.util.spec_from_file_location("ux5_study", MODULE_PATH)
assert SPEC and SPEC.loader
study = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(study)


def observed_session(role="author"):
    result = study.new_session_template()
    result.update({
        "role": role,
        "consent_obtained": True,
        "moderated_observation": True,
        "synthetic_environment": True,
    })
    return result


def observed_task(session, task_id, outcome="completed_unassisted",
                  seconds=85, navigation_errors=0, interpretation="correct",
                  incident_codes=None):
    task = next(item for item in session["tasks"] if item["id"] == task_id)
    task.update({
        "outcome": outcome,
        "duration_seconds": seconds,
        "navigation_errors": navigation_errors,
        "interpretation": interpretation,
        "incident_codes": incident_codes or [],
    })


class UX5ModeratedStudyTests(unittest.TestCase):
    def test_template_is_incomplete_by_default_and_matches_e2e_task_contract(self):
        template = study.new_session_template()
        self.assertIsNone(template["role"])
        self.assertIs(template["consent_obtained"], False)
        self.assertIs(template["moderated_observation"], False)
        self.assertIs(template["synthetic_environment"], True)
        self.assertEqual(len(template["tasks"]), 7)
        self.assertTrue(all(t["outcome"] == "not_attempted" for t in template["tasks"]))
        ts = (ROOT / "tests" / "pilot-evidence.ts").read_text(encoding="utf-8")
        block = ts.split("PILOT_TASKS = [", 1)[1].split("] as const", 1)[0]
        self.assertEqual([m.group(1) for m in re.finditer(r'"([a-z0-9_]+)"', block)],
                         study.TASK_IDS)

    def test_requires_consent_moderation_and_synthetic_environment(self):
        for key, value in [
            ("consent_obtained", False),
            ("moderated_observation", False),
            ("synthetic_environment", False),
            ("role", None),
            ("role", "operator"),
        ]:
            with self.subTest(key=key, value=value):
                sample = observed_session()
                sample[key] = value
                with self.assertRaises(study.StudyDataError):
                    study.validate_session(sample)

    def test_rejects_personal_data_unknown_keys_and_wrong_task_schema(self):
        for key, value in [
            ("participant_name", "Sensitive Personal Information"),
            ("email", "private@example.test"),
            ("notes", "unstructured content"),
            ("recording_url", "https://somewhere"),
        ]:
            sample = observed_session()
            sample[key] = value
            with self.subTest(key=key), self.assertRaises(study.StudyDataError):
                study.validate_session(sample)
        sample = observed_session()
        sample["tasks"][0]["free_text"] = "Sensitive"
        with self.assertRaises(study.StudyDataError):
            study.validate_session(sample)
        sample = observed_session()
        sample["tasks"][1]["id"] = sample["tasks"][0]["id"]
        with self.assertRaises(study.StudyDataError):
            study.validate_session(sample)

    def test_unattempted_cannot_claim_time_and_attempted_requires_observation(self):
        sample = observed_session()
        sample["tasks"][0]["duration_seconds"] = 22
        with self.assertRaises(study.StudyDataError):
            study.validate_session(sample)
        sample = observed_session()
        sample["tasks"][0]["outcome"] = "completed_unassisted"
        with self.assertRaises(study.StudyDataError):
            study.validate_session(sample)
        for seconds, errors in [(True, 0), (0, 0), (-1, 0),
                                (15, True), (15, -1), (7201, 0)]:
            sample = observed_session()
            observed_task(sample, study.TASK_IDS[0], seconds=seconds, navigation_errors=errors)
            with self.subTest(seconds=seconds, errors=errors), self.assertRaises(study.StudyDataError):
                study.validate_session(sample)

    def test_rejects_unknown_or_duplicate_incidents_and_wrong_interpretation(self):
        for codes in [["arbitrary text"], ["unavailable_as_absent"] * 2]:
            sample = observed_session()
            observed_task(sample, study.TASK_IDS[0], incident_codes=codes)
            with self.assertRaises(study.StudyDataError):
                study.validate_session(sample)
        sample = observed_session()
        observed_task(sample, study.TASK_IDS[0], interpretation="verified_officially")
        with self.assertRaises(study.StudyDataError):
            study.validate_session(sample)

    def test_pilot_role_task_assignments_are_exact_and_distinct(self):
        self.assertEqual(study.ROLE_TASKS, {
            "president": ("scope_opened",),
            "author": ("scope_opened", "pdf_quarantined",
                       "draft_registered", "submitted_for_review"),
            "reviewer": ("scope_opened", "independent_decision"),
            "observer": ("scope_opened", "observer_read_only",
                         "sha256_export_verified"),
        })
        self.assertEqual(set(study.ROLE_TASKS), study.ROLES)
        self.assertEqual(set.union(*(set(v) for v in study.ROLE_TASKS.values())),
                         set(study.TASK_IDS))

    def test_role_specific_template_is_unobserved_and_requires_consent(self):
        for role, eligible in study.ROLE_TASKS.items():
            with self.subTest(role=role):
                template = study.new_session_template(role=role)
                self.assertEqual(template["role"], role)
                self.assertFalse(template["consent_obtained"])
                self.assertFalse(template["moderated_observation"])
                self.assertEqual(len(template["tasks"]), len(study.TASK_IDS))
                self.assertTrue(all(t["outcome"] == "not_attempted" for t in template["tasks"]))
                self.assertTrue(eligible)
                with self.assertRaises(study.StudyDataError):
                    study.validate_session(template)
        with self.assertRaises(study.StudyDataError):
            study.new_session_template(role="unrecognized")

    def test_ineligible_task_cannot_be_attributed_to_another_role(self):
        examples = [
            ("president", "pdf_quarantined"),
            ("author", "independent_decision"),
            ("reviewer", "draft_registered"),
            ("observer", "submitted_for_review"),
        ]
        for role, task_id in examples:
            sample = observed_session(role)
            observed_task(sample, "scope_opened")
            observed_task(sample, task_id)
            with self.subTest(role=role, task_id=task_id):
                with self.assertRaisesRegex(study.StudyDataError, "perfil"):
                    study.validate_session(sample)

    def test_each_role_accepts_only_its_own_planned_tasks(self):
        for role, eligible in study.ROLE_TASKS.items():
            with self.subTest(role=role):
                sample = observed_session(role)
                for task_id in eligible:
                    observed_task(sample, task_id)
                self.assertIs(study.validate_session(sample), sample)

    def test_role_template_cli_is_unobserved_and_rejects_unknown_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            for role in study.ROLES:
                result = subprocess.run(
                    [sys.executable, str(MODULE_PATH), "template", "--role", role],
                    cwd=ROOT, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                template = json.loads(result.stdout)
                self.assertEqual(template["role"], role)
                self.assertIs(template["consent_obtained"], False)
            invalid = subprocess.run(
                [sys.executable, str(MODULE_PATH), "template", "--role", "admin"],
                cwd=ROOT, capture_output=True, text=True
            )
            self.assertNotEqual(invalid.returncode, 0)

    def test_ineligible_tasks_never_enter_role_based_denominators(self):
        roles = ("president", "author", "reviewer", "observer", "author")
        samples = []
        for role in roles:
            sample = observed_session(role)
            for task_id in study.ROLE_TASKS[role]:
                observed_task(sample, task_id)
            samples.append(sample)
        report = study.summarize_sessions(samples)
        scope = next(t for t in report["tasks"] if t["id"] == "scope_opened")
        pdf = next(t for t in report["tasks"] if t["id"] == "pdf_quarantined")
        review = next(t for t in report["tasks"] if t["id"] == "independent_decision")
        self.assertEqual(scope["attempted"], 5)
        self.assertEqual(scope["unassisted_rate"], 1.0)
        self.assertEqual(pdf["attempted"], 2)
        self.assertIsNone(pdf["unassisted_rate"])
        self.assertEqual(review["attempted"], 1)
        self.assertIsNone(review["median_seconds"])
        self.assertEqual(report["institutional_authorization"], "not_granted")

    def test_legacy_protocol_version_requires_explicit_review_not_silent_upgrade(self):
        session = observed_session("author")
        observed_task(session, "scope_opened")
        session["study_version"] = "ux5.2-v1"
        with self.assertRaisesRegex(study.StudyDataError, "Versión"):
            study.validate_session(session)

    def test_cli_rejects_cross_role_observation_without_echoing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            record = observed_session("observer")
            observed_task(record, "scope_opened")
            observed_task(record, "independent_decision")
            path = Path(directory) / "not-allowed.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), "validate", str(path)],
                cwd=ROOT, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("perfil", result.stderr)
            self.assertNotIn("observer", result.stderr)
            self.assertNotIn("independent_decision", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_blank_consented_form_cannot_be_reported_as_a_completed_session(self):
        with self.assertRaises(study.StudyDataError):
            study.validate_session(observed_session())

    def test_no_sessions_never_become_zero_percent_or_fake_success(self):
        report = study.summarize_sessions([])
        self.assertEqual(report["human_usability"], "not_conducted")
        self.assertEqual(report["session_count"], 0)
        self.assertTrue(all(t["unassisted_rate"] is None for t in report["tasks"]))
        self.assertTrue(all(t["median_seconds"] is None for t in report["tasks"]))
        self.assertEqual(report["institutional_authorization"], "not_granted")
        self.assertEqual(report["manual_assistive_technology"], "not_verified")

    def test_five_real_observations_enable_denominator_based_metrics_not_certification(self):
        sessions = []
        outcomes = ["completed_unassisted", "completed_unassisted",
                    "completed_assisted", "completed_assisted", "failed"]
        for i, outcome in enumerate(outcomes):
            sample = observed_session(["president", "author", "reviewer", "observer", "author"][i])
            observed_task(sample, "scope_opened", outcome=outcome,
                          seconds=(i + 1) * 10,
                          navigation_errors=i % 2,
                          interpretation="incorrect" if i == 4 else "correct",
                          incident_codes=["unavailable_as_absent"] if i == 4 else [])
            sessions.append(sample)
        report = study.summarize_sessions(sessions)
        first = report["tasks"][0]
        self.assertEqual(report["session_count"], 5)
        self.assertEqual(report["human_usability"], "moderator_entered_observations")
        self.assertEqual(first["attempted"], 5)
        self.assertEqual(first["completed_unassisted"], 2)
        self.assertEqual(first["completed_assisted"], 2)
        self.assertEqual(first["failed"], 1)
        self.assertEqual(first["unassisted_rate"], 0.4)
        self.assertEqual(first["median_seconds"], 30)
        self.assertEqual(first["interpretation_errors"], 1)
        self.assertEqual(report["critical_incidents"]["unavailable_as_absent"], 1)
        self.assertIsNone(report["tasks"][1]["unassisted_rate"])
        self.assertNotIn("role", json.dumps(report))
        self.assertNotIn("participant", json.dumps(report))
        self.assertEqual(report["release_gate"], "requires_independent_approval")

    def test_small_sample_does_not_publish_rate_or_median(self):
        sample = observed_session()
        observed_task(sample, "scope_opened")
        result = study.summarize_sessions([sample])
        self.assertEqual(result["tasks"][0]["attempted"], 1)
        self.assertIsNone(result["tasks"][0]["unassisted_rate"])
        self.assertIsNone(result["tasks"][0]["median_seconds"])

    def test_ci_runs_study_privacy_contracts_and_local_records_are_ignored(self):
        ci = (ROOT / "scripts" / "ci.sh").read_text(encoding="utf-8")
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("test_ux5_study.py", ci)
        self.assertIn("/.ux5-study/", ignored)

    def test_summary_is_not_marked_ready_even_if_all_eligible_tasks_have_results(self):
        samples = []
        for role in ("president", "author", "reviewer", "observer", "author"):
            sample = observed_session(role)
            for task_id in study.ROLE_TASKS[role]:
                observed_task(sample, task_id)
            samples.append(sample)
        report = study.summarize_sessions(samples)
        self.assertEqual(report["session_count"], 5)
        self.assertEqual(report["release_gate"], "requires_independent_approval")
        self.assertEqual(report["institutional_authorization"], "not_granted")
        self.assertEqual(report["manual_assistive_technology"], "not_verified")
        self.assertEqual(report["tasks"][0]["unassisted_rate"], 1.0)

    def test_public_summary_on_empty_study_has_no_participant_level_metadata(self):
        public = study.public_summary(study.summarize_sessions([]))
        self.assertEqual(public["study_status"], "not_conducted")
        self.assertEqual(public["authorization"], "not_granted")
        self.assertEqual(public["manual_accessibility"], "not_verified")
        self.assertEqual(public["task_coverage"], "not_released")
        self.assertEqual(public["disclosure"], "requires_human_review")
        self.assertNotIn("session_count", json.dumps(public))
        self.assertNotIn("critical_incidents", json.dumps(public))
        self.assertNotIn("unassisted_rate", json.dumps(public))

    def test_public_summary_suppresses_all_task_information_below_five_sessions(self):
        sample = observed_session("observer")
        observed_task(sample, "observer_read_only", outcome="failed",
                      incident_codes=["internal_validation_as_official"])
        report = study.public_summary(study.summarize_sessions([sample]))
        self.assertEqual(report["study_status"], "limited_observations")
        self.assertEqual(report["task_coverage"], "not_released")
        for secret in ("observer_read_only", "internal_validation_as_official",
                       "failed", "median_seconds", "role", "session_count",
                       "navigation_errors", "interpretation_errors"):
            self.assertNotIn(secret, json.dumps(report))

    def test_public_summary_only_exposes_coarse_task_coverage_with_five_sessions(self):
        sessions = []
        for role in ("president", "author", "reviewer", "observer", "author"):
            sample = observed_session(role)
            for task_id in study.ROLE_TASKS[role]:
                observed_task(sample, task_id)
            sessions.append(sample)
        internal = study.summarize_sessions(sessions)
        public = study.public_summary(internal)
        self.assertEqual(public["study_status"], "coverage_review_available")
        coverage = {task["id"]:task["coverage"] for task in public["task_coverage"]}
        self.assertEqual(coverage["scope_opened"], "minimum_met")
        self.assertEqual(coverage["independent_decision"], "below_minimum")
        self.assertEqual(coverage["pdf_quarantined"], "below_minimum")
        self.assertEqual(len(coverage), len(study.TASK_IDS))
        self.assertEqual(public["authorization"], "not_granted")
        self.assertNotIn("session_count", json.dumps(public))
        self.assertNotIn("completed_unassisted", json.dumps(public))
        self.assertNotIn("critical_incidents", json.dumps(public))
        self.assertNotIn('"attempted"', json.dumps(public))

    def test_cli_summary_is_reduced_disclosure_by_default_and_detailed_only_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.json"
            sample = observed_session("author")
            observed_task(sample, "scope_opened")
            path.write_text(json.dumps(sample), encoding="utf-8")
            public = subprocess.run(
                [sys.executable, str(MODULE_PATH), "summarize", str(path)],
                cwd=ROOT, capture_output=True, text=True
            )
            self.assertEqual(public.returncode, 0, public.stderr)
            clean = json.loads(public.stdout)
            self.assertEqual(clean["task_coverage"], "not_released")
            self.assertNotIn("session_count", clean)
            self.assertNotIn("unassisted_rate", public.stdout)
            detailed = subprocess.run(
                [sys.executable, str(MODULE_PATH), "summarize", "--internal", str(path)],
                cwd=ROOT, capture_output=True, text=True
            )
            self.assertEqual(detailed.returncode, 0, detailed.stderr)
            self.assertEqual(json.loads(detailed.stdout)["session_count"], 1)
            self.assertIn("solo uso local", detailed.stderr.lower())
            self.assertNotIn("author", detailed.stderr)

    def test_public_summary_fails_closed_on_malformed_internal_report(self):
        internal = study.summarize_sessions([])
        internal["release_gate"] = "approved"
        with self.assertRaises(study.StudyDataError):
            study.public_summary(internal)
        internal = study.summarize_sessions([])
        internal["tasks"][0]["id"] = "fabricated"
        with self.assertRaises(study.StudyDataError):
            study.public_summary(internal)

    def test_cli_rejects_duplicate_json_keys_and_duplicate_input_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), "validate", str(path)],
                cwd=ROOT, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Traceback", result.stderr)
            sample = observed_session()
            observed_task(sample, "scope_opened")
            path.write_text(json.dumps(sample), encoding="utf-8")
            duplicate = subprocess.run(
                [sys.executable, str(MODULE_PATH), "summarize", str(path), str(path)],
                cwd=ROOT, capture_output=True, text=True
            )
            self.assertNotEqual(duplicate.returncode, 0)

    def test_internal_cli_outputs_detailed_aggregate_without_session_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.json"
            sample = observed_session()
            observed_task(sample, "scope_opened")
            path.write_text(json.dumps(sample), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), "summarize", "--internal", str(path)],
                cwd=ROOT, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["session_count"], 1)
            self.assertNotIn("consent_obtained", result.stdout)
            self.assertNotIn("synthetic_environment", result.stdout)
            self.assertNotIn('"role": "author"', result.stdout)


if __name__ == "__main__":
    unittest.main()
