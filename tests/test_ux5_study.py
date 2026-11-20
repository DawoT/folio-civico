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

    def test_summary_is_not_marked_ready_even_if_all_tasks_have_results(self):
        sample = observed_session()
        for task in study.TASK_IDS:
            observed_task(sample, task)
        report = study.summarize_sessions([sample] * 5)
        self.assertEqual(report["session_count"], 5)
        self.assertEqual(report["release_gate"], "requires_independent_approval")
        self.assertEqual(report["institutional_authorization"], "not_granted")
        self.assertEqual(report["manual_assistive_technology"], "not_verified")
        self.assertEqual(report["tasks"][0]["unassisted_rate"], 1.0)

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

    def test_cli_outputs_sanitized_aggregate_without_session_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.json"
            sample = observed_session()
            observed_task(sample, "scope_opened")
            path.write_text(json.dumps(sample), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(MODULE_PATH), "summarize", str(path)],
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
