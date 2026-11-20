"""R1.41 TDD: pinned source/commit postimages are research, not VEX."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))

import tesseract_554_source_patch_probe as m

PATCH = """From 614e971036d2b95d521057ff63d68d6612429b23 Mon Sep 17 00:00:00 2001
Subject: [PATCH] guard
---
diff --git a/src/lstm/test.cpp b/src/lstm/test.cpp
index abc..def 100644
--- a/src/lstm/test.cpp
+++ b/src/lstm/test.cpp
@@ -1,3 +1,3 @@
 void test() {
-  vulnerable();
+  secure();
 }
-- 
2.39.2
"""


class TesseractProbeTests(unittest.TestCase):
    def test_complete_fourteen_CVEs_pinned_to_official_backlog(self):
        m.validate_manifest()
        self.assertEqual(len(m.PINNED_COMMITS), 14)
        self.assertEqual(len({item[0] for item in m.PINNED_COMMITS.values()}), 14)
        self.assertIn("CVE-2026-119338", m.PINNED_COMMITS)

    def test_reject_missing_or_duplicate_patch_ids(self):
        with patch.object(m, "PINNED_COMMITS", {
            k: v for k, v in m.PINNED_COMMITS.items()
            if k != "CVE-2026-119338"
        }):
            with self.assertRaises(ValueError):
                m.validate_manifest()
        bad = dict(m.PINNED_COMMITS)
        bad["CVE-2026-119339"] = bad["CVE-2026-119338"]
        with patch.object(m, "PINNED_COMMITS", bad):
            with self.assertRaises(ValueError):
                m.validate_manifest()

    def test_source_postimage_must_match_exact_lines(self):
        source = {"src/lstm/test.cpp": (
            "void test() {", "  secure();", "}"
        )}
        result = m.probe_postimages(source, PATCH)
        self.assertEqual(result["status"], "all_source_postimages_exact")
        self.assertEqual(result["exact_postimage_hunks"], 1)
        self.assertEqual(result["source_hunks"], 1)

        wrong = {"src/lstm/test.cpp": (
            "void test() {", "  vulnerable();", "}"
        )}
        result = m.probe_postimages(wrong, PATCH)
        self.assertEqual(result["status"], "partial_unresolved")
        self.assertEqual(result["exact_postimage_hunks"], 0)
        self.assertEqual(result["unresolved_paths"], ["src/lstm/test.cpp"])

    def test_git_patch_trailer_is_not_accepted_as_source_hunk(self):
        hunks = m.patch_hunks(PATCH)
        self.assertEqual(hunks, [("src/lstm/test.cpp", (
            "void test() {", "  secure();", "}"
        ))])

    def test_removal_only_security_hunks_never_disappear_from_review(self):
        patch_data = PATCH.replace(
            "-  vulnerable();\n+  secure();",
            "-  vulnerable();",
        )
        self.assertEqual(m.patch_hunks(patch_data), [
            ("src/lstm/test.cpp", ())
        ])
        result = m.probe_postimages({
            "src/lstm/test.cpp": ("void test() {", "}",)
        }, patch_data)
        self.assertEqual(result["status"], "partial_unresolved")
        self.assertEqual(result["source_hunks"], 1)
        self.assertEqual(result["exact_postimage_hunks"], 0)

    def test_missing_src_hunks_or_unsafe_paths_fail_closed(self):
        with self.assertRaises(ValueError):
            m.patch_hunks(PATCH.replace("src/lstm/test.cpp", "README.md"))
        with self.assertRaises(ValueError):
            m.patch_hunks(PATCH.replace(
                "src/lstm/test.cpp", "src/../../etc/passwd"
            ))
        with self.assertRaises(ValueError):
            m.probe_postimages({}, PATCH)

    def test_verified_archive_requires_sha_and_full_source_set(self):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w:gz") as tar:
            for i in range(101):
                data = f"int fn{i}() {{ return {i}; }}".encode()
                info = tarfile.TarInfo(
                    f"tesseract-5.5.4/src/checked_{i}.cpp"
                )
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        blob = content.getvalue()
        with patch.object(m, "SOURCE_TARBALL_SHA256",
                          hashlib.sha256(blob).hexdigest()):
            files = m.archive_sources(blob)
            self.assertEqual(len(files), 101)
            self.assertEqual(files["src/checked_1.cpp"], (
                "int fn1() { return 1; }",
            ))
        with self.assertRaises(ValueError):
            m.archive_sources(blob)

    def test_worker_refuses_altered_fixed_upstream_patch(self):
        name = "CVE-2026-119341"
        commit = m.PINNED_COMMITS[name][0]
        with patch.object(m, "PINNED_COMMITS", {
            name: (commit, hashlib.sha256(PATCH.encode()).hexdigest())
        }), patch.object(m, "archive_sources", return_value={
            "src/lstm/test.cpp": ("void test() {", "  secure();", "}")
        }), patch.object(m, "_fetch", side_effect=[b"synthetic-tar",
                                                    b"modified-patch"]):
            with self.assertRaisesRegex(ValueError, "patch bytes"):
                m.worker()

    def test_worker_emits_no_CVE_clearance_even_if_all_hunks_match(self):
        name = "CVE-2026-119341"
        commit = m.PINNED_COMMITS[name][0]
        with patch.object(m, "PINNED_COMMITS", {
            name: (commit, hashlib.sha256(PATCH.encode()).hexdigest())
        }), patch.object(m, "archive_sources", return_value={
            "src/lstm/test.cpp": ("void test() {", "  secure();", "}")
        }), patch.object(m, "_fetch", side_effect=[b"synthetic-tar",
                                                    PATCH.encode()]):
            result = m.worker()
        self.assertEqual(result["cves_with_all_source_hunks_exact"], 1)
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["compiled_elf_bound_to_source_by_build_attestation"])
        self.assertFalse(result["complete_source_advisory_coverage"])
        self.assertFalse(result["patch_files_signed_by_vendor"])
        self.assertEqual(result["vex"], "not_issued")

    def _synthetic_complete_report(self):
        rows = {cve: {
            "upstream_commit": commit,
            "upstream_commit_patch_sha256": sha,
            "source_hunks": 1,
            "exact_postimage_hunks": 0,
            "status": "partial_unresolved",
            "unresolved_paths": ["src/lstm/unverified.cpp"],
        } for cve, (commit, sha) in m.PINNED_COMMITS.items()}
        return {
            "status": "source_hunks_research_release_blocked",
            "source_version": m.SOURCE_VERSION,
            "source_tarball_sha256": m.SOURCE_TARBALL_SHA256,
            "source_url": m.SOURCE_URL,
            "cve_results": rows,
            "cves_with_all_source_hunks_exact": 0,
            "cves_partially_unresolved": sorted(rows),
            "patch_files_signed_by_vendor": False,
            "compiled_elf_bound_to_source_by_build_attestation": False,
            "full_cve_runtime_exploit_tests": False,
            "complete_source_advisory_coverage": False,
            "scanner_findings_suppressed": False,
            "vex": "not_issued",
            "security_gate": "blocked",
            "release_authorized": False,
        }

    def test_reviewer_recomputes_entire_CVE_evidence_and_keeps_gate(self):
        report = self._synthetic_complete_report()
        result = m.verify_report(report)
        self.assertEqual(result["cves_with_all_source_hunks_exact"], 0)
        self.assertEqual(len(result["cves_partially_unresolved"]), 14)
        self.assertFalse(result["release_authorized"])

    def test_reviewer_rejects_forged_release_and_inflated_patch_results(self):
        report = self._synthetic_complete_report()
        cve = "CVE-2026-119341"
        for field, fake in [
            ("release_authorized", True),
            ("scanner_findings_suppressed", True),
            ("full_cve_runtime_exploit_tests", True),
            ("complete_source_advisory_coverage", True),
            ("compiled_elf_bound_to_source_by_build_attestation", True),
        ]:
            corrupted = dict(report, **{field: fake})
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.verify_report(corrupted)
        import copy
        bad = copy.deepcopy(report)
        bad["cve_results"][cve]["exact_postimage_hunks"] = 1
        with self.assertRaises(ValueError):
            m.verify_report(bad)
        bad = copy.deepcopy(report)
        bad["cve_results"][cve]["upstream_commit_patch_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            m.verify_report(bad)
        bad = copy.deepcopy(report)
        bad["cves_partially_unresolved"] = []
        with self.assertRaises(ValueError):
            m.verify_report(bad)

    def test_private_verifier_rejects_unsafe_permissions_and_forged_script(self):
        report = self._synthetic_complete_report()
        report["isolation_container_image_id"] = "sha256:" + "a" * 64
        report["source_probe_script_sha256"] = hashlib.sha256(
            Path(m.__file__).read_bytes()
        ).hexdigest()
        path = Path("/tmp/folio-r141-tesseract-unitfixture.json")
        self.assertFalse(path.exists())
        try:
            path.write_text(json.dumps(report))
            path.chmod(0o600)
            self.assertFalse(m.verify_private_report(path)["release_authorized"])
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                m.verify_private_report(path)
            path.chmod(0o600)
            report["source_probe_script_sha256"] = "b" * 64
            path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                m.verify_private_report(path)
        finally:
            path.unlink(missing_ok=True)

    def test_remote_Docker_or_host_root_rejected(self):
        with patch.object(m.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "root"):
                m.host_probe()
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote:2375"}):
            with self.assertRaisesRegex(ValueError, "Remote"):
                m.host_probe()

    def test_worker_docker_confined_nonroot_no_mounts(self):
        sha = "sha256:" + "a" * 64
        rows = {cve: {
            "upstream_commit": v[0], "upstream_commit_patch_sha256": v[1],
            "source_hunks": 1, "exact_postimage_hunks": 0,
            "status": "partial_unresolved", "unresolved_paths": ["src/a.cpp"]
        } for cve, v in m.PINNED_COMMITS.items()}
        evidence = {
            "cve_results": rows,
            "source_tarball_sha256": m.SOURCE_TARBALL_SHA256,
            "security_gate": "blocked", "release_authorized": False,
        }
        calls = []

        def run(argv, timeout=300, expected=(0,)):
            calls.append(argv)
            if argv[:3] == ["docker", "context", "inspect"]:
                return "unix:///var/run/docker.sock\n"
            if argv[:3] == ["docker", "image", "inspect"]:
                return sha + "\n"
            if argv[:2] == ["docker", "run"]:
                self.assertEqual(expected, (2,))
                return json.dumps(evidence)
            raise AssertionError("Unexpected docker call")

        with patch.object(m.os, "geteuid", return_value=1000), \
             patch.object(m, "_command", side_effect=run):
            result = m.host_probe()
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["isolation_container_image_id"], sha)
        args = calls[-1]
        joined = " ".join(args)
        for check in ("--network bridge", "--pull never", "--read-only",
                      "--cap-drop ALL", "--user 65534:65534",
                      "--security-opt no-new-privileges", sha):
            self.assertIn(check, joined)
        self.assertNotIn("--mount", args)
        self.assertNotIn("--privileged", args)


if __name__ == "__main__":
    unittest.main()
