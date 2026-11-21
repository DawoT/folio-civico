"""R1.42: immutable image-identity bridge is not a build attestation."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
import tesseract_554_candidate_lineage as m

IMAGE_SHA = "sha256:" + "a" * 64
EXE_SHA = "b" * 64
LIB_SHA = "c" * 64
META_SHA = "d" * 64
MODEL_HASHES = {"eng": "e" * 64, "spa": "f" * 64}
SNAP = Path("/tmp/folio-r140-labfixture")
SOURCE = Path("/tmp/folio-r142-tesseract-labfixture.json")
RECEIPT = Path("/tmp/folio-r142-lineage-labfixture.json")


def fixture():
    prior = {
        "status": "independently_verified_research_release_blocked",
        "image_id": IMAGE_SHA,
        "report_sha256": "0" * 64,
        "audit_gate_status": "blocked",
        "security_gate": "blocked",
        "release_authorized": False,
    }
    source = {
        "status": "source_guard_excerpts_revalidated_release_blocked",
        "report_sha256": "1" * 64,
        "security_gate": "blocked",
        "release_authorized": False,
        "source_tarball_sha256": m.SOURCE_SHA,
        "guards": {
            c: {"source_guard_landmarks_present": True, "failed": []}
            for c in m.CVE_IDS
        },
    }
    native = {
        "mode": "candidate", "source": "folio-local-elf-provenance-v1",
        "components": [{
            "name": "tesseract",
            "version": "5.5.4",
            "executable_sha256": EXE_SHA,
            "library_sha256": LIB_SHA,
            "provenance_sha256": META_SHA,
            "model_sha256": MODEL_HASHES,
            "automated_cve_coverage": "not_verified",
            "cve_assessment": "required",
        }],
    }
    inspector_sha = "2" * 64
    return prior, {
        "source": source,
        "saved": native,
        "native_inspector_sha256": inspector_sha,
    }


class CandidateLineageTDD(unittest.TestCase):
    def test_historical_R140_inventory_implementation_remains_sha_pinned(self):
        original_v1 = "6effc14e9267f507e1d54b6fab71b2709737414eba952e812133c460de772d2c"
        actual = hashlib.sha256((ROOT / "apps/inspector/source_inventory.py").read_bytes()).hexdigest()
        self.assertEqual(actual, original_v1, "R1.40 inventory v1 cannot be mutated in place")

    def test_R140_R142_synthetic_historical_snapshot_replay(self):
        previous, evidence = fixture()
        manifest = {
            "immutable_local_image_id": previous["image_id"],
            "native_inspector_sha256": evidence.get("native_inspector_sha256"),
        }
        manifest["native_inspector_sha256"] = hashlib.sha256(
            (ROOT / "apps/inspector/source_inventory.py").read_bytes()
        ).hexdigest()

        def private_file(path):
            return manifest if path.name == m.SNAPSHOT_MANIFEST else evidence["saved"]

        with patch.object(m, "verify_snapshot", return_value=previous), \
             patch.object(m, "private_report", return_value=evidence["source"]), \
             patch.object(m, "_json_private", side_effect=private_file):
            snapshot, actual = m.validated_context(SNAP, SOURCE)
        self.assertEqual(snapshot["image_id"], IMAGE_SHA)
        self.assertEqual(actual["native_inspector_sha256"], manifest["native_inspector_sha256"])
        self.assertEqual(actual["saved"], evidence["saved"])

    def _capture(self, *, tag_sha=IMAGE_SHA, returned_native=None):
        prior, evidence = fixture()
        seen = []
        def command(argv, timeout=50):
            seen.append(argv)
            if argv[:3] == ["docker", "context", "inspect"]:
                return "unix:///var/run/docker.sock\n"
            if argv[:3] == ["docker", "image", "inspect"]:
                return tag_sha + "\n"
            if argv[:2] == ["docker", "run"]:
                return json.dumps(returned_native if returned_native is not None
                                  else evidence["saved"])
            raise AssertionError("Unexpected Docker invocation: " + str(argv))
        with patch.object(m.os, "geteuid", return_value=1000), \
             patch.object(m, "validated_context",
                          return_value=(prior, evidence)), \
             patch.object(m, "_run", side_effect=command):
            result = m.capture(SNAP, SOURCE)
        return result, seen

    def test_exact_nonroot_live_image_matches_R140_without_claiming_build(self):
        result, seen = self._capture()
        self.assertEqual(result["candidate_immutable_local_image_id"],
                         IMAGE_SHA)
        self.assertTrue(result["runtime_inventory_matches_R140"])
        self.assertFalse(result["source_to_ELF_reproducible_build_attested"])
        self.assertFalse(result["full_runtime_CVE_regressions_passed"])
        self.assertFalse(result["registry_manifest_digest_attested"])
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["security_gate"], "blocked")
        calls = [cmd for cmd in seen if cmd[:2] == ["docker", "run"]]
        self.assertEqual(len(calls), 1)
        joined = " ".join(calls[0])
        for token in ("--network none", "--read-only", "--cap-drop ALL",
                      "--security-opt no-new-privileges", "--user 65534:65534",
                      "--pull never", IMAGE_SHA, "-I -c"):
            self.assertIn(token, joined)
        self.assertNotIn("--mount", calls[0])

    def test_image_tag_change_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "tag was changed"):
            self._capture(tag_sha="sha256:" + "9" * 64)

    def test_runtime_component_tampering_fails_closed(self):
        _, evidence = fixture()
        broken = copy.deepcopy(evidence["saved"])
        broken["components"][0]["library_sha256"] = "9" * 64
        with self.assertRaisesRegex(ValueError, "ELF/model hashes"):
            self._capture(returned_native=broken)

    def test_remote_docker_or_root_cannot_probe(self):
        with patch.object(m.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "root"):
                m.capture(SNAP, SOURCE)
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote:2375"}):
            with self.assertRaisesRegex(ValueError, "Remote"):
                m.capture(SNAP, SOURCE)

    def test_source_identity_or_guard_false_rejects_linkage(self):
        _, proof = fixture()
        previous, _ = fixture()
        modified = copy.deepcopy(proof["source"])
        modified["source_tarball_sha256"] = "0" * 64
        with patch.object(m, "verify_snapshot", return_value=previous), \
             patch.object(m, "private_report", return_value=modified):
            with self.assertRaises(ValueError):
                m.validated_context(SNAP, SOURCE)
        modified = copy.deepcopy(proof["source"])
        modified["guards"]["CVE-2026-88052"]["source_guard_landmarks_present"] = False
        with patch.object(m, "verify_snapshot", return_value=previous), \
             patch.object(m, "private_report", return_value=modified):
            with self.assertRaises(ValueError):
                m.validated_context(SNAP, SOURCE)

    def test_offline_receipt_rechecks_every_identity_and_no_release(self):
        result, _ = self._capture()
        # Avoid touching a shared path outside the test; mock only private
        # file read and security-exact R1.40/R1.42 snapshots.
        prior, evidence = fixture()
        with patch.object(m, "validated_context", return_value=(prior, evidence)), \
             patch.object(m, "_json_private", return_value=result), \
             patch.object(Path, "read_bytes", return_value=b"synthetic-json"):
            receipt = m.verify_receipt(RECEIPT, SNAP, SOURCE)
        self.assertEqual(receipt["image_id"], IMAGE_SHA)
        self.assertFalse(receipt["source_to_ELF_reproducible_build_attested"])
        self.assertFalse(receipt["release_authorized"])
        for key in ("source_to_ELF_reproducible_build_attested",
                    "signed_binary_build_provenance",
                    "registry_manifest_digest_attested",
                    "release_authorized"):
            bad = {**result, key: True}
            with patch.object(m, "validated_context", return_value=(prior, evidence)), \
                 patch.object(m, "_json_private", return_value=bad):
                with self.assertRaisesRegex(ValueError, "unsupported identity"):
                    m.verify_receipt(RECEIPT, SNAP, SOURCE)

    def test_output_path_notarization_rejects_arbitrary_paths(self):
        with self.assertRaises(ValueError):
            m.verify_receipt(Path("/etc/folio-r142-lineage-bad.json"),
                             SNAP, SOURCE)
        with self.assertRaises(ValueError):
            m.verify_receipt(Path("/tmp/unrelated-asset.json"), SNAP, SOURCE)


if __name__ == "__main__":
    unittest.main()
