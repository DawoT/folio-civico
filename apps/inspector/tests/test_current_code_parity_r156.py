"""R1.56: image source equality is not a waiver for any scanner finding."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
from current_code_parity_r156 import (  # noqa: E402
    CODE_FILES, BASE_ID, BASE_NAME, CANDIDATE_NAME,
    compare_code_roots, compare_image_metadata, compare_security_evidence,
)
from gnupg_flat_prune_comparison import EMPTY_LAYER  # noqa: E402
from test_combined_cli_prune_r155 import fixture as combined_fixture  # noqa: E402

H = "a" * 64
J = "b" * 64
BASE = "sha256:" + "c" * 64
NEW = "sha256:" + "d" * 64
PREFIX = "/srv/folio-inspector/"
OLD_NAMES = ("inspector.py", "fixtures.py", "preflight.py",
             "smoke_real_engines.py", "smoke_http_real.py")


def fixture():
    manifest = {key: H for key in CODE_FILES}
    original = {
        PREFIX + key: {"kind": "file", "mode": "0o664", "sha256": J if key in (
            "inspector.py", "fixtures.py", "preflight.py") else H}
        for key in OLD_NAMES
    }
    original["/"] = {"kind": "directory", "mode": "0o755"}
    original[PREFIX + "__pycache__"] = {"kind": "directory", "mode": "0o755"}
    original[PREFIX + "__pycache__/inspector.cpython-312.pyc"] = {
        "kind": "file", "mode": "0o644",
        "sha256": "834cf9412cec3e83fee99c0480847e50d0d32952bd1f768dc08033682bfc81ea"}
    original["/usr/local/bin/clamscan"] = {
        "kind": "file", "mode": "0o755", "sha256": H
    }
    after = copy.deepcopy(original)
    for name, sha in manifest.items():
        after[PREFIX + name] = {"kind": "file", "mode": "0o664", "sha256": sha}
    del after[PREFIX + "__pycache__/inspector.cpython-312.pyc"]
    del after[PREFIX + "__pycache__"]
    fs = lambda rows: {
        "schema": "folio-r148-complete-runtime-filesystem-v1",
        "excluded_top_level": ["/dev", "/proc", "/run", "/sys", "/tmp"],
        "excluded_docker_injected": ["/etc/hostname", "/etc/hosts", "/etc/resolv.conf"],
        "paths": rows,
    }
    return fs(original), fs(after), manifest


class CurrentCodeParityTests(unittest.TestCase):
    def test_current_code_has_exact_delta_and_still_blocks_release(self):
        a, b, source = fixture()
        verdict = compare_code_roots(a, b, source)
        self.assertEqual(verdict["changed_python"], [
            "fixtures.py", "inspector.py", "preflight.py"])
        self.assertEqual(verdict["added_python"], [
            "qpdf_paint_triage_r154.py", "qpdf_scoped_gate_r155.py"])
        self.assertEqual(verdict["unchanged_python"], [
            "smoke_http_real.py", "smoke_real_engines.py"])
        self.assertTrue(verdict["code_matches_main"])
        self.assertEqual(verdict["deleted_stale_bytecode"], 2)
        self.assertFalse(verdict["release_authorized"])

    def test_rejects_any_unexpected_file_or_binary_mutation(self):
        for scenario in ("new_exec", "mutated_elf", "removed_lib",
                         "pycache", "unexpected_code", "suid", "absent_module"):
            a, b, source = fixture()
            if scenario == "new_exec":
                b["paths"]["/usr/local/bin/new"] = {
                    "kind": "file", "mode": "0o755", "sha256": H}
            elif scenario == "mutated_elf":
                b["paths"]["/usr/local/bin/clamscan"]["sha256"] = J
            elif scenario == "removed_lib":
                b["paths"].pop("/usr/local/bin/clamscan")
            elif scenario == "pycache":
                b["paths"][PREFIX + "__pycache__/inspector.pyc"] = {
                    "kind": "file", "mode": "0o644", "sha256": J}
            elif scenario == "unexpected_code":
                b["paths"][PREFIX + "evil.py"] = {
                    "kind": "file", "mode": "0o644", "sha256": J}
            elif scenario == "suid":
                b["paths"][PREFIX + "inspector.py"]["mode"] = "0o4755"
            else:
                b["paths"].pop(PREFIX + "qpdf_scoped_gate_r155.py")
            with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                compare_code_roots(a, b, source)

    def test_rejects_manifest_forgery_and_unsupported_roots(self):
        cases = [
            lambda a,b,m: m.pop("inspector.py"),
            lambda a,b,m: m.update({"debug.py": H}),
            lambda a,b,m: m.update({"inspector.py": "not-a-sha"}),
            lambda a,b,m: m.update({"inspector.py": J}),
            lambda a,b,m: b.update(excluded_top_level=[]),
            lambda a,b,m: b.update(schema="untrusted"),
            lambda a,b,m: b["paths"][PREFIX+"inspector.py"].update(kind="symlink"),
            lambda a,b,m: b["paths"][PREFIX+"inspector.py"].update(mode="0o755"),
            lambda a,b,m: a["paths"][PREFIX+"__pycache__/inspector.cpython-312.pyc"].update(sha256=J),
            lambda a,b,m: b["paths"].update({PREFIX+"__pycache__":a["paths"][PREFIX+"__pycache__"]}),
        ]
        for case in cases:
            a,b,m=fixture()
            case(a,b,m)
            with self.subTest(case=cases.index(case)), self.assertRaises(ValueError):
                compare_code_roots(a,b,m)

    def test_flat_image_metadata_and_immutable_base_are_required(self):
        config = {
            "User": "65534:65534", "Entrypoint": None,
            "Cmd": ["python3", "-I", "/srv/folio-inspector/inspector.py"],
            "WorkingDir": "/srv/folio-inspector", "ExposedPorts": {"8789/tcp": {}},
            "Env": ["CLAMAV_DB_DIR=/opt/clamdb"],
        }
        def image(identity, layer):
            return {"Id": identity, "Os": "linux", "Architecture": "amd64",
                    "Config": copy.deepcopy(config),
                    "RootFS": {"Type": "layers", "Layers": [layer, EMPTY_LAYER]}}
        candidate = "sha256:" + "f"*64
        base = image(BASE_ID, "sha256:"+"e"*64)
        new = image(candidate, "sha256:"+"d"*64)
        self.assertIsNone(compare_image_metadata(base, new, candidate))
        cases = [
            lambda a,b: b["Config"].update(User="root"),
            lambda a,b: b["Config"].update(Cmd=["python3", "/tmp/unsafe.py"]),
            lambda a,b: b["RootFS"]["Layers"].__setitem__(0, a["RootFS"]["Layers"][0]),
            lambda a,b: b["RootFS"]["Layers"].append("sha256:"+"a"*64),
            lambda a,b: b["RootFS"].update(Type="opaque"),
            lambda a,b: b.update(Architecture="arm64"),
            lambda a,b: b.update(Id=BASE_ID),
            lambda a,b: b["Config"]["Env"].append("UNAPPROVED_KEY=true"),
        ]
        for i, mutate in enumerate(cases):
            original, modified = copy.deepcopy(base), copy.deepcopy(new)
            mutate(original, modified)
            with self.subTest(case=i), self.assertRaises(ValueError):
                compare_image_metadata(original, modified, candidate)

    def test_scan_and_sbom_must_have_identical_rows_with_native_provenance(self):
        v = combined_fixture()
        scan_before, scan_after = copy.deepcopy(v[0]), copy.deepcopy(v[1])
        sbom_before, sbom_after = copy.deepcopy(v[2]), copy.deepcopy(v[3])
        candidate = "sha256:"+"f"*64
        for scan, label in ((scan_before, BASE_NAME),
                            (scan_after, CANDIDATE_NAME)):
            scan["ArtifactName"] = label
        for sbom, label, ident in ((sbom_before, BASE_NAME, BASE_ID),
                                   (sbom_after, CANDIDATE_NAME, candidate)):
            sbom["metadata"]["component"]["name"] = label
            sbom["metadata"]["component"]["properties"][0]["value"] = ident
        native_before, native_after = copy.deepcopy(v[6]), copy.deepcopy(v[7])
        a = (scan_before, scan_after, sbom_before, sbom_after, candidate,
             native_before, native_after)
        result = compare_security_evidence(*a)
        self.assertEqual(result["cve_counts"], {"HIGH": 55, "UNKNOWN": 15})
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["scanner_gate"], "blocked")
        cases = [
            lambda x: x[1]["Results"][0]["Vulnerabilities"].pop(),
            lambda x: x[1]["Results"][0]["Vulnerabilities"][0].update(Severity="LOW"),
            lambda x: x[3]["components"].pop(),
            lambda x: x[3]["metadata"]["component"]["properties"][0].update(value=BASE_ID),
            lambda x: x[6]["components"][0].update(version="unproven"),
        ]
        for i, mutate in enumerate(cases):
            sample = copy.deepcopy(list(a))
            mutate(sample)
            with self.subTest(case=i), self.assertRaises(ValueError):
                compare_security_evidence(*sample)


if __name__ == "__main__":
    unittest.main()
