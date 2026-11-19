import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def parse_jsonc(path: Path) -> dict:
    # Our checked-in Wrangler examples use full-line comments only.
    raw = "\n".join(
        line for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("//")
    )
    return json.loads(raw)


class DeploymentActivationGates(unittest.TestCase):
    def test_standard_configs_cannot_allocate_containers_or_queues(self):
        for relative in (
            "apps/api/wrangler.jsonc",
            "apps/processor/wrangler.jsonc",
            "apps/inspector-gateway/wrangler.jsonc"
        ):
            with self.subTest(path=relative):
                config = parse_jsonc(ROOT / relative)
                self.assertFalse(config.get("workers_dev", True))
                self.assertFalse(config.get("preview_urls", True))
                for key in ("containers", "durable_objects", "exports",
                            "queues", "triggers", "services"):
                    self.assertNotIn(key, config)
                self.assertNotIn("INSPECTOR_HMAC_KEY", config.get("vars", {}))

    def test_approved_template_is_private_and_references_exact_docker_build_context(self):
        directory = ROOT / "apps" / "inspector-gateway"
        config = parse_jsonc(directory / "wrangler.container.example.jsonc")
        self.assertFalse(config["workers_dev"])
        self.assertFalse(config["preview_urls"])
        self.assertEqual(config["containers"][0]["class_name"], "InspectorContainer")
        self.assertEqual(config["containers"][0]["scheduling_policy"], "durable_object")
        self.assertEqual(config["durable_objects"]["bindings"][0]["name"], "INSPECTOR_CONTAINER")
        self.assertEqual(config["exports"]["InspectorContainer"]["storage"], "sqlite")
        image = config["containers"][0]["images"]["base"]
        self.assertTrue((directory / image["dockerfile"]).is_file())
        self.assertTrue((directory / image["build_context"]).is_dir())
        self.assertNotIn("vars", config)
        self.assertNotIn("routes", config)

    def test_dockerfile_requires_vendor_signature_and_patched_clamav(self):
        text=(ROOT / "apps/inspector/Dockerfile").read_text(encoding="utf-8")
        for value in (
            "ARG CLAMAV_VERSION=1.5.5",
            "clamav-${CLAMAV_VERSION}.linux.x86_64.deb",
            "clamav-${CLAMAV_VERSION}.linux.x86_64.deb.sig",
            "5BADCA2665EF59DCF8A23D8B707F0DB480836771",
            "gpg", "--verify", "verify_clamav_version",
        ):
            with self.subTest(value=value):
                self.assertIn(value,text)
        self.assertNotIn("clamav-freshclam qpdf",text)
        self.assertLess(text.index("--verify"),text.index("dpkg -i"))
        self.assertIn("5BADCA2665EF59DCF8A23D8B707F0DB480836771",text)

    def test_zlib_security_version_is_checked_before_publishing_image(self):
        dockerfile=(ROOT/"apps/inspector/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("zlib1g",dockerfile)
        self.assertIn("dpkg --compare-versions",dockerfile)
        self.assertIn("1:1.3.dfsg+really1.3.1-1+deb13u1",dockerfile)

    def test_tesseract_source_is_pinned_and_optional_archive_stack_disabled(self):
        source=(ROOT / "apps/inspector/Dockerfile").read_text(encoding="utf-8")
        for expected in (
            "AS ocr_builder",
            "ARG TESSERACT_VERSION=5.5.4",
            "a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4",
            "sha256sum --check",
            "-DDISABLE_ARCHIVE=ON",
            "-DDISABLE_CURL=ON",
            "-DDISABLED_LEGACY_ENGINE=ON",
            "COPY --from=ocr_builder",
            "ldconfig",
            "libxml2",
            "libarchive",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, source)
        self.assertNotIn("FROM folio-civico-inspector:validation", source)

    def test_runtime_does_not_install_packaged_tesseract(self):
        source=(ROOT / "apps/inspector/Dockerfile").read_text(encoding="utf-8")
        runtime=source.split("FROM python:3.12-slim-trixie", 1)[1]
        self.assertIn("tesseract-ocr-spa tesseract-ocr-eng", runtime)
        self.assertNotIn("tesseract-ocr tesseract-ocr-spa", runtime)
        self.assertIn("libtesseract.so", runtime)
        self.assertIn("! ldd", runtime)
        self.assertNotIn("apt-get purge", runtime)

    def test_vendor_download_tools_do_not_survive_into_pdf_runtime(self):
        source=(ROOT/"apps/inspector/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("AS clamav_verifier",source)
        self.assertIn("COPY --from=clamav_verifier",source)
        verifier,runtime=source.split("FROM python:3.12-slim-trixie",1)
        self.assertIn("gpg --batch",verifier)
        self.assertIn("--verify",verifier)
        self.assertIn("curl --fail",verifier)
        self.assertNotIn("curl --fail",runtime)
        self.assertNotIn("ca-certificates curl",runtime)
        self.assertNotIn("apt-get purge",runtime)
        self.assertIn("freshclam",runtime)
        self.assertIn("USER 65534:65534",runtime)

    def test_optional_image_audit_has_no_vulnerability_suppressions(self):
        source=(ROOT/"apps/inspector/audit_image.sh").read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail",source)
        self.assertIn("folio-civico-inspector:validation",source)
        self.assertIn("--image-src docker",source)
        self.assertIn("--format cyclonedx",source)
        self.assertIn("--format json",source)
        self.assertIn("audit_image.py",source)
        self.assertIn("image_changed_during_audit",source)
        for forbidden in ("--ignore-unfixed", "--skip-db-update", "--ignorefile",
                          "--exit-code 0", "|| true", "docker system prune"):
            self.assertNotIn(forbidden,source)

    def test_optional_runtime_triage_cannot_bypass_original_cve_gate(self):
        source=(ROOT/"apps/inspector/audit_image.sh").read_text(encoding="utf-8")
        self.assertIn('TRIAGE_MODE="${1:-}"',source)
        self.assertIn("runtime_inventory.py",source)
        self.assertIn("triage_image.py",source)
        self.assertIn("--network none --read-only --cap-drop ALL",source)
        self.assertIn('--entrypoint python3 "$BEFORE"',source)
        self.assertIn("image_changed_during_triage",source)
        self.assertIn('python3 apps/inspector/audit_image.py',source)
        self.assertLess(source.index("apps/inspector/audit_image.py"),
                        source.index("apps/inspector/triage_image.py"))
        self.assertIn("triage_gate_mismatch",source)
        self.assertNotIn("--ignore-unfixed",source)
        self.assertNotIn("--ignorefile",source)
        self.assertNotIn("docker system prune",source)
        self.assertIn('TRIAGE_MODE="${1:-}"',source)
        self.assertIn("--candidate", source)
        self.assertIn("folio-civico-inspector:ocr-integrated", source)

    def test_local_real_engine_runner_requires_preflight_and_is_offline(self):
        runner=(ROOT / "apps/inspector/validate_real_engines.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("set -euo pipefail", runner)
        preflight=runner.index("python3 apps/inspector/preflight.py --mode build")
        build=runner.index("docker build")
        run=runner.index("docker run")
        self.assertLess(preflight, build)
        self.assertLess(build, run)
        for expected in ("--network none", "--read-only", "--cap-drop ALL",
                         "--security-opt no-new-privileges", "--memory 4g",
                         "--memory-swap 4g", "--tmpfs /tmp:", "--rm"):
            with self.subTest(flag=expected):
                self.assertIn(expected, runner)
        self.assertNotIn("--publish", runner)
        self.assertNotIn("docker system prune", runner)
        dockerfile=(ROOT / "apps/inspector/Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("--datadir=/opt/clamdb", dockerfile)
        self.assertIn("smoke_real_engines.py", dockerfile)
        self.assertIn("fixtures.py", dockerfile)
        self.assertIn("smoke_http_real.py", dockerfile)
        self.assertEqual(runner.count("--network none"), 3)
        self.assertIn("/srv/folio-inspector/smoke_http_real.py", runner)
        self.assertIn("! command -v curl",runner)
        self.assertIn("/opt/folio-ocr/source-provenance.json", runner)
        self.assertIn("libxml2.so.2", runner)
        self.assertIn("libtesseract.so.5.5.4", runner)

    def test_private_container_process_never_receives_hmac_signing_key(self):
        source=(ROOT / "apps/inspector-gateway/src/index.ts").read_text(encoding="utf-8")
        self.assertIn('FOLIO_INSPECTOR_OUTPUT_MODE:"unsigned"', source)
        self.assertNotIn('FOLIO_INSPECTOR_HMAC_KEY:', source)
        self.assertIn('enableInternet:false', source)


if __name__ == "__main__":
    unittest.main()
