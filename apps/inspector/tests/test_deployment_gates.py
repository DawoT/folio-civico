import json
from pathlib import Path
import subprocess
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

    def test_invalid_audit_and_candidate_options_reject_before_running_docker(self):
        for args in (
            ("--unknown",), ("--candidate", "--candidate"),
            ("--triage", "--triage"), ("--candidate", "--triage", "--extra"),
            ("--candidate", "--experiment"), ("--experiment", "--experiment"),
            ("--advisories", "--advisories"),
            ("--candidate","--triage","--advisories","--unknown"),
        ):
            with self.subTest(args=args):
                result=subprocess.run(
                    ["bash","apps/inspector/audit_image.sh",*args],
                    cwd=ROOT,timeout=5,capture_output=True,text=True,
                    check=False
                )
                self.assertEqual(result.returncode,3)
                self.assertEqual(json.loads(result.stdout)["status"],"error")
        runner=subprocess.run(
            ["bash","apps/inspector/validate_real_engines.sh","--invalid"],
            cwd=ROOT,timeout=5,capture_output=True,text=True,check=False
        )
        self.assertEqual(runner.returncode,3)

    def test_clamav_signature_rebuild_avoids_stale_docker_layer_cache(self):
        dockerfile=(ROOT/"apps/inspector/Dockerfile").read_text(encoding="utf-8")
        runner=(ROOT/"apps/inspector/validate_real_engines.sh").read_text(encoding="utf-8")
        self.assertIn("ARG CLAMAV_SIGNATURE_REFRESH_EPOCH",dockerfile)
        self.assertIn('test -n "$CLAMAV_SIGNATURE_REFRESH_EPOCH"',dockerfile)
        self.assertIn('date -u +%s',runner)
        self.assertIn('CLAMAV_SIGNATURE_REFRESH_EPOCH=$REFRESH_EPOCH',runner)
        self.assertIn('--build-arg',runner)
        self.assertIn('IMAGE="folio-civico-inspector:ocr-integrated"',runner)
        self.assertIn('"--candidate"',runner)
        self.assertLess(
            dockerfile.index("ARG CLAMAV_SIGNATURE_REFRESH_EPOCH"),
            dockerfile.index("freshclam --config-file")
        )

    def test_runtime_contains_trusted_fontconfig_used_by_sandboxed_parsers(self):
        dockerfile=(ROOT/"apps/inspector/Dockerfile").read_text(encoding="utf-8")
        for check in ("test -r /etc/fonts/fonts.conf",
                      "test ! -L /etc/fonts/fonts.conf",
                      "test -d /etc/fonts/conf.d"):
            self.assertIn(check,dockerfile)
        inspector=(ROOT/"apps/inspector/inspector.py").read_text(encoding="utf-8")
        self.assertIn('"FONTCONFIG_FILE": "/etc/fonts/fonts.conf"',inspector)
        self.assertIn('"FONTCONFIG_PATH": "/etc/fonts"',inspector)
        self.assertIn('env=engine_environment()',inspector)
        self.assertNotIn('env=os.environ',inspector)

    def test_signed_vendor_downloads_have_bounded_timeouts(self):
        source=(ROOT / "apps/inspector/Dockerfile").read_text(encoding="utf-8")
        verifier=source.split("FROM debian:trixie-slim AS ocr_builder", 1)[0]
        self.assertEqual(verifier.count("--connect-timeout 15"), 3)
        self.assertEqual(verifier.count("--max-time 45"), 2)
        self.assertEqual(verifier.count("--max-time 180"), 1)
        self.assertLess(verifier.index("clamav.deb.sig"), verifier.index("--verify"))

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
        self.assertIn('linked_bin="$(timeout 15s ldd', runtime)
        self.assertIn('linked_lib="$(timeout 15s ldd', runtime)
        self.assertIn("gate: forbidden Debian packages", runtime)
        self.assertIn("TESSDATA_PREFIX=/usr/share/tesseract-ocr/5/tessdata", runtime)
        self.assertIn("OCR language discovery", runtime)
        self.assertIn('test "$code" -eq 1', runtime)
        self.assertIn("for package in libxml2 libarchive13t64", runtime)
        self.assertIn("test \"$status\" != 'install ok installed'", runtime)
        self.assertNotIn("dpkg-query -W -f=\"\\${Status}", runtime)
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
        self.assertIn('TRIAGE_MODE=""',source)
        self.assertIn("runtime_inventory.py",source)
        self.assertIn("triage_image.py",source)
        self.assertIn("--network none --read-only --cap-drop ALL",source)
        self.assertIn('--entrypoint python3 "$BEFORE"',source)
        self.assertIn("image_changed_during_triage",source)
        self.assertIn('python3 apps/inspector/audit_image.py',source)
        self.assertLess(source.index("apps/inspector/audit_image.py"),
                        source.index("apps/inspector/triage_image.py"))
        self.assertIn("triage_gate_mismatch",source)
        self.assertIn('ADVISORIES_MODE=0',source)
        self.assertIn("advisory_inventory.py",source)
        self.assertIn("advisory_gate_mismatch",source)
        self.assertIn("source_inventory.py",source)
        self.assertIn('IMAGE_MODE="experiment"',source)
        self.assertIn('IMAGE_MODE="candidate"',source)
        self.assertIn('"$BEFORE" \\',source)
        self.assertIn('--source-inventory "$OUTPUT/source-inventory.json"',source)
        self.assertLess(source.index("apps/inspector/source_inventory.py"),
                        source.index("apps/inspector/audit_image.py"))
        self.assertIn("--advisories",source)
        self.assertLess(source.index("apps/inspector/audit_image.py"),
                        source.index("apps/inspector/advisory_inventory.py"))
        self.assertNotIn("--ignore-unfixed",source)
        self.assertNotIn("--ignorefile",source)
        self.assertNotIn("docker system prune",source)
        self.assertIn('TRIAGE_MODE=""',source)
        self.assertIn("--candidate", source)
        self.assertIn("folio-civico-inspector:ocr-integrated", source)
        self.assertIn("folio-civico-inspector:poppler-experiment", source)
        self.assertIn("--experiment",source)
        self.assertIn('for option in "$@"; do', source)
        self.assertIn('case "$option" in', source)
        self.assertIn('TRIAGE_MODE="--triage"', source)

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
        self.assertEqual(runner.count("--network none"), 4)
        self.assertIn("/srv/folio-inspector/smoke_http_real.py", runner)
        self.assertIn("smoke_signature_freshness.py", runner)
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
