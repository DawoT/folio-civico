"""Guardrails for a separately tagged, non-deployable Poppler experiment."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps" / "inspector"))


class ExperimentalPopplerPolicyTests(unittest.TestCase):
    def test_debian_patched_poppler_source_and_disabled_network_backends(self):
        source=(ROOT/"apps/inspector/Dockerfile.poppler-experiment").read_text(encoding="utf-8")
        for token in (
            "FROM debian:trixie-slim AS poppler_builder",
            "POPPLER_DEBIAN_VERSION=25.03.0-5+deb13u4",
            "apt-get source",
            "dpkg-parsechangelog",
            "-DFONT_CONFIGURATION=fontconfig",
            "-DENABLE_LIBCURL=OFF",
            "-DENABLE_GPGME=OFF",
            "-DENABLE_NSS3=OFF",
            "-DENABLE_UTILS=ON",
            "COPY --from=poppler_builder",
            "ARG POPPLER_BASE_IMAGE=scratch",
            "FROM ${POPPLER_BASE_IMAGE}",
            "poppler-utils libpoppler147",
            "libgssapi-krb5-2",
            "ldconfig",
            "USER 65534:65534",
        ):
            with self.subTest(token=token):
                self.assertIn(token,source)
        self.assertNotIn("--allow-unauthenticated",source)
        self.assertNotIn("sid",source)
        self.assertNotIn("unstable",source)
        self.assertNotIn("FROM folio-civico-inspector:validation",source)
        self.assertNotIn("FROM folio-civico-inspector:ocr-integrated",source)
        self.assertIn('linked="$(ldd "/opt/folio-poppler/bin/$binary")"',source)
        self.assertNotIn('! ldd "',source)
        self.assertIn('libgpgme|libnss3',source)
        self.assertIn("grep -q 'libfontconfig'", source)
        self.assertIn("test -r /etc/fonts/fonts.conf", source)
        self.assertIn("test ! -L /etc/fonts/fonts.conf", source)
        self.assertIn("test -d /etc/fonts/conf.d", source)
        self.assertNotIn("-DFONT_CONFIGURATION=generic", source)
        # Debian signed APT metadata is necessary but not sufficient for a
        # reproducible source revision; pin its three source artifacts too.
        from poppler_source_patch_probe import ARCHIVE_HASHES, ARCHIVE_NAMES
        self.assertIn("sha256sum --check -", source)
        for filename in ARCHIVE_NAMES.values():
            self.assertIn(filename, source)
            self.assertIn(ARCHIVE_HASHES[filename], source)

    def test_poppler_quality_comparison_is_optional_and_reuses_strict_gate(self):
        source=(ROOT/"apps/inspector/compare_ocr_quality.sh").read_text(encoding="utf-8")
        self.assertIn('--experiment',source)
        self.assertIn('folio-civico-inspector:poppler-experiment',source)
        self.assertIn('folio-civico-inspector:ocr-integrated',source)
        self.assertIn('ocr_quality_matrix.py --compare',source)
        result=subprocess.run(
            ['bash','apps/inspector/compare_ocr_quality.sh','--invalid'],
            cwd=ROOT,timeout=5,capture_output=True,text=True
        )
        self.assertEqual(result.returncode,3)

    def test_current_raster_guard_runs_offline_without_rebuilding_images(self):
        script=(ROOT/"apps/inspector/verify_raster_guard.sh").read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail",script)
        self.assertIn('python3 apps/inspector/preflight.py --mode build',script)
        self.assertIn('folio-civico-inspector:poppler-experiment',script)
        self.assertIn('docker image inspect "$IMAGE"',script)
        self.assertIn('--network none --read-only --cap-drop ALL',script)
        self.assertIn('--security-opt no-new-privileges',script)
        self.assertIn('smoke_real_engines.py',script)
        self.assertIn('base64 -w0 apps/inspector/inspector.py',script)
        self.assertIn('base64 -w0 apps/inspector/smoke_real_engines.py',script)
        self.assertIn('sys.modules["inspector"]=module',script)
        self.assertIn('exec(compile(smoke,path,"exec")',script)
        self.assertNotIn('docker build',script)
        self.assertNotIn('docker push',script)
        self.assertNotIn('--publish',script)
        self.assertNotIn('--mount',script)
        self.assertNotIn('wrangler deploy',script)
        result=subprocess.run(
            ["bash","apps/inspector/verify_raster_guard.sh","--invalid"],
            cwd=ROOT,timeout=5,capture_output=True,text=True,check=False
        )
        self.assertEqual(result.returncode,3)

    def test_manual_builder_is_isolated_from_approved_images_and_network(self):
        script=(ROOT/"apps/inspector/build_poppler_experiment.sh").read_text(encoding="utf-8")
        for token in (
            "set -euo pipefail",
            "python3 apps/inspector/preflight.py --mode build",
            "Dockerfile.poppler-experiment",
            "folio-civico-inspector:poppler-experiment",
            "smoke_real_engines.py",
            "smoke_http_real.py",
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
        ):
            with self.subTest(token=token):
                self.assertIn(token,script)
        self.assertNotIn("--publish",script)
        self.assertNotIn("docker system prune",script)
        self.assertNotIn("docker push",script)
        self.assertNotIn("wrangler deploy",script)
        self.assertIn('linked="$(ldd "$resolved")"',script)
        self.assertIn('--build-arg "POPPLER_BASE_IMAGE=$BASE_PIN"',script)
        self.assertIn('BASE_PIN="folio-civico-inspector@$BEFORE"',script)
        self.assertIn('EXPERIMENT_ID="$(docker image inspect',script)
        self.assertEqual(script.count("docker run --rm --pull never"), 2)
        self.assertIn("experiment_image_changed",script)
        self.assertIn('if dpkg-query -W "$package"',script)
        self.assertNotIn('! ldd "',script)
        self.assertNotIn('! dpkg-query -W',script)
        result=subprocess.run(
            ["bash","apps/inspector/build_poppler_experiment.sh","--bad-flag"],
            cwd=ROOT,timeout=5,capture_output=True,text=True
        )
        self.assertEqual(result.returncode,3)


if __name__=="__main__":
    unittest.main()
