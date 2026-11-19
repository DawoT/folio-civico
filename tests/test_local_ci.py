"""Contract tests for the local, provider-independent CI entrypoint."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI_SCRIPT = ROOT / "scripts" / "ci.sh"
EXPECTED = [
    "install --frozen-lockfile",
    "test:local-ci",
    "test",
    "test:inspector",
    "typecheck",
    "build",
    "test:workers",
    "test:browser",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/api/wrangler.jsonc",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/mcp/wrangler.jsonc",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/processor/wrangler.jsonc",
]


class LocalCiContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="folio-ci-test-")
        self.addCleanup(self.directory.cleanup)
        self.temp = Path(self.directory.name)
        bindir = self.temp / "bin"
        bindir.mkdir()
        fake_pnpm = bindir / "pnpm"
        fake_pnpm.write_text(
            '#!/bin/sh\n'
            'printf "%s\\n" "$*" >> "$CI_FAKE_LOG"\n'
            'if [ "${CI_FAIL_STEP:-}" = "$*" ]; then exit 47; fi\n'
        )
        fake_pnpm.chmod(0o755)
        self.log = self.temp / "calls.log"
        self.env = os.environ.copy()
        self.env["PATH"] = f"{bindir}:{self.env['PATH']}"
        self.env["CI_FAKE_LOG"] = str(self.log)

    def run_ci(self, *args):
        return subprocess.run(
            ["sh", str(CI_SCRIPT), *args],
            cwd=self.temp,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_runs_all_gates_in_order_from_any_cwd(self):
        result = self.run_ci()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), EXPECTED)
        self.assertIn("CI PASSED", result.stdout)

    def test_fails_closed_when_a_gate_fails(self):
        self.env["CI_FAIL_STEP"] = "test:inspector"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:4])
        self.assertNotIn("CI PASSED", result.stdout)

    def test_browser_failures_block_database_steps_and_success(self):
        self.env["CI_FAIL_STEP"] = "test:browser"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:8])
        self.assertNotIn("CI PASSED", result.stdout)
        self.assertFalse(any("d1 migrations" in call for call in self.calls()))

    def test_rejects_unknown_options_before_running_anything(self):
        result = self.run_ci("--skip-security")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_does_not_perform_remote_migrations_or_deployments(self):
        result = self.run_ci()
        self.assertEqual(result.returncode, 0, result.stderr)
        invocations = self.calls()
        self.assertTrue(all("--local" in call for call in invocations if "d1 migrations" in call))
        self.assertFalse(any("deploy" in call or "--remote" in call for call in invocations))

    def test_github_actions_installs_real_chromium_before_browser_ci(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        install_deps = "run: pnpm install --frozen-lockfile"
        install_browser = "run: pnpm exec playwright install --with-deps chromium"
        run_ci = "run: sh scripts/ci.sh"
        self.assertIn(install_deps, workflow)
        self.assertIn(install_browser, workflow)
        self.assertLess(workflow.index(install_deps), workflow.index(install_browser))
        self.assertLess(workflow.index(install_browser), workflow.index(run_ci))
        self.assertNotIn("playwright install --with-deps firefox", workflow)
        self.assertNotIn("playwright install --with-deps webkit", workflow)
        self.assertNotIn("wrangler deploy --remote", workflow)

    def test_main_ci_cannot_activate_unapproved_inspector_runtime(self):
        """Main code integration does not grant container/Cloudflare release."""
        import json

        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("branches:", workflow)
        self.assertIn("      - main", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("run: sh scripts/ci.sh", workflow)
        self.assertNotIn("wrangler deploy", workflow)
        self.assertNotIn("docker build", workflow)
        self.assertNotIn("docker push", workflow)

        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertNotIn("audit:inspector:image", package["scripts"]["build"])
        self.assertNotIn("test:inspector:docker", package["scripts"]["build"])
        for app in ("api", "mcp", "processor", "inspector-gateway"):
            build = json.loads(
                (ROOT / "apps" / app / "package.json").read_text(encoding="utf-8")
            )["scripts"]["build"]
            self.assertEqual(build, "wrangler deploy --dry-run --outdir dist")

        decision = (ROOT / "docs" /
                    "ADR-023-main-code-integration-runtime-release-gate.md")
        policy = decision.read_text(encoding="utf-8")
        for required in (
            "main", "exit 2", "Cloudflare", "Preview", "VEX",
            "sin desplegar", "CVE", "no autoriza",
        ):
            self.assertIn(required, policy)


if __name__ == "__main__":
    unittest.main()
